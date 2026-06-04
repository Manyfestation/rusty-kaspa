use crate::connection::Connection;
use kaspa_notify::{
    connection::{ChannelType, Connection as NotifyConnection},
    listener::{ListenerId, ListenerLifespan},
    scope::{Scope, VirtualChainChangedScope},
};
use kaspa_rpc_core::{
    CovenantTransactionFilter, CovenantTransactionsNotification, Notification, RpcHash, RpcResult,
    notify::{channel::NotificationChannel, connection::ChannelConnection},
};
use kaspa_rpc_service::service::RpcCoreService;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use workflow_log::*;

const WRPC_COVENANT_TRANSACTIONS: &str = "wrpc-covenant-transactions";

#[derive(Clone)]
struct CovenantTransactionsSubscription {
    connection: Connection,
    watched_covenant_ids: Vec<RpcHash>,
    covenant_filter: CovenantTransactionFilter,
}

#[derive(Default)]
struct CovenantTransactionsSubscriptionBridgeInner {
    by_connection: HashMap<u64, CovenantTransactionsSubscription>,
    listener_id: Option<ListenerId>,
}

impl CovenantTransactionsSubscriptionBridgeInner {
    fn replace_existing(
        &mut self,
        connection_id: u64,
        watched_covenant_ids: Vec<RpcHash>,
        covenant_filter: CovenantTransactionFilter,
    ) -> bool {
        if let Some(subscription) = self.by_connection.get_mut(&connection_id) {
            subscription.watched_covenant_ids = watched_covenant_ids;
            subscription.covenant_filter = covenant_filter;
            true
        } else {
            false
        }
    }

    fn insert(&mut self, connection: Connection, watched_covenant_ids: Vec<RpcHash>, covenant_filter: CovenantTransactionFilter) {
        self.by_connection
            .insert(connection.id(), CovenantTransactionsSubscription { connection, watched_covenant_ids, covenant_filter });
    }

    fn snapshot(&self) -> Vec<CovenantTransactionsSubscription> {
        self.by_connection.values().cloned().collect()
    }

    fn remove(&mut self, connection_id: u64) -> bool {
        self.by_connection.remove(&connection_id).is_some()
    }

    fn take_listener_if_empty(&mut self) -> Option<ListenerId> {
        self.by_connection.is_empty().then(|| self.listener_id.take()).flatten()
    }

    fn clear_listener(&mut self, listener_id: ListenerId) {
        if self.listener_id == Some(listener_id) {
            self.listener_id = None;
        }
    }
}

#[derive(Clone, Default)]
pub(crate) struct CovenantTransactionsSubscriptionBridge {
    inner: Arc<Mutex<CovenantTransactionsSubscriptionBridgeInner>>,
}

impl CovenantTransactionsSubscriptionBridge {
    pub(crate) fn start(
        &self,
        connection: &Connection,
        service: Arc<RpcCoreService>,
        watched_covenant_ids: Vec<RpcHash>,
        covenant_filter: CovenantTransactionFilter,
    ) -> RpcResult<()> {
        let mut subscriptions = self.inner.lock().unwrap();
        // One covenant transaction subscription per wRPC connection; repeated start replaces it.
        if subscriptions.replace_existing(connection.id(), watched_covenant_ids.clone(), covenant_filter) {
            return Ok(());
        }

        if subscriptions.listener_id.is_some() {
            subscriptions.insert(connection.clone(), watched_covenant_ids, covenant_filter);
            return Ok(());
        }

        let notification_channel = NotificationChannel::default();
        let listener_id = service.notifier().register_new_listener(
            ChannelConnection::new(WRPC_COVENANT_TRANSACTIONS, notification_channel.sender(), ChannelType::Closable),
            ListenerLifespan::Dynamic,
        );
        service
            .notifier()
            .try_start_notify(listener_id, Scope::VirtualChainChanged(VirtualChainChangedScope::new(true)))
            .inspect_err(|_| {
                let _ = service.notifier().unregister_listener(listener_id);
            })?;
        subscriptions.insert(connection.clone(), watched_covenant_ids, covenant_filter);
        subscriptions.listener_id = Some(listener_id);
        drop(subscriptions);

        self.spawn_bridge_task(service, listener_id, notification_channel);
        Ok(())
    }

    fn spawn_bridge_task(&self, service: Arc<RpcCoreService>, listener_id: ListenerId, notification_channel: NotificationChannel) {
        let notification_receiver = notification_channel.receiver();
        let subscriptions = self.clone();
        workflow_core::task::spawn(async move {
            while let Ok(notification) = notification_receiver.recv().await {
                let Notification::VirtualChainChanged(notification) = notification else {
                    continue;
                };
                let active_subscriptions = subscriptions.inner.lock().unwrap().snapshot();
                for subscription in active_subscriptions {
                    let mut transactions = Vec::new();
                    for accepted in notification.accepted_transaction_ids.iter() {
                        if accepted.accepted_transaction_ids.is_empty() {
                            continue;
                        }
                        let notification = match service
                            .get_covenant_transactions_for_accepted_transactions(
                                accepted.accepting_block_hash,
                                &accepted.accepted_transaction_ids,
                                &subscription.watched_covenant_ids,
                                subscription.covenant_filter,
                            )
                            .await
                        {
                            Ok(notification) => notification,
                            Err(err) => {
                                log_warn!("error collecting covenant transactions: {err}");
                                continue;
                            }
                        };
                        transactions.extend(notification.transactions.iter().cloned());
                    }
                    if transactions.is_empty() {
                        continue;
                    }
                    let notification = CovenantTransactionsNotification { transactions: Arc::new(transactions) };
                    let message = <Connection as NotifyConnection>::into_message(
                        &Notification::CovenantTransactions(notification),
                        &subscription.connection.encoding(),
                    );
                    if <Connection as NotifyConnection>::send(&subscription.connection, message).await.is_err() {
                        let connection_id = subscription.connection.id();
                        subscriptions.stop(&service, connection_id).unwrap_or_else(|err| {
                            log_warn!("error cleaning up covenant transaction subscription for connection {connection_id}: {err}");
                        });
                    }
                }
            }

            subscriptions.inner.lock().unwrap().clear_listener(listener_id);
        });
    }

    pub(crate) fn stop(&self, service: &Arc<RpcCoreService>, connection_id: u64) -> RpcResult<()> {
        let listener_id = {
            let mut subscriptions = self.inner.lock().unwrap();
            subscriptions.remove(connection_id);
            subscriptions.take_listener_if_empty()
        };
        if let Some(listener_id) = listener_id {
            service.notifier().unregister_listener(listener_id)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn covenant_connection_subscription_takes_listener_only_when_empty() {
        let listener_id = 100;
        let mut subscriptions = CovenantTransactionsSubscriptionBridgeInner::default();
        subscriptions.listener_id = Some(listener_id);

        assert_eq!(subscriptions.take_listener_if_empty(), Some(listener_id));
        assert_eq!(subscriptions.take_listener_if_empty(), None);
    }

    #[test]
    fn covenant_connection_subscription_clear_listener_only_when_matching() {
        let mut subscriptions = CovenantTransactionsSubscriptionBridgeInner::default();
        subscriptions.listener_id = Some(100);

        subscriptions.clear_listener(99);
        assert_eq!(subscriptions.listener_id, Some(100));
        subscriptions.clear_listener(100);
        assert_eq!(subscriptions.listener_id, None);
    }
}
