use kaspa_consensus_core::tx::SignableTransaction;
use kaspa_hashes::Hash;
use kaspa_rpc_core::CovenantTransactionFilter;

pub fn touches_covenant(tx: &SignableTransaction, watched_covenant_ids: &[Hash], covenant_filter: CovenantTransactionFilter) -> bool {
    match covenant_filter {
        CovenantTransactionFilter::Input => input_touches_covenant(tx, watched_covenant_ids),
        CovenantTransactionFilter::Output => output_touches_covenant(tx, watched_covenant_ids),
        CovenantTransactionFilter::Both => {
            input_touches_covenant(tx, watched_covenant_ids) || output_touches_covenant(tx, watched_covenant_ids)
        }
    }
}

fn input_touches_covenant(tx: &SignableTransaction, watched_covenant_ids: &[Hash]) -> bool {
    tx.entries.iter().any(|entry| {
        entry
            .as_ref()
            .and_then(|entry| entry.covenant_id)
            .is_some_and(|covenant_id| covenant_id_matches(covenant_id, watched_covenant_ids))
    })
}

fn output_touches_covenant(tx: &SignableTransaction, watched_covenant_ids: &[Hash]) -> bool {
    tx.tx
        .as_ref()
        .outputs
        .iter()
        .any(|output| output.covenant.as_ref().is_some_and(|covenant| covenant_id_matches(covenant.covenant_id, watched_covenant_ids)))
}

fn covenant_id_matches(covenant_id: Hash, watched_covenant_ids: &[Hash]) -> bool {
    watched_covenant_ids.is_empty() || watched_covenant_ids.contains(&covenant_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_consensus_core::{
        subnets::SUBNETWORK_ID_NATIVE,
        tx::{CovenantBinding, ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry},
    };

    const OP_TRUE: u8 = 0x51;

    fn hash(byte: u8) -> Hash {
        Hash::from_bytes([byte; 32])
    }

    fn tx_with_covenants(input_covenant_id: Option<Hash>, output_covenant_id: Option<Hash>) -> SignableTransaction {
        let script_public_key = ScriptPublicKey::from_vec(0, vec![OP_TRUE]);
        let input = TransactionInput::new(TransactionOutpoint::new(hash(0x01), 0), Vec::new(), u64::MAX, 0);
        let output =
            TransactionOutput::with_covenant(900, script_public_key.clone(), output_covenant_id.map(|id| CovenantBinding::new(0, id)));
        let tx = Transaction::new(0, vec![input], vec![output], 0, SUBNETWORK_ID_NATIVE, 0, Vec::new());
        let entry = UtxoEntry::new(1000, script_public_key, 0, false, input_covenant_id);
        SignableTransaction::with_entries(tx, vec![entry])
    }

    #[test]
    fn input_filter_detects_transactions_spending_watched_covenant_utxos() {
        let watched = hash(0x77);
        let watched_tx = tx_with_covenants(Some(watched), None);
        let other_tx = tx_with_covenants(Some(hash(0x88)), None);
        let non_covenant_tx = tx_with_covenants(None, None);

        assert!(touches_covenant(&watched_tx, &[watched], CovenantTransactionFilter::Input));
        assert!(!touches_covenant(&other_tx, &[watched], CovenantTransactionFilter::Input));
        assert!(!touches_covenant(&non_covenant_tx, &[watched], CovenantTransactionFilter::Input));
        assert!(touches_covenant(&watched_tx, &[], CovenantTransactionFilter::Input));
    }

    #[test]
    fn filter_selects_input_output_or_either_side() {
        let watched = hash(0x77);
        let input_tx = tx_with_covenants(Some(watched), None);
        let output_tx = tx_with_covenants(None, Some(watched));

        assert!(touches_covenant(&input_tx, &[watched], CovenantTransactionFilter::Input));
        assert!(!touches_covenant(&input_tx, &[watched], CovenantTransactionFilter::Output));
        assert!(!touches_covenant(&output_tx, &[watched], CovenantTransactionFilter::Input));
        assert!(touches_covenant(&output_tx, &[watched], CovenantTransactionFilter::Output));
        assert!(touches_covenant(&input_tx, &[watched], CovenantTransactionFilter::Both));
        assert!(touches_covenant(&output_tx, &[watched], CovenantTransactionFilter::Both));
    }

    #[test]
    fn empty_watch_set_is_wildcard_for_selected_side() {
        let output_tx = tx_with_covenants(None, Some(hash(0x88)));

        assert!(touches_covenant(&output_tx, &[], CovenantTransactionFilter::Output));
        assert!(touches_covenant(&output_tx, &[], CovenantTransactionFilter::Both));
        assert!(!touches_covenant(&output_tx, &[], CovenantTransactionFilter::Input));
    }
}
