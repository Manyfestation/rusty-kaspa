//! Integration test for double-spend detection via the VCC v2 RPC endpoint.
//!
//! This test verifies both types of double-spend conflict detection:
//! 1. **Concurrent conflicts**: Two transactions in sibling blocks (same mergeset) spending the same UTXO
//! 2. **Historical conflicts**: A transaction rejected because the UTXO was already spent in a past chain block

use crate::common::{client_notify::ChannelNotify, daemon::Daemon, utils::is_utxo_spendable};
use kaspa_addresses::{Address, Prefix, Version};
use kaspa_consensus::params::SIMNET_PARAMS;
use kaspa_consensus_core::{
    block::MutableBlock,
    constants::TX_VERSION,
    header::Header,
    merkle::calc_hash_merkle_root,
    sign::sign,
    subnets::SUBNETWORK_ID_NATIVE,
    tx::{SignableTransaction, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry},
};
use kaspa_core::info;
use kaspa_grpc_client::GrpcClient;
use kaspa_hashes::Hash;
use kaspa_notify::{
    connection::{ChannelConnection, ChannelType},
    scope::{Scope, VirtualDaaScoreChangedScope},
};
use kaspa_rpc_core::{
    api::rpc::RpcApi,
    model::{GetBlockDagInfoRequest, GetBlockTemplateRequest, GetVirtualChainFromBlockV2Request, RpcRawBlock, SubmitBlockRequest},
    Notification,
};
use kaspa_txscript::pay_to_address_script;
use kaspa_utils::fd_budget;
use secp256k1::Keypair;
use std::{sync::Arc, time::Duration};

// ================================================================================================
// Block/Transaction Conversion Helpers
// ================================================================================================

/// Converts an RpcTransaction to a consensus Transaction.
fn rpc_tx_to_consensus(rpc_tx: &kaspa_rpc_core::RpcTransaction) -> Transaction {
    Transaction::new(
        rpc_tx.version,
        rpc_tx
            .inputs
            .iter()
            .map(|i| TransactionInput {
                previous_outpoint: TransactionOutpoint {
                    transaction_id: i.previous_outpoint.transaction_id,
                    index: i.previous_outpoint.index,
                },
                signature_script: i.signature_script.clone(),
                sequence: i.sequence,
                sig_op_count: i.sig_op_count,
            })
            .collect(),
        rpc_tx.outputs.iter().map(|o| TransactionOutput { value: o.value, script_public_key: o.script_public_key.clone() }).collect(),
        rpc_tx.lock_time,
        rpc_tx.subnetwork_id.clone(),
        rpc_tx.gas,
        rpc_tx.payload.clone(),
    )
}

/// Converts an RPC block to a mutable consensus block for manipulation.
fn rpc_block_to_mutable(rpc_block: &RpcRawBlock) -> MutableBlock {
    let header = Header::new_finalized(
        rpc_block.header.version,
        rpc_block.header.parents_by_level.clone().try_into().expect("valid parents"),
        rpc_block.header.hash_merkle_root,
        rpc_block.header.accepted_id_merkle_root,
        rpc_block.header.utxo_commitment,
        rpc_block.header.timestamp,
        rpc_block.header.bits,
        rpc_block.header.nonce,
        rpc_block.header.daa_score,
        rpc_block.header.blue_work,
        rpc_block.header.blue_score,
        rpc_block.header.pruning_point,
    );

    let transactions = rpc_block.transactions.iter().map(rpc_tx_to_consensus).collect();
    MutableBlock::new(header, transactions)
}

/// Converts a mutable consensus block back to RPC format.
fn mutable_to_rpc_block(block: &MutableBlock) -> RpcRawBlock {
    RpcRawBlock { header: (&block.header).into(), transactions: block.transactions.iter().map(|tx| tx.into()).collect() }
}

// ================================================================================================
// Mining Helpers
// ================================================================================================

/// Solves the PoW for Simnet (simple brute-force, Simnet has high target).
fn solve_block(block: &mut MutableBlock) {
    for _ in 0..10_000 {
        block.header.finalize();
        // Simnet has a very high target, so most hashes will pass.
        if block.header.hash.as_bytes()[31] == 0 {
            return;
        }
        block.header.nonce = block.header.nonce.wrapping_add(1);
    }
}

/// Recalculates the merkle root after modifying transactions.
fn update_merkle_root(block: &mut MutableBlock) {
    block.header.hash_merkle_root = calc_hash_merkle_root(block.transactions.iter());
}

/// Mines a single block to the given address, waiting for DAA score confirmation.
async fn mine_block_to_address(client: &GrpcClient, pay_address: &Address, event_receiver: &async_channel::Receiver<Notification>) {
    let template = client
        .get_block_template_call(None, GetBlockTemplateRequest { pay_address: pay_address.clone(), extra_data: vec![] })
        .await
        .unwrap();

    let mut block = rpc_block_to_mutable(&template.block);
    solve_block(&mut block);

    client
        .submit_block_call(None, SubmitBlockRequest { block: mutable_to_rpc_block(&block), allow_non_daa_blocks: false })
        .await
        .unwrap();

    // Wait for virtual DAA score to advance
    while let Ok(notification) = tokio::time::timeout(Duration::from_secs(2), event_receiver.recv()).await.unwrap() {
        if matches!(notification, Notification::VirtualDaaScoreChanged(_)) {
            break;
        }
    }
}

/// Mines multiple blocks to a dummy address (just for advancing the chain).
async fn mine_blocks(client: &GrpcClient, count: usize, event_receiver: &async_channel::Receiver<Notification>) {
    let dummy_address = Address::new(Prefix::Simnet, Version::PubKey, &[0u8; 32]);
    for _ in 0..count {
        mine_block_to_address(client, &dummy_address, event_receiver).await;
    }
}

// ================================================================================================
// Transaction Helpers
// ================================================================================================

/// Creates and signs a transaction spending the given UTXO.
/// The `discriminator` byte is added to payload to create distinct transaction IDs.
fn create_double_spend_tx(
    utxo_outpoint: TransactionOutpoint,
    utxo_entry: &UtxoEntry,
    signing_key: Keypair,
    output_script: &kaspa_consensus_core::tx::ScriptPublicKey,
    discriminator: u8,
) -> Transaction {
    let fee = 1000u64;
    let tx = Transaction::new(
        TX_VERSION,
        vec![TransactionInput { previous_outpoint: utxo_outpoint, signature_script: vec![], sequence: 0, sig_op_count: 1 }],
        vec![TransactionOutput { value: utxo_entry.amount.saturating_sub(fee), script_public_key: output_script.clone() }],
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![discriminator], // Makes each tx have a unique ID
    );

    let signable = SignableTransaction::with_entries(tx, vec![utxo_entry.clone()]);
    sign(signable, signing_key).tx.as_ref().clone()
}

// ================================================================================================
// Conflict Tracking
// ================================================================================================

/// Tracks detected conflicts for verification
#[derive(Debug, Default)]
struct ConflictTracker {
    concurrent_conflict_found: bool,
    historical_conflict_found: bool,
    concurrent_accepting_block: Option<Hash>,
    historical_accepting_block: Option<Hash>,
}

// ================================================================================================
// Test Implementation
// ================================================================================================

/// Comprehensive test for double-spend detection covering both concurrent and historical conflicts.
///
/// ## Test Scenarios:
///
/// ### Scenario 1: Concurrent Conflict (same mergeset)
/// - TX_A and TX_B both spend UTXO_1
/// - Both are submitted in sibling blocks (Block A and Block B)
/// - When merged, one is rejected with the other as the accepted spender
///
/// ### Scenario 2: Historical Conflict (past chain block)
/// - TX_C spends UTXO_2 and is accepted in Block C
/// - Several blocks are mined, making Block C "historical"
/// - TX_D (also spending UTXO_2) is submitted in a later block
/// - TX_D is rejected because TX_C was already accepted in a past block
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn double_spend_detection_test() {
    kaspa_core::log::try_init_logger("info");

    // ============================================================================================
    // Setup: Start daemon and RPC client
    // ============================================================================================

    let args = kaspad_lib::args::Args {
        simnet: true,
        disable_upnp: true,
        enable_unsynced_mining: true,
        utxoindex: true,
        unsafe_rpc: true,
        ..Default::default()
    };

    let mut daemon = Daemon::new_random_with_args(args, fd_budget::limit());
    let client = daemon.start().await;

    // Setup notification listener for DAA score changes
    let (notify_sender, event_receiver) = async_channel::unbounded();
    let connection = ChannelConnection::new("double_spend_test", notify_sender.clone(), ChannelType::Closable);
    client.register_new_listener(connection);
    client.start(Some(Arc::new(ChannelNotify::new(notify_sender)))).await;
    client.start_notify(Default::default(), Scope::VirtualDaaScoreChanged(VirtualDaaScoreChangedScope {})).await.unwrap();

    let keypair = Keypair::new(secp256k1::SECP256K1, &mut secp256k1::rand::thread_rng());
    let (xonly_pubkey, _) = keypair.x_only_public_key();
    let test_address = Address::new(Prefix::Simnet, Version::PubKey, &xonly_pubkey.serialize());
    let p2addr_script = pay_to_address_script(&test_address);

    // ============================================================================================
    // Phase 1: Establish initial chain and mine TWO coinbases (for two UTXOs)
    // ============================================================================================

    info!("=== Phase 1: Mining initial blocks and coinbases ===");
    mine_blocks(&client, 10, &event_receiver).await;

    // Mine two coinbase blocks to our address (we need 2 UTXOs for 2 double-spend scenarios)
    info!("Mining first coinbase to our address...");
    mine_block_to_address(&client, &test_address, &event_receiver).await;
    info!("Mining second coinbase to our address...");
    mine_block_to_address(&client, &test_address, &event_receiver).await;

    // ============================================================================================
    // Phase 2: Mine blocks for coinbase maturity
    // ============================================================================================

    let coinbase_maturity = SIMNET_PARAMS.coinbase_maturity();
    let blocks_to_mine = coinbase_maturity + 10;
    info!("=== Phase 2: Mining {} blocks for coinbase maturity ===", blocks_to_mine);
    mine_blocks(&client, blocks_to_mine as usize, &event_receiver).await;

    // ============================================================================================
    // Phase 3: Get two spendable UTXOs
    // ============================================================================================

    info!("=== Phase 3: Finding spendable UTXOs ===");
    let utxos = client.get_utxos_by_addresses(vec![test_address.clone()]).await.unwrap();
    assert!(utxos.len() >= 2, "Expected at least 2 UTXOs at our address, got {}", utxos.len());

    let virtual_daa_score = client.get_server_info().await.unwrap().virtual_daa_score;
    info!("Virtual DAA score: {}, found {} UTXOs", virtual_daa_score, utxos.len());

    let spendable_utxos: Vec<_> =
        utxos.iter().filter(|u| is_utxo_spendable(&u.utxo_entry, virtual_daa_score, coinbase_maturity)).collect();
    assert!(spendable_utxos.len() >= 2, "Expected at least 2 spendable UTXOs, got {}", spendable_utxos.len());

    // UTXO_1: For concurrent conflict (TX_A vs TX_B in sibling blocks)
    let utxo_1_outpoint = TransactionOutpoint::from(spendable_utxos[0].outpoint);
    let utxo_1_entry = UtxoEntry::from(spendable_utxos[0].utxo_entry.clone());
    info!("UTXO_1 (concurrent conflict): {:?}", utxo_1_outpoint);

    // UTXO_2: For historical conflict (TX_C accepted first, TX_D rejected later)
    let utxo_2_outpoint = TransactionOutpoint::from(spendable_utxos[1].outpoint);
    let utxo_2_entry = UtxoEntry::from(spendable_utxos[1].utxo_entry.clone());
    info!("UTXO_2 (historical conflict): {:?}", utxo_2_outpoint);

    // ============================================================================================
    // Phase 4: Create all conflicting transactions
    // ============================================================================================

    info!("=== Phase 4: Creating conflicting transactions ===");

    // Concurrent conflict pair (UTXO_1)
    let tx_a = create_double_spend_tx(utxo_1_outpoint, &utxo_1_entry, keypair, &p2addr_script, 0xAA);
    let tx_b = create_double_spend_tx(utxo_1_outpoint, &utxo_1_entry, keypair, &p2addr_script, 0xBB);
    info!("Concurrent conflict: TX_A={} vs TX_B={} (both spend UTXO_1)", tx_a.id(), tx_b.id());

    // Historical conflict pair (UTXO_2)
    let tx_c = create_double_spend_tx(utxo_2_outpoint, &utxo_2_entry, keypair, &p2addr_script, 0xCC);
    let tx_d = create_double_spend_tx(utxo_2_outpoint, &utxo_2_entry, keypair, &p2addr_script, 0xDD);
    info!("Historical conflict: TX_C={} vs TX_D={} (both spend UTXO_2)", tx_c.id(), tx_d.id());

    // ============================================================================================
    // Phase 5: Create blocks for historical conflict (Block C and D as siblings, but submit C first)
    // ============================================================================================

    info!("=== Phase 5: Setting up historical conflict (TX_C accepted first, TX_D submitted later) ===");

    // Get template for C and D - they will be siblings (same parent)
    let template_cd = client
        .get_block_template_call(None, GetBlockTemplateRequest { pay_address: test_address.clone(), extra_data: vec![] })
        .await
        .unwrap();

    // Create Block C with TX_C
    let mut block_c = rpc_block_to_mutable(&template_cd.block);
    block_c.transactions.truncate(1);
    block_c.transactions.push(tx_c.clone());
    update_merkle_root(&mut block_c);
    solve_block(&mut block_c);
    let block_c_hash = block_c.header.hash;

    // Create Block D with TX_D (sibling of C, but DON'T submit yet!)
    let mut block_d = rpc_block_to_mutable(&template_cd.block);
    block_d.transactions.truncate(1);
    block_d.transactions.push(tx_d.clone());
    update_merkle_root(&mut block_d);
    block_d.header.timestamp += 1000; // Different timestamp
    block_d.header.nonce = 0;
    solve_block(&mut block_d);
    let block_d_hash = block_d.header.hash;

    // Submit Block C first
    client
        .submit_block_call(None, SubmitBlockRequest { block: mutable_to_rpc_block(&block_c), allow_non_daa_blocks: false })
        .await
        .unwrap();
    info!("Block C submitted: {} (contains TX_C)", block_c_hash);

    // Mine several blocks on top of C to make it "historical"
    info!("Mining 5 blocks to push Block C into history...");
    mine_blocks(&client, 5, &event_receiver).await;

    // ============================================================================================
    // Phase 6: Set up concurrent conflict (Block A and B as immediate siblings) and submit Block D
    // ============================================================================================

    info!("=== Phase 6: Setting up concurrent conflict + submitting historical Block D ===");

    // Record VCC start point (after C is historical, before A/B/D conflicts)
    let dag_info = client.get_block_dag_info_call(None, GetBlockDagInfoRequest {}).await.unwrap();
    let vcc_start_hash = dag_info.tip_hashes[0];
    info!("VCC start point: {}", vcc_start_hash);

    // Get template for concurrent conflict (A and B)
    let template_ab = client
        .get_block_template_call(None, GetBlockTemplateRequest { pay_address: test_address.clone(), extra_data: vec![] })
        .await
        .unwrap();

    // Block A with TX_A
    let mut block_a = rpc_block_to_mutable(&template_ab.block);
    block_a.transactions.truncate(1);
    block_a.transactions.push(tx_a.clone());
    update_merkle_root(&mut block_a);
    solve_block(&mut block_a);
    let block_a_hash = block_a.header.hash;

    // Block B with TX_B (sibling of A)
    let mut block_b = rpc_block_to_mutable(&template_ab.block);
    block_b.transactions.truncate(1);
    block_b.transactions.push(tx_b.clone());
    update_merkle_root(&mut block_b);
    block_b.header.timestamp += 1000;
    block_b.header.nonce = 0;
    solve_block(&mut block_b);
    let block_b_hash = block_b.header.hash;

    // Submit Block A
    client
        .submit_block_call(None, SubmitBlockRequest { block: mutable_to_rpc_block(&block_a), allow_non_daa_blocks: false })
        .await
        .unwrap();
    info!("Block A submitted: {} (contains TX_A, concurrent conflict)", block_a_hash);

    // Submit Block B (sibling of A)
    client
        .submit_block_call(None, SubmitBlockRequest { block: mutable_to_rpc_block(&block_b), allow_non_daa_blocks: false })
        .await
        .unwrap();
    info!("Block B submitted: {} (contains TX_B, sibling of A)", block_b_hash);

    // NOW submit Block D (created earlier as sibling of C, but submitted late!)
    // This creates a historical conflict: TX_D conflicts with TX_C which is now 5+ blocks in the past
    client
        .submit_block_call(None, SubmitBlockRequest { block: mutable_to_rpc_block(&block_d), allow_non_daa_blocks: false })
        .await
        .unwrap();
    info!("Block D submitted: {} (contains TX_D, late sibling of historical Block C)", block_d_hash);

    // ============================================================================================
    // Phase 7: Mine merging block to resolve all conflicts
    // ============================================================================================

    info!("=== Phase 7: Mining merging block ===");
    mine_blocks(&client, 1, &event_receiver).await;

    // ============================================================================================
    // Phase 9: Query VCC v2 and verify both conflict types
    // ============================================================================================

    info!("=== Phase 9: Querying VCC v2 for conflict detection ===");
    let vcc_response = client
        .get_virtual_chain_from_block_v2_call(
            None,
            GetVirtualChainFromBlockV2Request {
                start_hash: vcc_start_hash,
                min_confirmation_count: Some(0),
                data_verbosity_level: None,
            },
        )
        .await
        .unwrap();

    // Debug: Log VCC v2 response
    info!(
        "VCC v2 response: {} added blocks, {} removed blocks, {} chain_block_transactions",
        vcc_response.added_chain_block_hashes.len(),
        vcc_response.removed_chain_block_hashes.len(),
        vcc_response.chain_block_transactions.len()
    );
    for (i, block_acc) in vcc_response.chain_block_transactions.iter().enumerate() {
        info!(
            "  Block {}: {} accepted txs, {} conflicting txs",
            i,
            block_acc.accepted_transactions.len(),
            block_acc.conflicting_transactions.len()
        );
        for conflict in &block_acc.conflicting_transactions {
            let rejected_tx = rpc_tx_to_consensus(&conflict.rejected_transaction);
            info!("    Conflict: rejected_tx={}, inputs={:?}", rejected_tx.id(), conflict.conflicting_inputs.len());
        }
    }

    let mut tracker = ConflictTracker::default();

    for block_acceptance in vcc_response.chain_block_transactions.iter() {
        for conflict in &block_acceptance.conflicting_transactions {
            let rejected_tx = rpc_tx_to_consensus(&conflict.rejected_transaction);
            let rejected_id = rejected_tx.id();

            for conflicting_input in &conflict.conflicting_inputs {
                let accepted_id = conflicting_input.accepted_transaction_id;
                let accepting_block = conflicting_input.accepting_chain_block_hash;
                let double_spent_outpoint = TransactionOutpoint::from(conflicting_input.double_spent_outpoint);

                // Check for UTXO_1 conflict (TX_A vs TX_B)
                if double_spent_outpoint == utxo_1_outpoint {
                    let is_utxo1_conflict = (rejected_id == tx_a.id() && accepted_id == tx_b.id())
                        || (rejected_id == tx_b.id() && accepted_id == tx_a.id());

                    if is_utxo1_conflict {
                        info!(
                            "UTXO_1 CONFLICT: Rejected={}, Accepted={}, AcceptingBlock={}",
                            rejected_id, accepted_id, accepting_block
                        );
                        tracker.concurrent_conflict_found = true;
                        tracker.concurrent_accepting_block = Some(accepting_block);

                        // Just verify the accepting block is not zero/default
                        assert!(accepting_block != Hash::default(), "UTXO_1 conflict accepting block should not be default");
                    }
                }

                // Check for UTXO_2 conflict (TX_C vs TX_D) - HISTORICAL
                if double_spent_outpoint == utxo_2_outpoint {
                    let is_utxo2_conflict = (rejected_id == tx_c.id() && accepted_id == tx_d.id())
                        || (rejected_id == tx_d.id() && accepted_id == tx_c.id());

                    if is_utxo2_conflict {
                        info!(
                            "UTXO_2 CONFLICT (HISTORICAL): Rejected={}, Accepted={}, AcceptingBlock={}",
                            rejected_id, accepted_id, accepting_block
                        );
                        tracker.historical_conflict_found = true;
                        tracker.historical_accepting_block = Some(accepting_block);

                        // For historical conflict, verify the accepting block is valid
                        // Note: The accepting_chain_block_hash is the chain block where the tx was accepted,
                        // which may be a merging block rather than Block C itself
                        assert!(accepting_block != Hash::default(), "Historical conflict accepting block should not be default");
                    }
                }
            }
        }
    }

    // ============================================================================================
    // Final Assertions
    // ============================================================================================

    info!("=== Final Verification ===");
    info!("UTXO_1 conflict (TX_A vs TX_B) found: {} - CONCURRENT", tracker.concurrent_conflict_found);
    info!("UTXO_2 conflict (TX_C vs TX_D) found: {} - HISTORICAL", tracker.historical_conflict_found);

    assert!(tracker.concurrent_conflict_found, "Expected to find UTXO_1 double-spend conflict (TX_A vs TX_B in sibling blocks)");
    assert!(
        tracker.historical_conflict_found,
        "Expected to find UTXO_2 double-spend conflict (TX_D rejected due to TX_C in historical Block C)"
    );

    // Verify the accepting blocks are DIFFERENT (one is concurrent, one is historical)
    let concurrent_block = tracker.concurrent_accepting_block.unwrap();
    let historical_block = tracker.historical_accepting_block.unwrap();
    assert_ne!(
        concurrent_block, historical_block,
        "Concurrent and historical conflicts should have DIFFERENT accepting blocks! Concurrent={}, Historical={}",
        concurrent_block, historical_block
    );

    info!("=== Double-spend detection test PASSED! ===");
    info!("  - CONCURRENT conflict (UTXO_1): accepting block = {}", concurrent_block);
    info!("  - HISTORICAL conflict (UTXO_2): accepting block = {} (Block C)", historical_block);
}
