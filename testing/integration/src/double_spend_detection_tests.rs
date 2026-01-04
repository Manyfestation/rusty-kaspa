use kaspa_consensus::{config::ConfigBuilder, consensus::test_consensus::TestConsensus, params::MAINNET_PARAMS};
use kaspa_consensus_core::muhash::MuHashExtensions;
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{Transaction, TransactionInput, TransactionOutput};
use kaspa_consensus_core::{
    api::ConsensusApi,
    constants::SOMPI_PER_KASPA,
    header::Header,
    tx::{ScriptPublicKey, TransactionOutpoint, UtxoEntry},
};
use kaspa_muhash::MuHash;
use kaspa_txscript::opcodes::codes::{OpEqual, OpTrue};

fn new_tx(inputs: Vec<TransactionInput>, outputs: Vec<TransactionOutput>) -> Transaction {
    Transaction::new(0, inputs, outputs, 0, SUBNETWORK_ID_NATIVE, 0, vec![])
}

#[tokio::test]
async fn test_conflicting_detection_in_merge_set() {
    // Setup a UTXO whom we will try to double spend
    let origin_script = ScriptPublicKey::from_vec(0, vec![OpTrue]); // public key script with OpTrue - no need for sig script to spend
    let origin_outpoint = TransactionOutpoint::new(1.into(), 0);
    let origin_utxo = UtxoEntry { amount: SOMPI_PER_KASPA, script_public_key: origin_script, block_daa_score: 0, is_coinbase: false };
    let origin_input = (origin_outpoint, origin_utxo.clone());

    // Setup consensus
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .apply_args(|cfg| {
            let mut genesis_multiset = MuHash::new();
            genesis_multiset.add_utxo(&origin_input.0, &origin_input.1);
            cfg.params.genesis.utxo_commitment = genesis_multiset.finalize();
            cfg.params.genesis.hash = Header::from(&cfg.params.genesis).hash;
        })
        .build();
    let consensus = TestConsensus::new(&config);
    let mut genesis_multiset = MuHash::new();
    consensus.append_imported_pruning_point_utxos(&[origin_input.clone()], &mut genesis_multiset);
    consensus.import_pruning_point_utxo_set(config.genesis.hash, genesis_multiset).unwrap();
    consensus.init();

    let genesis = config.genesis.hash;

    // Create 2 different spending scripts, making the ids of txs a and b different
    let spk_a = ScriptPublicKey::from_vec(0, vec![OpTrue]);
    let spk_b = ScriptPublicKey::from_vec(0, vec![OpTrue, OpTrue, OpEqual]);

    // Create two conflicting transactions that spend the initial UTXO
    let tx_original_input = TransactionInput::new(origin_input.0, vec![], 0, 0);
    let tx_a = new_tx(vec![tx_original_input.clone()], vec![TransactionOutput::new(origin_input.1.amount, spk_a.clone())]);
    let tx_b = new_tx(vec![tx_original_input.clone()], vec![TransactionOutput::new(origin_input.1.amount, spk_b.clone())]);

    // Create sibling blocks with conflicting txs under the same parent (genesis)
    let _ = consensus.add_utxo_valid_block_with_parents(1.into(), vec![genesis], vec![tx_a.clone()]).await;
    let _ = consensus.add_utxo_valid_block_with_parents(2.into(), vec![genesis], vec![tx_b.clone()]).await;

    // Create a merge block that includes both conflicting txs
    let merge_block = 3.into();
    let _ = consensus.add_utxo_valid_block_with_parents(merge_block, vec![1.into(), 2.into()], vec![]).await;
    let conflicts = consensus.virtual_processor().detect_conflicting_transactions_in_chain_block(merge_block.into(), 0).unwrap();

    assert_eq!(conflicts.len(), 1, "should have detected 1 conflict");
    let (conflict_tx, conflicting_inputs) = &conflicts[0];
    assert_eq!(conflict_tx.id(), tx_a.id(), "should have detected tx_a as the conflicting transaction");
    assert_eq!(conflicting_inputs.len(), 1, "should have detected 1 conflicting input");
    assert_eq!(conflicting_inputs[0].accepted_transaction_id, tx_b.id(), "should have detected tx_b as the accepted transaction");
    assert_eq!(conflicting_inputs[0].accepting_block_hash, merge_block, "should have detected merge_block as the accepting block");
    assert_eq!(conflicting_inputs[0].double_spent_outpoint, origin_outpoint, "should have detected the double spent outpoint");
    assert_eq!(conflicting_inputs[0].double_spent_utxo, origin_utxo, "should have detected the double spent utxo");
}

#[tokio::test]
async fn test_historical_conflicting_transaction_detection() {
    // Setup a initial UTXO whom we will try to double spend
    let origin_script = ScriptPublicKey::from_vec(0, vec![OpTrue]);
    let origin_outpoint = TransactionOutpoint::new(1.into(), 0);
    let origin_utxo = UtxoEntry { amount: SOMPI_PER_KASPA, script_public_key: origin_script, block_daa_score: 0, is_coinbase: false };
    let origin_input = (origin_outpoint, origin_utxo.clone());

    // Setup consensus
    let config = ConfigBuilder::new(MAINNET_PARAMS)
        .skip_proof_of_work()
        .apply_args(|cfg| {
            let mut genesis_multiset = MuHash::new();
            genesis_multiset.add_utxo(&origin_input.0, &origin_input.1);
            cfg.params.genesis.utxo_commitment = genesis_multiset.finalize();
            cfg.params.genesis.hash = Header::from(&cfg.params.genesis).hash;
        })
        .build();
    let consensus = TestConsensus::new(&config);
    let mut genesis_multiset = MuHash::new();
    consensus.append_imported_pruning_point_utxos(&[origin_input.clone()], &mut genesis_multiset);
    consensus.import_pruning_point_utxo_set(config.genesis.hash, genesis_multiset).unwrap();
    consensus.init();
    let genesis = config.genesis.hash;

    // Create 2 different spending scripts, making the ids of txs a and b different
    let spk_a = ScriptPublicKey::from_vec(0, vec![OpTrue]);
    let spk_b = ScriptPublicKey::from_vec(0, vec![OpTrue, OpTrue, OpEqual]);

    // Create two conflicting transactions that spend the same UTXO
    let double_spend_input = TransactionInput::new(origin_input.0, vec![], 0, 0);
    let tx_a = new_tx(vec![double_spend_input.clone()], vec![TransactionOutput::new(origin_input.1.amount, spk_a.clone())]);
    let tx_b = new_tx(vec![double_spend_input.clone()], vec![TransactionOutput::new(origin_input.1.amount, spk_b.clone())]);

    // Submit block with tx_a
    let block_a = 1.into();
    let _ = consensus.add_utxo_valid_block_with_parents(block_a, vec![genesis], vec![tx_a.clone()]).await;
    // Create merge block accepting block a
    let block_accepting_a = 2.into();
    let _ = consensus.add_utxo_valid_block_with_parents(block_accepting_a, vec![block_a.into()], vec![]).await;

    // Submit block with tx_b
    let block_b = 3.into();
    let _ = consensus.add_utxo_valid_block_with_parents(block_b, vec![genesis], vec![tx_b.clone()]).await;

    // Merge the 2 tips
    let merge_block = 4.into();
    let _ = consensus.add_utxo_valid_block_with_parents(merge_block, vec![block_accepting_a, block_b], vec![]).await;

    let conflicts = consensus.get_conflicting_transactions(merge_block, 10).unwrap();

    assert_eq!(conflicts.len(), 1, "should have detected 1 conflict");
    let (conflict_tx, conflicting_inputs) = &conflicts[0];
    assert_eq!(conflict_tx.id(), tx_b.id(), "should have detected tx_b as the conflicting transaction");
    assert_eq!(conflicting_inputs.len(), 1, "should have detected 1 conflicting input");
    assert_eq!(conflicting_inputs[0].accepted_transaction_id, tx_a.id(), "should have detected tx_a as the accepted transaction");
    assert_eq!(
        conflicting_inputs[0].accepting_block_hash, block_accepting_a,
        "should have detected block_accepting_a as the accepting block"
    );
    assert_eq!(conflicting_inputs[0].double_spent_outpoint, origin_outpoint, "should have detected the double spent outpoint");
    assert_eq!(conflicting_inputs[0].double_spent_utxo, origin_utxo, "should have detected the double spent utxo");
}
