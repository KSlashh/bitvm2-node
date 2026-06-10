use crate::types::BitvmGcGraph;
use anyhow::{Result, bail};
use bitcoin::{Address, Amount, Network, ScriptBuf, Transaction, TxIn, TxOut, XOnlyPublicKey};
use bitvm::chunk::api::type_conversion_utils::RawWitness;
use goat::{
    assert_scripts::{INPUT_WIRE_NUM, Label},
    connectors::{
        assert_connectors::VerifierConnector, base::TaprootConnector, connector_c::ConnectorC,
        connector_e::ConnectorE,
    },
    constants::PROVER_CONNECTOR_TIMELOCK,
    scripts::{generate_opreturn_script, p2a_output},
    transactions::{
        assert::{pubin_disprove, pubin_disprove_script, validate_pubin},
        base::DUST_AMOUNT,
        pre_signed::PreSignedTransaction,
    },
    utils::num_blocks_per_network,
};

/// challenge has a pre-signed SinglePlusAnyoneCanPay input and output
/// get incomplete tx here, add inputs with enough amount, then broadcast it to start challnege progress
pub fn export_challenge_tx(graph: &BitvmGcGraph) -> Result<(Transaction, Amount)> {
    if !graph.committee_pre_signed() {
        bail!("missing pre-signatures from committee")
    };
    Ok((graph.challenge.tx().clone(), graph.challenge.challenge_amount))
}

/// return true if anchor output is added
/// return false if change output is added or no output is added
fn add_change_or_anchor_output(
    tx: &mut Transaction,
    total_input_amount: Amount,
    change_address: Address,
    fee_rate: f64,
) -> Result<bool> {
    let dust_amount = Amount::from_sat(DUST_AMOUNT);
    let output_amount = tx.output.iter().map(|o| o.value).sum();
    tx.output.push(TxOut { value: Amount::ZERO, script_pubkey: change_address.script_pubkey() });
    let min_relay_fee = 1.0;
    let min_fee_amount =
        Amount::from_sat((tx.weight().to_vbytes_ceil() as f64 * min_relay_fee).ceil() as u64);
    let fee_amount =
        Amount::from_sat((tx.weight().to_vbytes_ceil() as f64 * fee_rate).ceil() as u64);
    if min_fee_amount + dust_amount + output_amount > total_input_amount {
        bail!("insufficient input amount to cover min relay fee");
    }
    if fee_amount + output_amount + dust_amount < total_input_amount {
        // add change output
        let change_amount = total_input_amount - fee_amount - output_amount;
        tx.output.last_mut().unwrap().value = change_amount;
        Ok(false)
    } else if fee_amount + output_amount > total_input_amount {
        // add anchor output
        tx.output.pop();
        tx.output.push(p2a_output());
        Ok(true)
    } else {
        // not add any output since remaining is just enough to cover fee
        tx.output.pop();
        Ok(false)
    }
}

/// return (tx, true) if anchor output is added, subsequently challenger need to cover fee via CPFP
/// return (tx, false) if change output is added or no output is added, challenger can directly broadcast it
pub fn build_force_skip_kickoff_tx(
    graph: &BitvmGcGraph,
    verifier_receive_address: Address,
    fee_rate: f64,
) -> Result<(Transaction, bool)> {
    if !graph.operator_pre_signed() {
        bail!("missing pre-signatures from operator")
    };
    let mut tx = graph.force_skip_kickoff.tx().clone();
    let total_input_amount = graph.force_skip_kickoff.prev_outs().iter().map(|o| o.value).sum();
    let anchor_added = add_change_or_anchor_output(
        &mut tx,
        total_input_amount,
        verifier_receive_address,
        fee_rate,
    )?;
    Ok((tx, anchor_added))
}

/// return (tx, true) if anchor output is added, subsequently challenger need to cover fee via CPFP
/// return (tx, false) if change output is added or no output is added, challenger can directly broadcast it
pub fn build_quick_challenge_tx(
    graph: &BitvmGcGraph,
    verifier_receive_address: Address,
    fee_rate: f64,
) -> Result<(Transaction, bool)> {
    if !graph.operator_pre_signed() {
        bail!("missing pre-signatures from operator")
    };
    let mut tx = graph.quick_challenge.tx().clone();
    let total_input_amount = graph.quick_challenge.prev_outs().iter().map(|o| o.value).sum();
    let anchor_added = add_change_or_anchor_output(
        &mut tx,
        total_input_amount,
        verifier_receive_address,
        fee_rate,
    )?;
    Ok((tx, anchor_added))
}

/// return (tx, true) if anchor output is added, subsequently challenger need to cover fee via CPFP
/// return (tx, false) if change output is added or no output is added, challenger can directly broadcast it
pub fn build_challenge_incomplete_kickoff_tx(
    graph: &BitvmGcGraph,
    verifier_receive_address: Address,
    fee_rate: f64,
) -> Result<(Transaction, bool)> {
    if !graph.operator_pre_signed() {
        bail!("missing pre-signatures from operator")
    };
    let mut tx = graph.challenge_incomplete_kickoff.tx().clone();
    let total_input_amount =
        graph.challenge_incomplete_kickoff.prev_outs().iter().map(|o| o.value).sum();
    let anchor_added = add_change_or_anchor_output(
        &mut tx,
        total_input_amount,
        verifier_receive_address,
        fee_rate,
    )?;
    Ok((tx, anchor_added))
}

pub fn verify_prover_assertion(_graph: &BitvmGcGraph, _operator_assert_txin: TxIn) -> Result<bool> {
    todo!("verify operator assertion")
}

pub fn build_verifier_assert_tx(
    graph: &BitvmGcGraph,
    operator_assert_txin: TxIn,
    verifier_index: usize,
    labels: [Label; INPUT_WIRE_NUM],
) -> Result<Transaction> {
    if verifier_index >= graph.verifier_asserts.len() {
        bail!("invalid verifier index {verifier_index}")
    };

    let network = graph.parameters.instance_parameters.network;
    let n_of_n_taproot_public_key =
        XOnlyPublicKey::from(graph.parameters.instance_parameters.committee_agg_pubkey);
    let connector_c = ConnectorC::new(
        network,
        &n_of_n_taproot_public_key,
        &graph.parameters.operator_assert_wots_pubkey,
    );
    let operator_assertion = connector_c
        .extract_leaf_1_raw_witness(&operator_assert_txin)
        .map_err(|e| anyhow::anyhow!("failed to extract operator assertion: {e}"))?;

    let verifier_connector = VerifierConnector::new(
        network,
        &n_of_n_taproot_public_key,
        &graph.parameters.operator_assert_wots_pubkey,
        graph.parameters.gc_data[verifier_index].wire_hashes.clone(),
    );
    let mut verifier_assert = graph.verifier_asserts[verifier_index].clone();
    verifier_assert
        .verifier_publish_labels(&verifier_connector, labels, &operator_assertion)
        .map_err(|e| anyhow::anyhow!("failed to build verifier assert: {e}"))?;
    Ok(verifier_assert.tx().clone())
}

pub fn build_disprove_tx(
    graph: &BitvmGcGraph,
    verifier_index: usize,
    verifier_receive_address: Option<[u8; 20]>,
) -> Result<Transaction> {
    if verifier_index >= graph.disproves.len() {
        bail!("invalid verifier index {verifier_index}")
    };
    if !graph.committee_pre_signed {
        bail!("missing pre-signatures from committee")
    };
    let mut disprove_tx = graph.disproves[verifier_index].tx().clone();
    if let Some(verifier_receive_address) = verifier_receive_address {
        disprove_tx.output.insert(
            0,
            TxOut {
                value: Amount::ZERO,
                script_pubkey: generate_opreturn_script(verifier_receive_address.to_vec()),
            },
        );
    }
    Ok(disprove_tx)
}

pub fn validate_pubin_disprove(
    graph: &BitvmGcGraph,
    operator_commit_pubin_txin: &TxIn,
    operator_assert_txin: &TxIn,
    ack_preimages: Vec<Vec<u8>>,
) -> Result<Option<(RawWitness, ScriptBuf)>> {
    let network = graph.parameters.instance_parameters.network;
    let n_of_n_taproot_public_key =
        XOnlyPublicKey::from(graph.parameters.instance_parameters.committee_agg_pubkey);
    let connector_e = ConnectorE::new(
        network,
        &n_of_n_taproot_public_key,
        &graph.parameters.operator_commit_pubin_wots_pubkey,
    );
    let connector_c = ConnectorC::new(
        network,
        &n_of_n_taproot_public_key,
        &graph.parameters.operator_assert_wots_pubkey,
    );
    let operator_commit_pubin_witness = connector_e
        .extract_leaf_0_raw_witness(operator_commit_pubin_txin)
        .map_err(|e| anyhow::anyhow!("failed to extract operator commit pubin witness: {e}"))?;
    let operator_assert_witness = connector_c
        .extract_leaf_1_raw_witness(operator_assert_txin)
        .map_err(|e| anyhow::anyhow!("failed to extract operator assert witness: {e}"))?;
    let input_lock_script = pubin_disprove_script(
        &graph.parameters.operator_commit_pubin_wots_pubkey,
        &graph.parameters.operator_assert_wots_pubkey,
        &graph.parameters.pubin_disprove_constant,
        &graph.parameters.watchtower_ack_hashlocks,
    )
    .compile();

    Ok(validate_pubin(
        operator_commit_pubin_witness,
        operator_assert_witness,
        ack_preimages,
        input_lock_script,
    ))
}

pub fn build_pubin_disprove_txin(
    graph: &BitvmGcGraph,
    input_script_witness: RawWitness,
    input_lock_script: ScriptBuf,
) -> Result<TxIn> {
    let network = graph.parameters.instance_parameters.network;
    let n_of_n_taproot_public_key =
        XOnlyPublicKey::from(graph.parameters.instance_parameters.committee_agg_pubkey);
    let connector_e = ConnectorE::new(
        network,
        &n_of_n_taproot_public_key,
        &graph.parameters.operator_commit_pubin_wots_pubkey,
    );
    let connector_e_input = graph
        .watchtower_challenge_init
        .connector_e_input()
        .map_err(|e| anyhow::anyhow!("failed to get connector-e input: {e}"))?;
    pubin_disprove(
        &connector_e.generate_taproot_spend_info(),
        &connector_e_input,
        input_script_witness,
        input_lock_script,
    )
    .map_err(|e| anyhow::anyhow!("failed to build pubin-disprove txin: {e}"))
}

pub fn disprove_timelock(network: Network) -> u32 {
    num_blocks_per_network(network, PROVER_CONNECTOR_TIMELOCK)
}
