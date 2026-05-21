use anyhow::{Result, bail};
use bitcoin::{Address, Amount, OutPoint, Transaction, key::Keypair};
use goat::{
    connectors::watchtower_connectors::WatchtowerChallengeConnector,
    transactions::{
        base::Input, pre_signed::PreSignedTransaction, watchtower_challenge::watchtower_challenge,
    },
};

use crate::types::BitvmGcGraph;

pub fn estimate_watchtower_challenge_vbytes(commitment_data_len: usize) -> usize {
    120 + commitment_data_len.saturating_mul(12) / 10
}

pub fn build_watchtower_challenge_tx(
    graph: &BitvmGcGraph,
    watchtower_keypair: &Keypair,
    watchtower_index: usize,
    commitment_data: &[u8],
    payer_inputs: Vec<Input>,
    change_address: &Address,
    fee_amount: Amount,
) -> Result<Transaction> {
    if watchtower_index >= graph.parameters.watchtower_pubkeys.len() {
        bail!("Invalid watchtower index");
    }
    let network = graph.parameters.instance_parameters.network;
    let watchtower_taproot_public_key = graph.parameters.watchtower_pubkeys[watchtower_index];
    let watchtower_challenge_connector =
        WatchtowerChallengeConnector::new(network, &watchtower_taproot_public_key);
    let watchtower_challenge_connector_amount = graph
        .watchtower_challenge_init
        .tx()
        .output
        .get(watchtower_index)
        .ok_or_else(|| anyhow::anyhow!("watchtower index out of bounds"))?
        .value;
    let input_0 = Input {
        outpoint: OutPoint {
            txid: graph.watchtower_challenge_init.tx().compute_txid(),
            vout: watchtower_index as u32,
        },
        amount: watchtower_challenge_connector_amount,
    };

    watchtower_challenge(
        watchtower_keypair,
        &watchtower_challenge_connector,
        commitment_data,
        input_0,
        payer_inputs,
        change_address,
        fee_amount,
    )
    .map_err(|e| anyhow::anyhow!("failed to build watchtower challenge transaction: {e}"))
}
