use anyhow::{Result, bail};
use bitcoin::{Address, Amount, Transaction, TxIn, key::Keypair};
use bitcoin::{Network, OutPoint, PublicKey, Witness, XOnlyPublicKey};
use goat::assert_scripts::{OperatorAssertPublicKey, OperatorAssertSecretKey};
use goat::connectors::assert_connectors::{ProverConnector, VerifierConnector};
use goat::connectors::connector_0::Connector0;
use goat::connectors::connector_a::ConnectorA;
use goat::connectors::connector_b::ConnectorB;
use goat::connectors::connector_c::ConnectorC;
use goat::connectors::connector_d::ConnectorD;
use goat::connectors::kickoff_connectors::{
    ForceSkipConnector, GuardianConnector, KickoffConnector, PrekickoffConnector,
};
use goat::connectors::watchtower_connectors::WatchtowerChallengeConnector;
use goat::constants::{CONNECTOR_A_TIMELOCK, CONNECTOR_D_TIMELOCK};
use goat::transactions::assert::{
    DisproveTransaction, OperatorAssertTransaction, VerifierAssertTransaction, wrongly_challenged,
};
use goat::transactions::base::{DUST_AMOUNT, Input};
use goat::transactions::challenge::ChallengeTransaction;
use goat::transactions::kickoff::KickoffTransaction;
use goat::transactions::pre_signed::PreSignedTransaction;
use goat::transactions::prekickoff::{
    ChallengeIncompleteKickoffTransaction, ForceSkipKickoffTransaction, PrekickoffTransaction,
    QuickChallengeTransaction, operator_skip_kickoff,
};
use goat::transactions::take1::Take1Transaction;
use goat::transactions::take2::Take2Transaction;
use goat::transactions::watchtower_challenge::WatchtowerChallengeInitTransaction;
use goat::utils::num_blocks_per_network;
use goat::wots::{Wots, Wots64};

use crate::keys::hkdf_derive_bytes;
use crate::types::{BitvmGcGraph, BitvmGcGraphParameters};

const OPERATOR_WOTS_HKDF_SALT: &[u8] = b"bitvm-gc/operator-wots/v1";

#[allow(deprecated)]
pub fn generate_wots_key(seed: &str) -> (OperatorAssertSecretKey, OperatorAssertPublicKey) {
    let sec_str = hex::encode(hkdf_derive_bytes(
        seed.as_bytes(),
        OPERATOR_WOTS_HKDF_SALT,
        format!("wots64/0").as_bytes(),
        64,
    ));
    let secret = Wots64::secret_from_str(&sec_str);
    let public = Wots64::generate_public_key(&secret);
    (secret.into(), public.into())
}

pub fn operator_presig_num() -> usize {
    6
}

pub fn generate_bitvm_graph(params: BitvmGcGraphParameters) -> Result<BitvmGcGraph> {
    let network = params.instance_parameters.network;
    let operator_taproot_public_key = XOnlyPublicKey::from(params.operator_pubkey);
    let n_of_n_taproot_public_key =
        XOnlyPublicKey::from(params.instance_parameters.committee_agg_pubkey);
    let watchtower_num = params.watchtower_pubkeys.len();
    let verifier_num = params.gc_data.len();

    let (_, pegin, _) = params.instance_parameters.build_pegin_tx()?;
    let pegin_txid = pegin.tx().compute_txid();
    let connector_0_input = Input {
        outpoint: OutPoint { txid: pegin_txid, vout: 0 },
        amount: pegin.tx().output[0].value,
    };

    let cur_prekickoff_connector = PrekickoffConnector::new(network, &operator_taproot_public_key);
    let next_force_skip_connector = ForceSkipConnector::new(network, &operator_taproot_public_key);
    let next_kickoff_connector = KickoffConnector::new(network, &operator_taproot_public_key);
    let next_prekickoff_connector = PrekickoffConnector::new(network, &operator_taproot_public_key);
    let cur_prekickoff = params.prekickoff_parameters.cur_prekickoff_txn.clone();
    let cur_prekickoff_txid = cur_prekickoff.tx().compute_txid();
    let cur_prekickoff_connector_input = Input {
        outpoint: OutPoint { txid: cur_prekickoff_txid, vout: 2 },
        amount: cur_prekickoff.tx().output[2].value,
    };
    let next_prekickoff = PrekickoffTransaction::new_for_validation(
        &cur_prekickoff_connector,
        &next_force_skip_connector,
        &next_kickoff_connector,
        &next_prekickoff_connector,
        cur_prekickoff_connector_input,
        params.prekickoff_parameters.replenish_fee_inputs.clone(),
        params.prekickoff_parameters.replenish_fee_prev_outs.clone(),
        params.prekickoff_parameters.fee_amount,
        watchtower_num,
        verifier_num,
    )
    .map_err(|e| anyhow::anyhow!("failed to create pre-kickoff txn: {e}"))?;
    let next_prekickoff_txid = next_prekickoff.tx().compute_txid();
    let next_force_skip_connector_input = Input {
        outpoint: OutPoint { txid: next_prekickoff_txid, vout: 0 },
        amount: next_prekickoff.tx().output[0].value,
    };
    let next_prekickoff_connector_input = Input {
        outpoint: OutPoint { txid: next_prekickoff_txid, vout: 2 },
        amount: next_prekickoff.tx().output[2].value,
    };

    // kickoff
    let kickoff_connector_input = Input {
        outpoint: OutPoint { txid: cur_prekickoff_txid, vout: 1 },
        amount: cur_prekickoff.tx().output[1].value,
    };
    let kickoff_connector = KickoffConnector::new(network, &operator_taproot_public_key);
    let connector_a =
        ConnectorA::new(network, &operator_taproot_public_key, &n_of_n_taproot_public_key);
    let connector_b = ConnectorB::new(network, &operator_taproot_public_key);
    let connector_c =
        ConnectorC::new(network, &n_of_n_taproot_public_key, &params.operator_wots_pubkeys);
    let guardian_connector = GuardianConnector::new(network, &operator_taproot_public_key);
    let kickoff = KickoffTransaction::new_for_validation(
        &kickoff_connector,
        &connector_a,
        &connector_b,
        &connector_c,
        &guardian_connector,
        &kickoff_connector_input,
        watchtower_num,
        verifier_num,
    )
    .map_err(|e| anyhow::anyhow!("failed to create kickoff txn: {e}"))?;
    let kickoff_txid = kickoff.tx().compute_txid();
    let connector_a_input = Input {
        outpoint: OutPoint { txid: kickoff_txid, vout: 0 },
        amount: kickoff.tx().output[0].value,
    };
    let connector_b_input = Input {
        outpoint: OutPoint { txid: kickoff_txid, vout: 1 },
        amount: kickoff.tx().output[1].value,
    };
    let connector_c_input = Input {
        outpoint: OutPoint { txid: kickoff_txid, vout: 2 },
        amount: kickoff.tx().output[2].value,
    };
    let guardian_connector_input = Input {
        outpoint: OutPoint { txid: kickoff_txid, vout: 3 },
        amount: kickoff.tx().output[3].value,
    };

    // prekickoff challenge
    let force_skip_kickoff = ForceSkipKickoffTransaction::new_for_validation(
        &kickoff_connector,
        &next_force_skip_connector,
        kickoff_connector_input,
        next_force_skip_connector_input.clone(),
    );
    let quick_challenge = QuickChallengeTransaction::new_for_validation(
        &guardian_connector,
        &next_force_skip_connector,
        guardian_connector_input.clone(),
        next_force_skip_connector_input,
    );
    let challenge_incomplete_kickoff = ChallengeIncompleteKickoffTransaction::new_for_validation(
        &guardian_connector,
        &next_prekickoff_connector,
        guardian_connector_input.clone(),
        next_prekickoff_connector_input,
    );

    // take-1
    let connector_0 = Connector0::new(network, &n_of_n_taproot_public_key);
    let take1 = Take1Transaction::new_for_validation(
        &connector_0,
        &connector_a,
        &connector_b,
        &connector_c,
        &guardian_connector,
        connector_0_input.clone(),
        connector_a_input.clone(),
        connector_b_input.clone(),
        connector_c_input.clone(),
        guardian_connector_input.clone(),
        &params.operator_receive_address,
    )
    .map_err(|e| anyhow::anyhow!("failed to create take-1 txn: {e}"))?;

    // challenge
    let challenge = ChallengeTransaction::new_for_validation(
        &connector_a,
        connector_a_input,
        params.challenge_amount,
        &params.operator_receive_address,
    );

    // watchtower-challenge
    let watchtower_challenge_connectors = params
        .watchtower_pubkeys
        .iter()
        .map(|pubkey| WatchtowerChallengeConnector::new(network, pubkey))
        .collect::<Vec<_>>();
    let watchtower_challenge_init = WatchtowerChallengeInitTransaction::new_for_validation(
        &connector_b,
        &watchtower_challenge_connectors,
        connector_b_input,
    )
    .map_err(|e| anyhow::anyhow!("failed to create watchtower-challenge-init txn: {e}"))?;

    // prover-assert
    let connector_d =
        ConnectorD::new(network, &operator_taproot_public_key, &n_of_n_taproot_public_key);
    let verifier_connectors = params
        .gc_data
        .iter()
        .map(|data| {
            VerifierConnector::new(
                network,
                &n_of_n_taproot_public_key,
                &params.operator_wots_pubkeys,
                data.wire_hashes.clone(),
            )
        })
        .collect::<Vec<_>>();
    let operator_assert = OperatorAssertTransaction::new_for_validation(
        &connector_c,
        &verifier_connectors,
        &connector_d,
        connector_c_input,
    )
    .map_err(|e| anyhow::anyhow!("failed to create operator assert txn: {e}"))?;
    let operator_assert_txid = operator_assert.tx().compute_txid();
    let connector_d_input = Input {
        outpoint: OutPoint { txid: operator_assert_txid, vout: verifier_num as u32 },
        amount: operator_assert.tx().output[verifier_num].value,
    };

    // verifier-asserts and disproves
    let mut verifier_asserts = Vec::with_capacity(verifier_num);
    let mut disproves = Vec::with_capacity(verifier_num);
    for (i, verifier_connector) in verifier_connectors.iter().enumerate() {
        let verifier_input = Input {
            outpoint: OutPoint { txid: operator_assert_txid, vout: i as u32 },
            amount: operator_assert.tx().output[i].value,
        };
        let prover_connector = ProverConnector::new(
            network,
            n_of_n_taproot_public_key,
            params.gc_data[i].final_msg_hash,
        );
        let verifier_assert = VerifierAssertTransaction::new_for_validation(
            verifier_connector,
            &prover_connector,
            verifier_input,
        )
        .map_err(|e| anyhow::anyhow!("failed to create verifier assert txn {i}: {e}"))?;
        let prover_input = Input {
            outpoint: OutPoint { txid: verifier_assert.tx().compute_txid(), vout: 0 },
            amount: verifier_assert.tx().output[0].value,
        };
        let disprove = DisproveTransaction::new_for_validation(
            &prover_connector,
            &connector_d,
            prover_input,
            connector_d_input.clone(),
            Vec::new(),
        )
        .map_err(|e| anyhow::anyhow!("failed to create disprove txn {i}: {e}"))?;
        verifier_asserts.push(verifier_assert);
        disproves.push(disprove);
    }

    // take-2
    let take2 = Take2Transaction::new_for_validation(
        &connector_0,
        &connector_d,
        &guardian_connector,
        connector_0_input,
        connector_d_input,
        guardian_connector_input,
        &params.operator_receive_address,
    )
    .map_err(|e| anyhow::anyhow!("failed to create take-2 txn: {e}"))?;

    Ok(BitvmGcGraph {
        operator_pre_signed: false,
        committee_pre_signed: false,
        parameters: params,
        cur_prekickoff,
        next_prekickoff,
        force_skip_kickoff,
        quick_challenge,
        challenge_incomplete_kickoff,
        pegin,
        kickoff,
        take1,
        challenge,
        watchtower_challenge_init,
        operator_assert,
        verifier_asserts,
        disproves,
        take2,
    })
}

pub fn operator_pre_sign(
    operator_keypair: Keypair,
    graph: &mut BitvmGcGraph,
) -> Result<Vec<Witness>> {
    let keypair_pubkey = PublicKey::from(operator_keypair.public_key());
    if keypair_pubkey != graph.parameters.operator_pubkey {
        bail!("operator keypair does not match graph operator pubkey".to_string())
    };

    let mut wits = vec![];
    let context = graph.parameters.get_operator_context(operator_keypair)?;
    let network = context.network;
    let operator_taproot_public_key = context.operator_taproot_public_key;

    // presign force_skip_kickoff
    let kickoff_connector = KickoffConnector::new(network, &operator_taproot_public_key);
    let next_force_skip_connector = ForceSkipConnector::new(network, &operator_taproot_public_key);
    graph.force_skip_kickoff.pre_sign_and_push(
        &context,
        &kickoff_connector,
        &next_force_skip_connector,
    );
    wits.push(graph.force_skip_kickoff.tx().input[0].witness.clone());
    wits.push(graph.force_skip_kickoff.tx().input[1].witness.clone());

    // presign quick_challenge
    let guardian_connector = GuardianConnector::new(network, &operator_taproot_public_key);
    graph.quick_challenge.pre_sign_and_push(
        &context,
        &guardian_connector,
        &next_force_skip_connector,
    );
    wits.push(graph.quick_challenge.tx().input[0].witness.clone());
    wits.push(graph.quick_challenge.tx().input[1].witness.clone());

    // presign challenge_incomplete_kickoff
    let next_prekickoff_connector = PrekickoffConnector::new(network, &operator_taproot_public_key);
    graph.challenge_incomplete_kickoff.pre_sign_and_push(
        &context,
        &guardian_connector,
        &next_prekickoff_connector,
    );
    wits.push(graph.challenge_incomplete_kickoff.tx().input[0].witness.clone());
    wits.push(graph.challenge_incomplete_kickoff.tx().input[1].witness.clone());

    graph.operator_pre_signed = true;
    Ok(wits)
}

pub fn push_operator_pre_signature(
    graph: &mut BitvmGcGraph,
    signed_witness: &[Witness],
) -> Result<()> {
    if graph.operator_pre_signed {
        bail!("already pre-signed by operator".to_string())
    };
    if signed_witness.len() != operator_presig_num() {
        bail!("invalid number of pre-signatures".to_string())
    };

    graph.force_skip_kickoff.tx_mut().input[0].witness = signed_witness[0].clone();
    graph.force_skip_kickoff.tx_mut().input[1].witness = signed_witness[1].clone();
    graph.quick_challenge.tx_mut().input[0].witness = signed_witness[2].clone();
    graph.quick_challenge.tx_mut().input[1].witness = signed_witness[3].clone();
    graph.challenge_incomplete_kickoff.tx_mut().input[0].witness = signed_witness[4].clone();
    graph.challenge_incomplete_kickoff.tx_mut().input[1].witness = signed_witness[5].clone();

    graph.operator_pre_signed = true;
    Ok(())
}

/// remember to sign replensish inputs (if any) after this
pub fn operator_sign_prekickoff_input_0(
    operator_keypair: Keypair,
    graph: &mut BitvmGcGraph,
) -> Result<Transaction> {
    let operator_context = graph.parameters.get_operator_context(operator_keypair)?;
    let prev_prekickoff_connector = PrekickoffConnector::new(
        operator_context.network,
        &operator_context.operator_taproot_public_key,
    );
    graph.cur_prekickoff.sign_input_0(&operator_context, &prev_prekickoff_connector);
    Ok(graph.cur_prekickoff.tx().clone())
}

pub fn operator_sign_skip_kickoff(
    operator_keypair: Keypair,
    graph: &mut BitvmGcGraph,
    operator_receive_address: Address,
    fee_rate: f64,
) -> Result<Option<Transaction>> {
    let operator_context = graph.parameters.get_operator_context(operator_keypair)?;
    let kickoff_connector = KickoffConnector::new(
        operator_context.network,
        &operator_context.operator_taproot_public_key,
    );
    let kickoff_connector_input = Input {
        outpoint: OutPoint { txid: graph.cur_prekickoff.tx().compute_txid(), vout: 1 },
        amount: graph.cur_prekickoff.tx().output[1].value,
    };
    // create a sample tx to estimate fee
    let sample_tx = operator_skip_kickoff(
        &operator_context,
        &kickoff_connector,
        kickoff_connector_input.clone(),
        Amount::ZERO,
        operator_receive_address.clone(),
    )
    .map_err(|e| anyhow::anyhow!("failed to create sample skip-kickoff txn: {e}"))?;

    let fee_amount =
        Amount::from_sat((sample_tx.weight().to_vbytes_ceil() as f64 * fee_rate).ceil() as u64);
    if fee_amount + Amount::from_sat(DUST_AMOUNT) >= kickoff_connector_input.amount {
        // if fee_amount > input_amount - dust_amount, skip-kickoff tx is meaningless
        return Ok(None);
    }
    match operator_skip_kickoff(
        &operator_context,
        &kickoff_connector,
        kickoff_connector_input,
        fee_amount,
        operator_receive_address,
    ) {
        Ok(tx) => Ok(Some(tx)),
        Err(e) => bail!("failed to create skip-kickoff txn: {e}"),
    }
}

pub fn operator_sign_kickoff(
    operator_keypair: Keypair,
    graph: &mut BitvmGcGraph,
) -> Result<Transaction> {
    let operator_context = graph.parameters.get_operator_context(operator_keypair)?;
    let kickoff_connector = KickoffConnector::new(
        operator_context.network,
        &operator_context.operator_taproot_public_key,
    );
    graph.kickoff.sign_input_0(&operator_context, &kickoff_connector);
    Ok(graph.kickoff.tx().clone())
}

pub fn operator_sign_take1(
    operator_keypair: Keypair,
    graph: &mut BitvmGcGraph,
) -> Result<Transaction> {
    if !graph.committee_pre_signed() {
        bail!("missing pre-signatures from committee".to_string())
    };
    let operator_context = graph.parameters.get_operator_context(operator_keypair)?;
    let connector_a = ConnectorA::new(
        operator_context.network,
        &operator_context.operator_taproot_public_key,
        &operator_context.n_of_n_taproot_public_key,
    );
    let connector_b =
        ConnectorB::new(operator_context.network, &operator_context.operator_taproot_public_key);
    let guardian_connector = GuardianConnector::new(
        operator_context.network,
        &operator_context.operator_taproot_public_key,
    );
    graph.take1.sign_input_1(&operator_context, &connector_a);
    graph.take1.sign_input_2(&operator_context, &connector_b);
    graph.take1.sign_input_4(&operator_context, &guardian_connector);
    Ok(graph.take1.tx().clone())
}

pub fn operator_sign_take2(
    operator_keypair: Keypair,
    graph: &mut BitvmGcGraph,
) -> Result<Transaction> {
    if !graph.committee_pre_signed() {
        bail!("missing pre-signatures from committee".to_string())
    };
    let operator_context = graph.parameters.get_operator_context(operator_keypair)?;
    let connector_d = ConnectorD::new(
        operator_context.network,
        &operator_context.operator_taproot_public_key,
        &operator_context.n_of_n_taproot_public_key,
    );
    let guardian_connector = GuardianConnector::new(
        operator_context.network,
        &operator_context.operator_taproot_public_key,
    );
    graph.take2.sign_input_1(&operator_context, &connector_d);
    graph.take2.sign_input_2(&operator_context, &guardian_connector);
    Ok(graph.take2.tx().clone())
}

pub fn operator_sign_watchtower_challenge_init(
    operator_keypair: Keypair,
    graph: &mut BitvmGcGraph,
) -> Result<Transaction> {
    let operator_context = graph.parameters.get_operator_context(operator_keypair)?;
    let connector_b =
        ConnectorB::new(operator_context.network, &operator_context.operator_taproot_public_key);
    graph.watchtower_challenge_init.sign_input_0(&operator_context, &connector_b);
    Ok(graph.watchtower_challenge_init.tx().clone())
}

pub fn operator_sign_assert(
    graph: &mut BitvmGcGraph,
    wots_secret_key: &OperatorAssertSecretKey,
    proof: &[u8; 64],
) -> Result<Transaction> {
    if Wots64::generate_public_key(wots_secret_key) != graph.parameters.operator_wots_pubkeys {
        bail!("provided WOTS secret key does not match expected public key".to_string())
    };

    let network = graph.parameters.instance_parameters.network;
    let n_of_n_taproot_public_key =
        bitcoin::XOnlyPublicKey::from(graph.parameters.instance_parameters.committee_agg_pubkey);
    let connector_c = ConnectorC::new(
        network,
        &n_of_n_taproot_public_key,
        &graph.parameters.operator_wots_pubkeys,
    );

    graph
        .operator_assert
        .operator_commit_proof(wots_secret_key, &connector_c, proof)
        .map_err(|e| anyhow::anyhow!("failed to sign operator assert: {e}"))?;
    Ok(graph.operator_assert.tx().clone())
}

pub fn operator_sign_wrongly_challenged(
    graph: &BitvmGcGraph,
    verifier_index: usize,
    final_msg: &[u8],
) -> Result<(TxIn, Amount)> {
    if verifier_index >= graph.verifier_asserts.len() {
        bail!("invalid verifier index {verifier_index}".to_string())
    };

    let network = graph.parameters.instance_parameters.network;
    let n_of_n_taproot_public_key =
        bitcoin::XOnlyPublicKey::from(graph.parameters.instance_parameters.committee_agg_pubkey);
    let prover_connector = ProverConnector::new(
        network,
        n_of_n_taproot_public_key,
        graph.parameters.gc_data[verifier_index].final_msg_hash,
    );
    let input = Input {
        outpoint: OutPoint {
            txid: graph.verifier_asserts[verifier_index].tx().compute_txid(),
            vout: 0,
        },
        amount: graph.verifier_asserts[verifier_index].tx().output[0].value,
    };

    wrongly_challenged(&prover_connector, &input, final_msg)
        .map(|txin| (txin, input.amount))
        .map_err(|e| anyhow::anyhow!("failed to sign wrongly challenged: {e}"))
}

pub fn take1_timelock(network: Network) -> u32 {
    num_blocks_per_network(network, CONNECTOR_A_TIMELOCK)
}

pub fn take2_timelock(network: Network) -> u32 {
    num_blocks_per_network(network, CONNECTOR_D_TIMELOCK)
}
