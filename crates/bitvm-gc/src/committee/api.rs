use anyhow::{Result, bail, ensure};
use bitcoin::XOnlyPublicKey;
use bitcoin::{PublicKey, Transaction, key::Keypair, taproot::Signature as TaprootSignature};
use goat::connectors::assert_connectors::ProverConnector;
use goat::connectors::connector_0::Connector0;
use goat::connectors::connector_a::ConnectorA;
use goat::connectors::connector_c::ConnectorC;
use goat::connectors::connector_d::ConnectorD;
use goat::connectors::connector_e::ConnectorE;
use goat::connectors::connector_f::ConnectorF;
use goat::connectors::connector_z::ConnectorZ;
use goat::connectors::watchtower_connectors::AckConnector;
use goat::contexts::base::generate_n_of_n_public_key;
use goat::transactions::base::BaseTransaction;
use goat::transactions::pre_signed_musig2::{get_nonce_message, verify_public_nonce};
use goat::transactions::signing_musig2::generate_aggregated_nonce;
use musig2::{AggNonce, PartialSignature, PubNonce, SecNonce};
use secp256k1::schnorr::Signature as SchnorrSignature;
use serde::{Deserialize, Serialize};

use crate::keys::hkdf_derive_bytes;
use crate::types::BitvmGcGraph;

const COMMITTEE_NONCE_HKDF_SALT: &[u8] = b"bitvm-gc/committee-nonce/v1";

pub fn take1_pre_sign_num() -> usize {
    2
}
pub fn take2_pre_sign_num() -> usize {
    1
}
pub fn challenge_pre_sign_num() -> usize {
    1
}
pub fn watchtower_challenge_timeout_pre_sign_num(watchtower_num: usize) -> usize {
    watchtower_num
}
pub fn operator_challenge_nack_pre_sign_num(watchtower_num: usize) -> usize {
    watchtower_num * 2
}
pub fn operator_commit_timeout_pre_sign_num() -> usize {
    2
}
pub fn disprove_pre_sign_num(verifier_num: usize) -> usize {
    verifier_num * 2
}

pub fn sign_pegin_confirm(
    graph: &BitvmGcGraph,
    committee_member_keypair: Keypair,
    committee_member_sec_nonce: SecNonce,
    committee_agg_nonce: AggNonce,
) -> Result<PartialSignature> {
    let mut pegin_confirm = graph.parameters.instance_parameters.build_pegin_tx()?.1;
    let committee_context =
        graph.parameters.instance_parameters.get_committee_context(committee_member_keypair)?;
    pegin_confirm
        .sign_input_0_musig2(&committee_context, &committee_member_sec_nonce, &committee_agg_nonce)
        .map_err(|e| anyhow::anyhow!("fail to sign pegin confirm {}: {e}", pegin_confirm.name()))
}

pub fn agg_and_push_pegin_confirm_sigs(
    graph: &BitvmGcGraph,
    partial_sigs: Vec<PartialSignature>,
    agg_nonce: &AggNonce,
) -> Result<Transaction> {
    let mut pegin_confirm = graph.parameters.instance_parameters.build_pegin_tx()?.1;
    let context = graph.parameters.instance_parameters.get_base_context();
    let agg_sig = pegin_confirm
        .aggregate_input_0_musig2_signatures(&context, partial_sigs, agg_nonce)
        .map_err(|e| {
            anyhow::anyhow!("fail to aggregate pegin confirm {}: {e}", pegin_confirm.name())
        })?;
    let connector_z = ConnectorZ::new(
        graph.parameters.instance_parameters.network,
        &XOnlyPublicKey::from(graph.parameters.instance_parameters.committee_agg_pubkey),
        &graph.parameters.instance_parameters.user_info.user_xonly_pubkey,
    );
    pegin_confirm.push_input_0_signature(&connector_z, agg_sig);
    Ok(pegin_confirm.finalize())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeMusig2Data<T> {
    pub take1: Vec<T>,
    pub take2: Vec<T>,
    pub challenge: Vec<T>,
    pub watchtower_challenge_timeout: Vec<T>,
    pub operator_challenge_nack: Vec<T>,
    pub operator_commit_timeout: Vec<T>,
    pub disprove: Vec<T>,
}

pub type CommitteeSecNonces = CommitteeMusig2Data<SecNonce>;
pub type CommitteePubNonces = CommitteeMusig2Data<PubNonce>;
pub type CommitteeNonceSignatures = CommitteeMusig2Data<SchnorrSignature>;
pub type CommitteeAggNonces = CommitteeMusig2Data<AggNonce>;
pub type CommitteePartialSignatures = CommitteeMusig2Data<PartialSignature>;
pub type CommitteeSignatures = CommitteeMusig2Data<TaprootSignature>;

impl<T> CommitteeMusig2Data<T> {
    pub fn validate_length(&self, watchtower_num: usize, verifier_num: usize) -> Result<()> {
        ensure!(self.take1.len() == take1_pre_sign_num(), "invalid number of take1");
        ensure!(self.take2.len() == take2_pre_sign_num(), "invalid number of take2");
        ensure!(self.challenge.len() == challenge_pre_sign_num(), "invalid number of challenge");
        ensure!(
            self.watchtower_challenge_timeout.len()
                == watchtower_challenge_timeout_pre_sign_num(watchtower_num),
            "invalid number of watchtower challenge timeout"
        );
        ensure!(
            self.operator_challenge_nack.len()
                == operator_challenge_nack_pre_sign_num(watchtower_num),
            "invalid number of operator challenge nack"
        );
        ensure!(
            self.operator_commit_timeout.len() == operator_commit_timeout_pre_sign_num(),
            "invalid number of operator commit timeout"
        );
        ensure!(
            self.disprove.len() == disprove_pre_sign_num(verifier_num),
            "invalid number of disprove"
        );
        Ok(())
    }

    pub fn new_empty() -> Self {
        CommitteeMusig2Data {
            take1: vec![],
            take2: vec![],
            challenge: vec![],
            watchtower_challenge_timeout: vec![],
            operator_challenge_nack: vec![],
            operator_commit_timeout: vec![],
            disprove: vec![],
        }
    }
}

pub fn key_aggregation(pubkeys: &[PublicKey]) -> PublicKey {
    generate_n_of_n_public_key(pubkeys).0
}

pub fn committee_pre_sign(
    committee_member_keypair: Keypair,
    committee_member_sec_nonce: CommitteeSecNonces,
    committee_agg_nonce: CommitteeAggNonces,
    graph: &mut BitvmGcGraph,
) -> Result<CommitteePartialSignatures> {
    let verifier_num = graph.verifier_asserts.len();
    let watchtower_num = graph.parameters.watchtower_pubkeys.len();
    committee_member_sec_nonce.validate_length(watchtower_num, verifier_num)?;
    committee_agg_nonce.validate_length(watchtower_num, verifier_num)?;

    let committee_context =
        graph.parameters.instance_parameters.get_committee_context(committee_member_keypair)?;
    let mut res = CommitteePartialSignatures::new_empty();

    {
        // take-1
        let sec_nonces = committee_member_sec_nonce.take1.try_into().unwrap();
        let agg_nonces = committee_agg_nonce.take1.try_into().unwrap();
        match graph.take1.pre_sign(&committee_context, &sec_nonces, &agg_nonces) {
            Ok(v) => res.take1 = v.to_vec(),
            Err(e) => bail!("fail to pre-sign {}: {e}", graph.take1.name()),
        };
    }

    {
        // take-2
        let sec_nonces = committee_member_sec_nonce.take2.try_into().unwrap();
        let agg_nonces = committee_agg_nonce.take2.try_into().unwrap();
        match graph.take2.pre_sign(&committee_context, &sec_nonces, &agg_nonces) {
            Ok(v) => res.take2 = v.to_vec(),
            Err(e) => bail!("fail to pre-sign {}: {e}", graph.take2.name()),
        };
    }

    {
        // challenge
        let sec_nonces = committee_member_sec_nonce.challenge.try_into().unwrap();
        let agg_nonces = committee_agg_nonce.challenge.try_into().unwrap();
        match graph.challenge.pre_sign(&committee_context, &sec_nonces, &agg_nonces) {
            Ok(v) => res.challenge = v.to_vec(),
            Err(e) => bail!("fail to pre-sign {}: {e}", graph.challenge.name()),
        };
    }

    {
        // watchtower challenge timeout
        let mut timeout_sigs = vec![];
        for (i, tx) in graph.watchtower_challenge_timeouts.iter_mut().enumerate() {
            let sec_nonces = [committee_member_sec_nonce.watchtower_challenge_timeout[i].clone()];
            let agg_nonces = [committee_agg_nonce.watchtower_challenge_timeout[i].clone()];
            let sigs = tx
                .pre_sign(&committee_context, &sec_nonces, &agg_nonces)
                .map_err(|e| anyhow::anyhow!("fail to pre-sign {}: {e}", tx.name()))?;
            timeout_sigs.extend(sigs);
        }
        res.watchtower_challenge_timeout = timeout_sigs;
    }

    {
        // operator challenge nack
        let mut nack_sigs = vec![];
        for (i, tx) in graph.operator_challenge_nacks.iter_mut().enumerate() {
            let sec_nonces = [
                committee_member_sec_nonce.operator_challenge_nack[i * 2].clone(),
                committee_member_sec_nonce.operator_challenge_nack[i * 2 + 1].clone(),
            ];
            let agg_nonces = [
                committee_agg_nonce.operator_challenge_nack[i * 2].clone(),
                committee_agg_nonce.operator_challenge_nack[i * 2 + 1].clone(),
            ];
            let sigs = tx
                .pre_sign(&committee_context, &sec_nonces, &agg_nonces)
                .map_err(|e| anyhow::anyhow!("fail to pre-sign {}: {e}", tx.name()))?;
            nack_sigs.extend(sigs);
        }
        res.operator_challenge_nack = nack_sigs;
    }

    {
        // operator commit timeout
        let sec_nonces = committee_member_sec_nonce.operator_commit_timeout.try_into().unwrap();
        let agg_nonces = committee_agg_nonce.operator_commit_timeout.try_into().unwrap();
        match graph.operator_commit_timeout.pre_sign(&committee_context, &sec_nonces, &agg_nonces) {
            Ok(v) => res.operator_commit_timeout = v.to_vec(),
            Err(e) => bail!("fail to pre-sign {}: {e}", graph.operator_commit_timeout.name()),
        };
    }

    {
        // disprove
        let mut disprove_sigs = vec![];
        for (i, disprove_tx) in graph.disproves.iter_mut().enumerate() {
            let sec_nonces = [
                committee_member_sec_nonce.disprove[i * 2].clone(),
                committee_member_sec_nonce.disprove[i * 2 + 1].clone(),
            ];
            let agg_nonces = [
                committee_agg_nonce.disprove[i * 2].clone(),
                committee_agg_nonce.disprove[i * 2 + 1].clone(),
            ];
            let sigs = disprove_tx
                .pre_sign(&committee_context, &sec_nonces, &agg_nonces)
                .map_err(|e| anyhow::anyhow!("fail to pre-sign {}: {e}", disprove_tx.name()))?;
            disprove_sigs.extend(sigs);
        }
        res.disprove = disprove_sigs;
    }

    Ok(res)
}

pub fn nonce_aggregation(pub_nonces: &Vec<PubNonce>) -> AggNonce {
    generate_aggregated_nonce(pub_nonces)
}

pub fn nonces_aggregation(pub_nonces_vec: &[CommitteePubNonces]) -> Result<CommitteeAggNonces> {
    fn aggregate_field<F>(rows: &[CommitteePubNonces], get: F) -> Result<Vec<AggNonce>>
    where
        F: Fn(&CommitteePubNonces) -> &Vec<PubNonce>,
    {
        if rows.is_empty() {
            return Ok(Vec::new());
        }

        let expected = get(&rows[0]).len();

        for (idx, r) in rows.iter().enumerate() {
            if get(r).len() != expected {
                bail!("length mismatch on row {}: expected {}, got {}", idx, expected, get(r).len())
            }
        }

        Ok((0..expected)
            .map(|i| {
                let column: Vec<PubNonce> = rows.iter().map(|r| get(r)[i].clone()).collect();
                nonce_aggregation(&column)
            })
            .collect())
    }

    Ok(CommitteeAggNonces {
        take1: aggregate_field(pub_nonces_vec, |c| &c.take1)?,
        take2: aggregate_field(pub_nonces_vec, |c| &c.take2)?,
        challenge: aggregate_field(pub_nonces_vec, |c| &c.challenge)?,
        watchtower_challenge_timeout: aggregate_field(pub_nonces_vec, |c| {
            &c.watchtower_challenge_timeout
        })?,
        operator_challenge_nack: aggregate_field(pub_nonces_vec, |c| &c.operator_challenge_nack)?,
        operator_commit_timeout: aggregate_field(pub_nonces_vec, |c| &c.operator_commit_timeout)?,
        disprove: aggregate_field(pub_nonces_vec, |c| &c.disprove)?,
    })
}

pub fn signature_aggregation(
    partial_sigs: &Vec<CommitteePartialSignatures>,
    agg_nonces: &CommitteeAggNonces,
    graph: &BitvmGcGraph,
) -> Result<CommitteeSignatures> {
    let context = graph.parameters.get_base_context();
    let verifier_num = graph.verifier_asserts.len();
    let watchtower_num = graph.parameters.watchtower_pubkeys.len();
    agg_nonces.validate_length(watchtower_num, verifier_num)?;
    for r in partial_sigs {
        r.validate_length(watchtower_num, verifier_num)?;
    }

    let mut res: CommitteeSignatures = CommitteeSignatures::new_empty();

    // take1
    let take1_agg_nonces = agg_nonces.take1.clone().try_into().unwrap();
    let mut take1_partial_sigs = [vec![], vec![]];
    partial_sigs.iter().for_each(|r| {
        take1_partial_sigs[0].push(r.take1[0]);
        take1_partial_sigs[1].push(r.take1[1]);
    });
    match graph.take1.aggregate_pre_sigs(&context, &take1_partial_sigs, &take1_agg_nonces) {
        Ok(v) => res.take1 = v.to_vec(),
        Err(e) => bail!("fail to aggregate pre-sigs {}: {e}", graph.take1.name()),
    };

    // take2
    let take2_agg_nonces = agg_nonces.take2.clone().try_into().unwrap();
    let take2_partial_sigs = [partial_sigs.iter().map(|r| r.take2[0]).collect()];
    match graph.take2.aggregate_pre_sigs(&context, &take2_partial_sigs, &take2_agg_nonces) {
        Ok(v) => res.take2 = v.to_vec(),
        Err(e) => bail!("fail to aggregate pre-sigs {}: {e}", graph.take2.name()),
    };

    // challenge
    let challenge_agg_nonces = agg_nonces.challenge.clone().try_into().unwrap();
    let challenge_partial_sigs = [partial_sigs.iter().map(|r| r.challenge[0]).collect()];
    match graph.challenge.aggregate_pre_sigs(
        &context,
        &challenge_partial_sigs,
        &challenge_agg_nonces,
    ) {
        Ok(v) => res.challenge = v.to_vec(),
        Err(e) => bail!("fail to aggregate pre-sigs {}: {e}", graph.challenge.name()),
    };

    // watchtower challenge timeout
    let mut timeout_sigs = vec![];
    for (i, tx) in graph.watchtower_challenge_timeouts.iter().enumerate() {
        let agg_nonces = [agg_nonces.watchtower_challenge_timeout[i].clone()];
        let partial_sigs =
            [partial_sigs.iter().map(|r| r.watchtower_challenge_timeout[i]).collect()];
        let sigs = tx
            .aggregate_pre_sigs(&context, &partial_sigs, &agg_nonces)
            .map_err(|e| anyhow::anyhow!("fail to aggregate pre-sigs {}: {e}", tx.name()))?;
        timeout_sigs.extend(sigs);
    }
    res.watchtower_challenge_timeout = timeout_sigs;

    // operator challenge nack
    let mut nack_sigs = vec![];
    for (i, tx) in graph.operator_challenge_nacks.iter().enumerate() {
        let agg_nonces = [
            agg_nonces.operator_challenge_nack[i * 2].clone(),
            agg_nonces.operator_challenge_nack[i * 2 + 1].clone(),
        ];
        let mut partial_sigs_by_input = [vec![], vec![]];
        partial_sigs.iter().for_each(|r| {
            partial_sigs_by_input[0].push(r.operator_challenge_nack[i * 2]);
            partial_sigs_by_input[1].push(r.operator_challenge_nack[i * 2 + 1]);
        });
        let sigs = tx
            .aggregate_pre_sigs(&context, &partial_sigs_by_input, &agg_nonces)
            .map_err(|e| anyhow::anyhow!("fail to aggregate pre-sigs {}: {e}", tx.name()))?;
        nack_sigs.extend(sigs);
    }
    res.operator_challenge_nack = nack_sigs;

    // operator commit timeout
    let operator_commit_timeout_agg_nonces =
        agg_nonces.operator_commit_timeout.clone().try_into().unwrap();
    let mut operator_commit_timeout_partial_sigs = [vec![], vec![]];
    partial_sigs.iter().for_each(|r| {
        operator_commit_timeout_partial_sigs[0].push(r.operator_commit_timeout[0]);
        operator_commit_timeout_partial_sigs[1].push(r.operator_commit_timeout[1]);
    });
    match graph.operator_commit_timeout.aggregate_pre_sigs(
        &context,
        &operator_commit_timeout_partial_sigs,
        &operator_commit_timeout_agg_nonces,
    ) {
        Ok(v) => res.operator_commit_timeout = v.to_vec(),
        Err(e) => bail!("fail to aggregate pre-sigs {}: {e}", graph.operator_commit_timeout.name()),
    };

    // disprove
    let mut disprove_sigs = vec![];
    for (i, disprove_tx) in graph.disproves.iter().enumerate() {
        let _agg_nonces =
            [agg_nonces.disprove[i * 2].clone(), agg_nonces.disprove[i * 2 + 1].clone()];
        let mut _partial_sigs = [vec![], vec![]];
        partial_sigs.iter().for_each(|r| {
            _partial_sigs[0].push(r.disprove[i * 2]);
            _partial_sigs[1].push(r.disprove[i * 2 + 1]);
        });
        let sigs = disprove_tx.aggregate_pre_sigs(&context, &_partial_sigs, &_agg_nonces).map_err(
            |e| anyhow::anyhow!("fail to aggregate pre-sigs {}: {e}", disprove_tx.name()),
        )?;
        disprove_sigs.extend(sigs);
    }
    res.disprove = disprove_sigs;

    Ok(res)
}

pub fn push_committee_pre_signatures(
    graph: &mut BitvmGcGraph,
    sigs: &CommitteeSignatures,
) -> Result<()> {
    let verifier_num = graph.verifier_asserts.len();
    let watchtower_num = graph.parameters.watchtower_pubkeys.len();
    if graph.committee_pre_signed {
        bail!("already pre-signed by committee".to_string())
    };
    sigs.validate_length(watchtower_num, verifier_num)?;

    let network = graph.parameters.instance_parameters.network;
    let n_of_n_taproot_public_key =
        XOnlyPublicKey::from(graph.parameters.instance_parameters.committee_agg_pubkey);
    let operator_taproot_public_key = XOnlyPublicKey::from(graph.parameters.operator_pubkey);
    let connector_0 = Connector0::new(network, &n_of_n_taproot_public_key);
    let connector_a =
        ConnectorA::new(network, &operator_taproot_public_key, &n_of_n_taproot_public_key);
    let connector_c = ConnectorC::new(
        network,
        &n_of_n_taproot_public_key,
        &graph.parameters.operator_assert_wots_pubkey,
    );
    let connector_d =
        ConnectorD::new(network, &operator_taproot_public_key, &n_of_n_taproot_public_key);
    let connector_e = ConnectorE::new(
        network,
        &n_of_n_taproot_public_key,
        &graph.parameters.operator_commit_pubin_wots_pubkey,
    );
    let connector_f =
        ConnectorF::new(network, &operator_taproot_public_key, &n_of_n_taproot_public_key);
    let ack_connectors = graph
        .parameters
        .watchtower_ack_hashlocks
        .iter()
        .map(|hashlock| AckConnector::new(network, &n_of_n_taproot_public_key, *hashlock))
        .collect::<Vec<_>>();

    // take1
    graph.take1.push_pre_sigs(&connector_0, &connector_c, sigs.take1.clone().try_into().unwrap());

    // take2
    graph.take2.push_pre_sigs(&connector_0, sigs.take2.clone().try_into().unwrap());

    // challenge
    graph.challenge.push_pre_sigs(&connector_a, sigs.challenge.clone().try_into().unwrap());

    // watchtower challenge timeout
    for (i, tx) in graph.watchtower_challenge_timeouts.iter_mut().enumerate() {
        tx.push_pre_sigs(
            &ack_connectors[i],
            sigs.watchtower_challenge_timeout[i..(i + 1)].try_into().unwrap(),
        );
    }

    // operator challenge nack
    for (i, tx) in graph.operator_challenge_nacks.iter_mut().enumerate() {
        tx.push_pre_sigs(
            &ack_connectors[i],
            &connector_f,
            sigs.operator_challenge_nack[i * 2..(i * 2 + 2)].try_into().unwrap(),
        );
    }

    // operator commit timeout
    graph.operator_commit_timeout.push_pre_sigs(
        &connector_e,
        &connector_f,
        sigs.operator_commit_timeout.clone().try_into().unwrap(),
    );

    // disprove
    for (i, disprove_tx) in graph.disproves.iter_mut().enumerate() {
        let prover_connector = ProverConnector::new(
            network,
            n_of_n_taproot_public_key,
            graph.parameters.gc_data[i].final_msg_hashlocks.clone(),
        );
        disprove_tx.push_pre_sigs(
            &prover_connector,
            &connector_d,
            sigs.disprove[i * 2..(i * 2 + 2)].try_into().unwrap(),
        );
    }

    graph.committee_pre_signed = true;
    Ok(())
}

pub fn generate_nonce_from_seed(
    seed: String,
    graph_index: usize,
    signer_keypair: Keypair,
    watchtower_num: usize,
    verifier_num: usize,
) -> (CommitteePubNonces, CommitteeSecNonces, CommitteeNonceSignatures) {
    let graph_seed = hkdf_derive_bytes(
        seed.as_bytes(),
        COMMITTEE_NONCE_HKDF_SALT,
        format!("graph/{graph_index}").as_bytes(),
        32,
    );
    let mut pub_nonces = CommitteePubNonces::new_empty();
    let mut sec_nonces = CommitteeSecNonces::new_empty();
    let mut nonce_sigs = CommitteeNonceSignatures::new_empty();
    let mut index = 0;
    {
        // take1
        for _ in 0..take1_pre_sign_num() {
            let (sec_nonce, pub_nonce, nonce_sig) =
                generate_nonce(signer_keypair, &graph_seed, index);
            pub_nonces.take1.push(pub_nonce);
            sec_nonces.take1.push(sec_nonce);
            nonce_sigs.take1.push(nonce_sig);
            index += 1;
        }
    }
    {
        // take2
        for _ in 0..take2_pre_sign_num() {
            let (sec_nonce, pub_nonce, nonce_sig) =
                generate_nonce(signer_keypair, &graph_seed, index);
            pub_nonces.take2.push(pub_nonce);
            sec_nonces.take2.push(sec_nonce);
            nonce_sigs.take2.push(nonce_sig);
            index += 1;
        }
    }
    {
        // challenge
        for _ in 0..challenge_pre_sign_num() {
            let (sec_nonce, pub_nonce, nonce_sig) =
                generate_nonce(signer_keypair, &graph_seed, index);
            pub_nonces.challenge.push(pub_nonce);
            sec_nonces.challenge.push(sec_nonce);
            nonce_sigs.challenge.push(nonce_sig);
            index += 1;
        }
    }
    {
        // watchtower challenge timeout
        for _ in 0..watchtower_challenge_timeout_pre_sign_num(watchtower_num) {
            let (sec_nonce, pub_nonce, nonce_sig) =
                generate_nonce(signer_keypair, &graph_seed, index);
            pub_nonces.watchtower_challenge_timeout.push(pub_nonce);
            sec_nonces.watchtower_challenge_timeout.push(sec_nonce);
            nonce_sigs.watchtower_challenge_timeout.push(nonce_sig);
            index += 1;
        }
    }
    {
        // operator challenge nack
        for _ in 0..operator_challenge_nack_pre_sign_num(watchtower_num) {
            let (sec_nonce, pub_nonce, nonce_sig) =
                generate_nonce(signer_keypair, &graph_seed, index);
            pub_nonces.operator_challenge_nack.push(pub_nonce);
            sec_nonces.operator_challenge_nack.push(sec_nonce);
            nonce_sigs.operator_challenge_nack.push(nonce_sig);
            index += 1;
        }
    }
    {
        // operator commit timeout
        for _ in 0..operator_commit_timeout_pre_sign_num() {
            let (sec_nonce, pub_nonce, nonce_sig) =
                generate_nonce(signer_keypair, &graph_seed, index);
            pub_nonces.operator_commit_timeout.push(pub_nonce);
            sec_nonces.operator_commit_timeout.push(sec_nonce);
            nonce_sigs.operator_commit_timeout.push(nonce_sig);
            index += 1;
        }
    }
    {
        // disprove
        for _ in 0..disprove_pre_sign_num(verifier_num) {
            let (sec_nonce, pub_nonce, nonce_sig) =
                generate_nonce(signer_keypair, &graph_seed, index);
            pub_nonces.disprove.push(pub_nonce);
            sec_nonces.disprove.push(sec_nonce);
            nonce_sigs.disprove.push(nonce_sig);
            index += 1;
        }
    }
    (pub_nonces, sec_nonces, nonce_sigs)
}

pub fn verify_nonce_signatures(
    pubkey: &XOnlyPublicKey,
    pub_nonces: &CommitteePubNonces,
    nonce_sigs: &CommitteeNonceSignatures,
    watchtower_num: usize,
    verifier_num: usize,
) -> Result<bool> {
    pub_nonces.validate_length(watchtower_num, verifier_num)?;
    nonce_sigs.validate_length(watchtower_num, verifier_num)?;

    fn verify_vec(pubkey: &XOnlyPublicKey, nonces: &[PubNonce], sigs: &[SchnorrSignature]) -> bool {
        if nonces.len() != sigs.len() {
            return false;
        }
        nonces.iter().zip(sigs.iter()).all(|(nonce, sig)| verify_public_nonce(sig, nonce, pubkey))
    }

    Ok(verify_vec(pubkey, &pub_nonces.take1, &nonce_sigs.take1)
        && verify_vec(pubkey, &pub_nonces.take2, &nonce_sigs.take2)
        && verify_vec(pubkey, &pub_nonces.challenge, &nonce_sigs.challenge)
        && verify_vec(
            pubkey,
            &pub_nonces.watchtower_challenge_timeout,
            &nonce_sigs.watchtower_challenge_timeout,
        )
        && verify_vec(
            pubkey,
            &pub_nonces.operator_challenge_nack,
            &nonce_sigs.operator_challenge_nack,
        )
        && verify_vec(
            pubkey,
            &pub_nonces.operator_commit_timeout,
            &nonce_sigs.operator_commit_timeout,
        )
        && verify_vec(pubkey, &pub_nonces.disprove, &nonce_sigs.disprove))
}

pub(crate) fn generate_nonce(
    signer_keypair: Keypair,
    seed: &[u8],
    index: usize,
) -> (SecNonce, PubNonce, SchnorrSignature) {
    let nonce_seed =
        hkdf_derive_bytes(seed, COMMITTEE_NONCE_HKDF_SALT, format!("nonce/{index}").as_bytes(), 32);
    let nonce_seed: [u8; 32] =
        nonce_seed.try_into().expect("hkdf output length is fixed to 32 bytes");
    let sec_nonce = SecNonce::build(nonce_seed).build();
    let pub_nonce = sec_nonce.public_nonce();
    let nonce_signature = signer_keypair.sign_schnorr(get_nonce_message(&pub_nonce));
    (sec_nonce, pub_nonce, nonce_signature)
}
