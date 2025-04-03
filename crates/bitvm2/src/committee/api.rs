use bitcoin::{Witness, key::Keypair, hex::FromHex, TapSighashType};
use goat::transactions::signing_musig2::{generate_aggregated_nonce, generate_taproot_aggregated_signature};
use musig2::{secp256k1::schnorr::Signature, AggNonce, PartialSignature, PubNonce, SecNonce};
use sha2::{Sha256, Digest};
use goat::transactions::{
    base::BaseTransaction,
    pre_signed::PreSignedTransaction,
    pre_signed_musig2::get_nonce_message,
    signing_musig2::generate_taproot_partial_signature,
};
use goat::connectors::{
    connector_0::Connector0,
    connector_5::Connector5,
    connector_d::ConnectorD,
};
use crate::types::{Bitvm2Graph, Error};

pub const COMMITTEE_PRE_SIGN_NUM: usize = 5;

pub fn committee_pre_sign(
    committee_member_keypair: Keypair,
    committee_member_sec_nonce: [SecNonce; COMMITTEE_PRE_SIGN_NUM],
    committee_agg_nonce: [AggNonce; COMMITTEE_PRE_SIGN_NUM],
    graph: &Bitvm2Graph,
) -> Result<[PartialSignature; COMMITTEE_PRE_SIGN_NUM], Error> {
    let verifier_context = graph.parameters.get_verifier_context(committee_member_keypair);
    let mut res: Vec<PartialSignature> = vec![];

    {   // take-1 input-0, use nonce[0]
        let tx = &graph.take1;
        let input_index = 0;
        let nonce_index = 0;
        let sighash_type = TapSighashType::All;
        match generate_taproot_partial_signature(
            &verifier_context,
            tx.tx(),
            &committee_member_sec_nonce[nonce_index],
            &committee_agg_nonce[nonce_index],
            input_index,
            tx.prev_outs(),
            &tx.prev_scripts()[input_index],
            sighash_type,
        ) {
            Ok(v) => res.push(v),
            Err(e) => return Err(format!("fail to sign {} input-{input_index}: {e}", tx.name())),
        };
    }

    {   // take-2 input-0, use nonce[1]
        let tx = &graph.take2;
        let input_index = 0;
        let nonce_index = 1;
        let sighash_type = TapSighashType::All;
        match generate_taproot_partial_signature(
            &verifier_context,
            tx.tx(),
            &committee_member_sec_nonce[nonce_index],
            &committee_agg_nonce[nonce_index],
            input_index,
            tx.prev_outs(),
            &tx.prev_scripts()[input_index],
            sighash_type,
        ) {
            Ok(v) => res.push(v),
            Err(e) => return Err(format!("fail to sign {} input-{input_index}: {e}", tx.name())),
        };
    }

    {   // take-2 input-2, use nonce[2]
        let tx = &graph.take2;
        let input_index = 2;
        let nonce_index = 2;
        let sighash_type = TapSighashType::All;
        match generate_taproot_partial_signature(
            &verifier_context,
            tx.tx(),
            &committee_member_sec_nonce[nonce_index],
            &committee_agg_nonce[nonce_index],
            input_index,
            tx.prev_outs(),
            &tx.prev_scripts()[input_index],
            sighash_type,
        ) {
            Ok(v) => res.push(v),
            Err(e) => return Err(format!("fail to sign {} input-{input_index}: {e}", tx.name())),
        };
    }

    {   // assert-final input-0, use nonce[3]
        let tx = &graph.assert_final;
        let input_index = 0;
        let nonce_index = 3;
        let sighash_type = TapSighashType::All;
        match generate_taproot_partial_signature(
            &verifier_context,
            tx.tx(),
            &committee_member_sec_nonce[nonce_index],
            &committee_agg_nonce[nonce_index],
            input_index,
            tx.prev_outs(),
            &tx.prev_scripts()[input_index],
            sighash_type,
        ) {
            Ok(v) => res.push(v),
            Err(e) => return Err(format!("fail to sign {} input-{input_index}: {e}", tx.name())),
        };
    }

    {   // disprove input-0, use nonce[4]
        let tx = &graph.disprove;
        let input_index = 0;
        let nonce_index = 4;
        let sighash_type = TapSighashType::Single;
        match generate_taproot_partial_signature(
            &verifier_context,
            tx.tx(),
            &committee_member_sec_nonce[nonce_index],
            &committee_agg_nonce[nonce_index],
            input_index,
            tx.prev_outs(),
            &tx.prev_scripts()[input_index],
            sighash_type,
        ) {
            Ok(v) => res.push(v),
            Err(e) => return Err(format!("fail to sign {} input-{input_index}: {e}", tx.name())),
        };
    }

    Ok(res.try_into().unwrap())
}

pub fn nonce_aggregation(
    pub_nonces: &Vec<PubNonce>
) -> AggNonce {
    generate_aggregated_nonce(pub_nonces)
}

pub fn signature_aggregation_and_push(
    partial_sigs: &[Vec<PartialSignature>; COMMITTEE_PRE_SIGN_NUM],
    agg_nonces: &[AggNonce; COMMITTEE_PRE_SIGN_NUM],
    graph: &mut Bitvm2Graph,
) -> Result<[Witness; COMMITTEE_PRE_SIGN_NUM], Error> {
    let mut res: Vec<Witness> = vec![];

    let network = graph.parameters.network;
    let context = graph.parameters.get_base_context();

    let connector_0 = Connector0::new(
        network,
        &context.n_of_n_taproot_public_key,
    );
    let connector_5 = Connector5::new(
        network,
        &context.n_of_n_taproot_public_key,
    );
    let connector_d = ConnectorD::new(
        network,
        &context.n_of_n_taproot_public_key,
    );

    {   // take-1 input-0
        let tx = &mut graph.take1;
        let input_index = 0;
        let nonce_index = 0;
        let sighash_type = TapSighashType::All;
        let agg_sig = match generate_taproot_aggregated_signature(
            &context, 
            tx.tx(), 
            &agg_nonces[nonce_index], 
            input_index, 
            tx.prev_outs(),
            &tx.prev_scripts()[input_index],
            sighash_type, 
            partial_sigs[nonce_index].clone(),
        ) {
            Ok(v) => bitcoin::taproot::Signature {
                signature: v.into(),
                sighash_type,
            },
            Err(e) => return Err(format!("fail to aggregate partial-signatures of {} input-{input_index}: {e}", tx.name())),
        };
        tx.push_pre_sigs(
            &connector_0, 
            agg_sig,
        );
        res.push(tx.tx().input[input_index].witness.clone())
    }

    {   // take-2 input-0 & input-2
        // take-2 input-0
        let tx = &mut graph.take2;
        let input_index = 0;
        let nonce_index = 1;
        let sighash_type = TapSighashType::All;
        let agg_sig_0 = match generate_taproot_aggregated_signature(
            &context, 
            tx.tx(), 
            &agg_nonces[nonce_index], 
            input_index, 
            tx.prev_outs(),
            &tx.prev_scripts()[input_index],
            sighash_type, 
            partial_sigs[nonce_index].clone(),
        ) {
            Ok(v) => bitcoin::taproot::Signature {
                signature: v.into(),
                sighash_type,
            },
            Err(e) => return Err(format!("fail to aggregate partial-signatures of {} input-{input_index}: {e}", tx.name())),
        };

        // take-2 input-2
        let tx = &mut graph.take2;
        let input_index = 2;
        let nonce_index = 2;
        let sighash_type = TapSighashType::All;
        let agg_sig_2 = match generate_taproot_aggregated_signature(
            &context, 
            tx.tx(), 
            &agg_nonces[nonce_index], 
            input_index, 
            tx.prev_outs(),
            &tx.prev_scripts()[input_index],
            sighash_type, 
            partial_sigs[nonce_index].clone(),
        ) {
            Ok(v) => bitcoin::taproot::Signature {
                signature: v.into(),
                sighash_type,
            },
            Err(e) => return Err(format!("fail to aggregate partial-signatures of {} input-{input_index}: {e}", tx.name())),
        };

        tx.push_pre_sigs(&connector_0, &connector_5, agg_sig_0, agg_sig_2);
        res.push(tx.tx().input[0].witness.clone());
        res.push(tx.tx().input[2].witness.clone());
    }

    {   // assert-final input-0
        let tx = &mut graph.assert_final;
        let input_index = 0;
        let nonce_index = 3;
        let sighash_type = TapSighashType::All;
        let agg_sig = match generate_taproot_aggregated_signature(
            &context, 
            tx.tx(), 
            &agg_nonces[nonce_index], 
            input_index, 
            tx.prev_outs(),
            &tx.prev_scripts()[input_index],
            sighash_type, 
            partial_sigs[nonce_index].clone(),
        ) {
            Ok(v) => bitcoin::taproot::Signature {
                signature: v.into(),
                sighash_type,
            },
            Err(e) => return Err(format!("fail to aggregate partial-signatures of {} input-{input_index}: {e}", tx.name())),
        };

        tx.push_pre_sigs(&connector_d, agg_sig);
        res.push(tx.tx().input[input_index].witness.clone());
    }

    {   // disprove input-0
        let tx = &mut graph.disprove;
        let input_index = 0;
        let nonce_index = 4;
        let sighash_type = TapSighashType::Single;
        let agg_sig = match generate_taproot_aggregated_signature(
            &context, 
            tx.tx(), 
            &agg_nonces[nonce_index], 
            input_index, 
            tx.prev_outs(),
            &tx.prev_scripts()[input_index],
            sighash_type, 
            partial_sigs[nonce_index].clone(),
        ) {
            Ok(v) => bitcoin::taproot::Signature {
                signature: v.into(),
                sighash_type,
            },
            Err(e) => return Err(format!("fail to aggregate partial-signatures of {} input-{input_index}: {e}", tx.name())),
        };

        tx.push_pre_sigs(&connector_5, agg_sig);
        res.push(tx.tx().input[input_index].witness.clone());
    }

    graph.committee_pre_signed = true;

    Ok(res.try_into().unwrap())
}

pub fn push_committee_pre_signatures(
    graph: &mut Bitvm2Graph,
    signed_witness: &[Witness; COMMITTEE_PRE_SIGN_NUM],
) -> Option<Error> {
    if graph.committee_pre_signed == true {
        return Some("already pre-signed by committee".to_string())
    };
    graph.take1.tx_mut().input[0].witness = signed_witness[0].clone();
    graph.take2.tx_mut().input[0].witness = signed_witness[1].clone();
    graph.take2.tx_mut().input[2].witness = signed_witness[2].clone();
    graph.assert_final.tx_mut().input[0].witness = signed_witness[3].clone();
    graph.disprove.tx_mut().input[0].witness = signed_witness[4].clone();
    None
}

pub fn generate_keypair_from_seed(seed: String) -> Keypair {
    let keypair_secret = sha256(&format!("{seed}/master"));
    Keypair::from_seckey_str_global(&keypair_secret).unwrap()
}

pub fn generate_nonce_from_seed(seed: String, graph_index: usize, signer_keypair: Keypair) -> [(SecNonce, PubNonce, Signature); COMMITTEE_PRE_SIGN_NUM] {
    let graph_seed = sha256_with_id(&seed, graph_index);
    let mut res = vec![];
    for i in 0..COMMITTEE_PRE_SIGN_NUM {
        let nonce_seed = sha256_with_id(&graph_seed, i);
        let nonce_seed = <[u8; 32]>::from_hex(&nonce_seed).unwrap();
        let sec_nonce = SecNonce::build(nonce_seed).build();
        let pub_nonce = sec_nonce.public_nonce();
        let nonce_signature = signer_keypair.sign_schnorr(get_nonce_message(&pub_nonce));
        res.push((sec_nonce, pub_nonce, nonce_signature));
    }
    res.try_into().unwrap()
}

fn sha256(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    format!("{:x}", hasher.finalize())
}
fn sha256_with_id(input: &str, idx: usize) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    sha256(&format!("{:x}{:04x}", hasher.finalize(), idx))
}