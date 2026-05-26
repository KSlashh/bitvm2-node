use std::collections::BTreeMap;

use anyhow::{Result, bail};
use bitcoin::{
    Address, Amount, Network, OutPoint, PrivateKey, PublicKey, TxOut, Witness, XOnlyPublicKey,
    key::Keypair, taproot::LeafVersion,
};
use goat::{
    assert_scripts::{INPUT_WIRE_NUM, LabelHash, OperatorAssertPublicKey, WireHash},
    connectors::{base::TaprootConnector, connector_0::Connector0, connector_z::ConnectorZ},
    contexts::{base::BaseContext, committee::CommitteeContext, operator::OperatorContext},
    transactions::{
        assert::{DisproveTransaction, OperatorAssertTransaction, VerifierAssertTransaction},
        base::*,
        challenge::ChallengeTransaction,
        kickoff::KickoffTransaction,
        pegin::*,
        pre_signed::PreSignedTransaction,
        prekickoff::{
            ChallengeIncompleteKickoffTransaction, ForceSkipKickoffTransaction,
            PrekickoffTransaction, QuickChallengeTransaction,
        },
        take1::Take1Transaction,
        take2::Take2Transaction,
        watchtower_challenge::WatchtowerChallengeInitTransaction,
    },
};
use secp256k1::SECP256K1;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use uuid::Uuid;

use crate::{
    committee::{CommitteeSignatures, push_committee_pre_signatures},
    operator::{generate_bitvm_graph, push_operator_pre_signature},
};

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct UserInfo {
    pub depositor_evm_address: [u8; 20],
    pub txn_fees: [u64; 3],
    pub inputs: Vec<Input>,
    pub user_xonly_pubkey: XOnlyPublicKey,
    #[serde(with = "node_serializer::address")]
    pub user_change_address: Address,
    #[serde(with = "node_serializer::address")]
    pub user_refund_address: Address,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct BitvmGcInstanceParameters {
    pub network: Network,
    pub instance_id: Uuid,
    pub user_info: UserInfo,
    pub pegin_amount: Amount,
    pub committee_pubkeys: Vec<PublicKey>,
    pub committee_agg_pubkey: PublicKey,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct PrekickoffParameters {
    pub cur_prekickoff_txn: PrekickoffTransaction,
    pub replenish_fee_inputs: Vec<Input>,
    pub replenish_fee_prev_outs: Vec<TxOut>,
    pub fee_amount: u64,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct BitvmGcGraphParameters {
    pub instance_parameters: BitvmGcInstanceParameters,
    pub prekickoff_parameters: PrekickoffParameters,
    pub graph_id: Uuid,
    pub graph_nonce: u64,
    pub challenge_amount: Amount,
    pub operator_pubkey: PublicKey,
    #[serde(with = "BigArray")]
    pub operator_wots_pubkeys: OperatorAssertPublicKey,
    #[serde(with = "node_serializer::address")]
    pub operator_receive_address: Address,
    pub watchtower_pubkeys: Vec<XOnlyPublicKey>,
    pub gc_data: Vec<BitvmGcCircuitData>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct BitvmGcCircuitData {
    pub final_msg_hashlocks: Vec<LabelHash>,
    #[serde(with = "BigArray")]
    pub wire_hashes: [WireHash; INPUT_WIRE_NUM],
}

impl BitvmGcInstanceParameters {
    pub fn build_pegin_tx(
        &self,
    ) -> Result<(PegInDepositTransaction, PegInConfirmTransaction, PegInRefundTransaction)> {
        let network = self.network;
        let n_of_n_taproot_public_key = XOnlyPublicKey::from(self.committee_agg_pubkey);
        let user_taproot_public_key = self.user_info.user_xonly_pubkey;
        let connector_0 = Connector0::new(network, &n_of_n_taproot_public_key);
        let connector_z =
            ConnectorZ::new(network, &n_of_n_taproot_public_key, &user_taproot_public_key);
        let pegin_message = [
            get_magic_bytes(&network),
            self.instance_id.as_bytes().to_vec(),
            self.user_info.depositor_evm_address.to_vec(),
        ]
        .concat();

        let pegin_deposit = PegInDepositTransaction::new_unsigned(
            &connector_z,
            self.user_info.inputs.clone(),
            self.pegin_amount + Amount::from_sat(self.user_info.txn_fees[1]),
            Amount::from_sat(self.user_info.txn_fees[0]),
            self.user_info.user_change_address.clone(),
        )
        .map_err(|e| anyhow::anyhow!("fail to build pegin deposit txn: {e}"))?;
        let deposit_outpoint = Input {
            outpoint: OutPoint { txid: pegin_deposit.tx().compute_txid(), vout: 0 },
            amount: pegin_deposit.tx().output[0].value,
        };
        let pegin_confirm = PegInConfirmTransaction::new_for_validation(
            &connector_0,
            &connector_z,
            deposit_outpoint.clone(),
            Amount::from_sat(self.user_info.txn_fees[1]),
            pegin_message,
        )
        .map_err(|e| anyhow::anyhow!("fail to build pegin confirm txn: {e}"))?;
        let pegin_refund = PegInRefundTransaction::new_for_validation(
            &connector_z,
            deposit_outpoint,
            &self.user_info.user_refund_address,
            Amount::from_sat(self.user_info.txn_fees[2]),
        )
        .map_err(|e| anyhow::anyhow!("fail to build pegin refund txn: {e}"))?;

        Ok((pegin_deposit, pegin_confirm, pegin_refund))
    }

    pub fn build_pegin_cancel_psbt(&self) -> Result<bitcoin::psbt::Psbt> {
        let network = self.network;
        let n_of_n_taproot_public_key = XOnlyPublicKey::from(self.committee_agg_pubkey);
        let user_taproot_public_key = self.user_info.user_xonly_pubkey;
        let connector_z =
            ConnectorZ::new(network, &n_of_n_taproot_public_key, &user_taproot_public_key);

        let pegin_deposit = PegInDepositTransaction::new_unsigned(
            &connector_z,
            self.user_info.inputs.clone(),
            self.pegin_amount + Amount::from_sat(self.user_info.txn_fees[1]),
            Amount::from_sat(self.user_info.txn_fees[0]),
            self.user_info.user_change_address.clone(),
        )
        .map_err(|e| anyhow::anyhow!("fail to build pegin deposit txn: {e}"))?;
        let deposit_outpoint = Input {
            outpoint: OutPoint { txid: pegin_deposit.tx().compute_txid(), vout: 0 },
            amount: pegin_deposit.tx().output[0].value,
        };
        let pegin_refund = PegInRefundTransaction::new_for_validation(
            &connector_z,
            deposit_outpoint.clone(),
            &self.user_info.user_refund_address,
            Amount::from_sat(self.user_info.txn_fees[2]),
        )
        .map_err(|e| anyhow::anyhow!("fail to build pegin refund txn: {e}"))?;

        let mut psbt = bitcoin::psbt::Psbt::from_unsigned_tx(pegin_refund.tx().clone()).unwrap();
        let taproot_spend_info = connector_z.generate_taproot_spend_info();
        let mut tap_scripts = BTreeMap::new();
        let tap_script_1 = connector_z.generate_taproot_leaf_script(1);
        tap_scripts.insert(
            taproot_spend_info
                .control_block(&(tap_script_1.clone(), LeafVersion::TapScript))
                .unwrap(),
            (tap_script_1, LeafVersion::TapScript),
        );
        let psbt_input_0 = bitcoin::psbt::Input {
            witness_utxo: {
                Some(TxOut {
                    value: deposit_outpoint.amount,
                    script_pubkey: connector_z.generate_taproot_address().script_pubkey(),
                })
            },
            tap_merkle_root: taproot_spend_info.merkle_root(),
            tap_internal_key: Some(n_of_n_taproot_public_key),
            tap_scripts,
            ..Default::default()
        };
        psbt.inputs[0] = psbt_input_0;

        Ok(psbt)
    }

    pub fn get_committee_context(
        &self,
        committee_member_keypair: Keypair,
    ) -> Result<CommitteeContext> {
        let network = self.network;
        let committee_public_key = self.committee_agg_pubkey;
        let committee_taproot_public_key = XOnlyPublicKey::from(committee_public_key);
        let private_key = PrivateKey::new(committee_member_keypair.secret_key(), network);
        let committee_member_public_key = PublicKey::from_private_key(SECP256K1, &private_key);
        if !self.committee_pubkeys.contains(&committee_member_public_key) {
            bail!("The provided committee member keypair does not match any committee public key");
        }
        Ok(CommitteeContext {
            network,
            committee_keypair: committee_member_keypair,
            committee_public_key: committee_member_public_key,
            n_of_n_public_keys: self.committee_pubkeys.clone(),
            n_of_n_public_key: committee_public_key,
            n_of_n_taproot_public_key: committee_taproot_public_key,
        })
    }

    pub fn get_base_context(&self) -> BaseBitvmContext {
        let network = self.network;
        let n_of_n_public_keys = self.committee_pubkeys.clone();
        let n_of_n_public_key = self.committee_agg_pubkey;
        let n_of_n_taproot_public_key = XOnlyPublicKey::from(n_of_n_public_key);
        BaseBitvmContext {
            network,
            n_of_n_public_keys,
            n_of_n_public_key,
            n_of_n_taproot_public_key,
        }
    }
}

impl BitvmGcGraphParameters {
    pub fn get_operator_context(&self, operator_keypair: Keypair) -> Result<OperatorContext> {
        let network = self.instance_parameters.network;
        let operator_public_key = self.operator_pubkey;
        let operator_taproot_public_key = XOnlyPublicKey::from(operator_public_key);
        let committee_public_key = self.instance_parameters.committee_agg_pubkey;
        let committee_taproot_public_key = XOnlyPublicKey::from(committee_public_key);
        if operator_public_key
            != PublicKey::from_private_key(
                SECP256K1,
                &PrivateKey::new(operator_keypair.secret_key(), network),
            )
        {
            bail!("The provided operator keypair does not match the operator public key");
        }
        Ok(OperatorContext {
            network,
            operator_keypair,
            operator_public_key,
            operator_taproot_public_key,

            n_of_n_public_keys: self.instance_parameters.committee_pubkeys.clone(),
            n_of_n_public_key: committee_public_key,
            n_of_n_taproot_public_key: committee_taproot_public_key,
        })
    }

    pub fn get_base_context(&self) -> BaseBitvmContext {
        self.instance_parameters.get_base_context()
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct BitvmGcGraph {
    pub(crate) operator_pre_signed: bool,
    pub(crate) committee_pre_signed: bool,
    pub parameters: BitvmGcGraphParameters,

    pub cur_prekickoff: PrekickoffTransaction,
    pub next_prekickoff: PrekickoffTransaction,
    pub force_skip_kickoff: ForceSkipKickoffTransaction,
    pub quick_challenge: QuickChallengeTransaction,
    pub challenge_incomplete_kickoff: ChallengeIncompleteKickoffTransaction,

    pub pegin: PegInConfirmTransaction,
    pub kickoff: KickoffTransaction,
    pub take1: Take1Transaction,
    pub challenge: ChallengeTransaction,
    pub watchtower_challenge_init: WatchtowerChallengeInitTransaction,
    pub operator_assert: OperatorAssertTransaction,
    pub verifier_asserts: Vec<VerifierAssertTransaction>,
    pub disproves: Vec<DisproveTransaction>,
    pub take2: Take2Transaction,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct SimplifiedBitvmGcGraph {
    pub(crate) operator_pre_signed: bool,
    pub(crate) committee_pre_signed: bool,
    pub parameters: BitvmGcGraphParameters,
    pub operator_pre_sigs: Option<Vec<Witness>>,
    pub committee_pre_sigs: Option<CommitteeSignatures>,
}

impl BitvmGcGraph {
    pub fn operator_pre_signed(&self) -> bool {
        self.operator_pre_signed
    }
    pub fn committee_pre_signed(&self) -> bool {
        self.committee_pre_signed
    }
    pub fn to_simplified(&self) -> Result<SimplifiedBitvmGcGraph> {
        fn extract_sig_from_witness(witness: &Witness) -> Result<bitcoin::taproot::Signature> {
            witness
                .nth(0)
                .and_then(|data| bitcoin::taproot::Signature::from_slice(data).ok())
                .ok_or_else(|| anyhow::anyhow!("No valid signature found in witness"))
        }
        let operator_pre_sigs = if self.operator_pre_signed {
            Some(vec![
                self.force_skip_kickoff.tx().input[0].witness.clone(),
                self.force_skip_kickoff.tx().input[1].witness.clone(),
                self.quick_challenge.tx().input[0].witness.clone(),
                self.quick_challenge.tx().input[1].witness.clone(),
                self.challenge_incomplete_kickoff.tx().input[0].witness.clone(),
                self.challenge_incomplete_kickoff.tx().input[1].witness.clone(),
            ])
        } else {
            None
        };
        let committee_pre_sigs = if self.committee_pre_signed {
            let take1 = vec![
                extract_sig_from_witness(&self.take1.tx().input[0].witness)?,
                extract_sig_from_witness(&self.take1.tx().input[3].witness)?,
            ];
            let take2 = vec![extract_sig_from_witness(&self.take2.tx().input[0].witness)?];
            let challenge = vec![extract_sig_from_witness(&self.challenge.tx().input[0].witness)?];
            let mut disprove = Vec::new();
            for disprove_tx in &self.disproves {
                disprove.push(extract_sig_from_witness(&disprove_tx.tx().input[0].witness)?);
                disprove.push(extract_sig_from_witness(&disprove_tx.tx().input[1].witness)?);
            }
            Some(CommitteeSignatures { take1, take2, challenge, disprove })
        } else {
            None
        };
        Ok(SimplifiedBitvmGcGraph {
            operator_pre_signed: self.operator_pre_signed,
            committee_pre_signed: self.committee_pre_signed,
            parameters: self.parameters.clone(),
            operator_pre_sigs,
            committee_pre_sigs,
        })
    }
    pub fn from_simplified(simplified: &SimplifiedBitvmGcGraph) -> Result<BitvmGcGraph> {
        let mut graph = generate_bitvm_graph(simplified.parameters.clone())?;
        if simplified.operator_pre_signed {
            let operator_pre_sigs = simplified
                .operator_pre_sigs
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Missing operator pre signatures"))?;
            push_operator_pre_signature(&mut graph, operator_pre_sigs)?;
            graph.operator_pre_signed = true;
        }
        if simplified.committee_pre_signed {
            let committee_pre_sigs = simplified
                .committee_pre_sigs
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Missing committee pre signatures"))?;
            push_committee_pre_signatures(&mut graph, committee_pre_sigs)?;
            graph.committee_pre_signed = true;
        }
        Ok(graph)
    }
}

pub struct BaseBitvmContext {
    pub network: Network,
    pub n_of_n_public_keys: Vec<PublicKey>,
    pub n_of_n_public_key: PublicKey,
    pub n_of_n_taproot_public_key: XOnlyPublicKey,
}

impl BaseContext for BaseBitvmContext {
    fn network(&self) -> Network {
        self.network
    }
    fn n_of_n_public_keys(&self) -> &Vec<PublicKey> {
        &self.n_of_n_public_keys
    }
    fn n_of_n_public_key(&self) -> &PublicKey {
        &self.n_of_n_public_key
    }
    fn n_of_n_taproot_public_key(&self) -> &XOnlyPublicKey {
        &self.n_of_n_taproot_public_key
    }
}

pub fn get_magic_bytes(net: &Network) -> Vec<u8> {
    match net {
        Network::Bitcoin => hex::encode(b"GTV6").as_bytes().to_vec(),
        _ => hex::encode(b"GTT6").as_bytes().to_vec(),
    }
}

pub mod node_serializer {
    use bitcoin::Address;
    use serde::{Deserialize, Deserializer, Serializer};
    use std::str::FromStr;

    pub mod address {
        use super::*;

        pub fn serialize<S>(addr: &Address, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(&addr.to_string())
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Address, D::Error>
        where
            D: Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            Address::from_str(&s)
                .map(|addr| addr.assume_checked())
                .map_err(serde::de::Error::custom)
        }
    }
}
