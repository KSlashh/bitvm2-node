use std::collections::HashSet;
use std::marker::PhantomData;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;

use anyhow::{Result, bail};
use ark_bn254::{Bn254, Fq, Fr};
use ark_groth16::VerifyingKey as Groth16VerifyingKey;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use garbled_snark_verifier::bag::S;
use goat::assert_scripts::{INPUT_WIRE_NUM, WireHash};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use verifiable_circuit_babe::babe::WeKnownPi1SetupCt as RealSetupCt;
use verifiable_circuit_babe::cac::{
    CACSetupPackage as RealCACSetupPackage, FinalizedInstanceData as RealFinalizedInstanceData,
    cac_finalize_indices, verify_finalized_instances, verify_opened_instances,
};
use verifiable_circuit_babe::gc::{
    SparseAdaptorEntry as RealSparseAdaptorEntry, SparseAdaptorRow as RealSparseAdaptorRow,
    SparseAdaptorTable as RealSparseAdaptorTable,
};
use verifiable_circuit_babe::instance::BABEInstance;
use verifiable_circuit_babe::instance::commit::CACInstanceCommit as RealCACInstanceCommit;
use verifiable_circuit_babe::prover::BABEProver;
use verifiable_circuit_babe::soldering::{
    SolderedLabelsData as RealSolderedLabelsData, SolderingData as RealSolderingData,
    SolderingProof as RealSolderingProof,
};
use verifiable_circuit_babe::verifier::BABEVerifier;

use crate::types::BitvmGcCircuitData;

/// Number of Lamport signature fragments expected by the current operator assert witness.
pub const LAMPORT_SIG_COUNT: usize = 508;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CACSetupPackage {
    pub commits: Vec<CACInstanceCommit>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CACInstanceCommit {
    pub epk: Vec<[[u8; 20]; 2]>,
    pub constant_commits: [[[u8; 32]; 2]; 2],
    pub h_msg: [u8; 20],
    pub h_ct_setup: [u8; 32],
    pub com_adaptor: [u8; 32],
    pub com_gc: [u8; 32],
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalizedInstanceData {
    pub index: usize,
    pub final_msg_hash: [u8; 20],
    pub wire_hashes: Vec<WireHash>,
    pub gc_commitment: [u8; 32],
    pub adaptor_commitment: [u8; 32],
    pub ct_setup_commitment: [u8; 32],
    pub real_data: Option<RealFinalizedPayload>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealFinalizedPayload {
    pub gc_ciphertexts: Vec<Option<[u8; 16]>>,
    pub adaptor_table: SerializableSparseAdaptorTable,
    pub ct_setup: SerializableSetupCt,
    pub constant_labels: [[u8; 16]; 2],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializableSetupCt {
    pub ct2_r_delta_g2: Vec<u8>,
    pub ct3_masked_msg: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializableSparseAdaptorTable {
    pub entries: Vec<SerializableSparseAdaptorEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializableSparseAdaptorEntry {
    pub x: SerializableSparseAdaptorRow,
    pub y: SerializableSparseAdaptorRow,
    pub z: SerializableSparseAdaptorRow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializableSparseAdaptorRow {
    pub cts: Vec<[u8; 32]>,
    pub offset: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolderingData {
    pub finalized_indices: Vec<usize>,
    pub soldered_output: SolderedLabelsData,
    pub proof: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SolderedLabelsData {
    pub base_commitment: Vec<([u8; 32], [u8; 32])>,
    pub deltas: Vec<Vec<([u8; 16], [u8; 16])>>,
    pub commitments: Vec<Vec<([u8; 32], [u8; 32])>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BabeVerifierPrivateState {
    pub instance_seeds: Vec<u64>,
    pub temp_val: [u8; 32],
    pub statement_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BabeVerifierState {
    pub package: CACSetupPackage,
    pub finalized_indices: Vec<usize>,
    pub verifier_pubkey: bitcoin::PublicKey,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BabeProverState {
    pub package: CACSetupPackage,
    pub finalized: Vec<FinalizedInstanceData>,
    pub soldering: SolderingData,
    pub h_msgs: Vec<[u8; 20]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BabeAssertWitness {
    pub pi1: Vec<u8>,
    pub lamport_sig: Vec<[u8; 16]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BabeChallengeAssertWitness {
    pub verifier_index: usize,
    pub input_labels: Vec<[u8; 16]>,
    pub lamport_sig: Vec<[u8; 16]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BabeWronglyChallengedWitness {
    pub verifier_index: usize,
    pub msg: Vec<u8>,
}

impl CACInstanceCommit {
    /// Builds deterministic placeholder setup commitments for tests and wiring.
    pub fn sample(seed: u8) -> Self {
        let epk = (0..INPUT_WIRE_NUM)
            .map(|wire| [hash20(&[seed, wire as u8, 0]), hash20(&[seed, wire as u8, 1])])
            .collect();
        Self {
            epk,
            constant_commits: [
                [hash32(&[seed, 0xf0, 0]), hash32(&[seed, 0xf0, 1])],
                [hash32(&[seed, 0xf1, 0]), hash32(&[seed, 0xf1, 1])],
            ],
            h_msg: hash20(&[seed, 0xa0]),
            h_ct_setup: hash32(&[seed, 0xa1]),
            com_adaptor: hash32(&[seed, 0xa2]),
            com_gc: hash32(&[seed, 0xa3]),
        }
    }
}

impl FinalizedInstanceData {
    /// Builds deterministic placeholder finalized data for tests and graph wiring.
    pub fn sample(index: usize) -> Self {
        let seed = index as u8;
        let wire_hashes = (0..INPUT_WIRE_NUM)
            .map(|wire| WireHash {
                true_label_hash: hash20(&[seed, wire as u8, 1]),
                false_label_hash: hash20(&[seed, wire as u8, 0]),
            })
            .collect();
        Self {
            index,
            final_msg_hash: hash20(&[seed, 0xb0]),
            wire_hashes,
            gc_commitment: hash32(&[seed, 0xb1]),
            adaptor_commitment: hash32(&[seed, 0xb2]),
            ct_setup_commitment: hash32(&[seed, 0xb3]),
            real_data: None,
        }
    }
}

impl SolderingData {
    /// Builds deterministic placeholder soldering data for the selected finalized indices.
    pub fn sample(finalized_indices: Vec<usize>) -> Self {
        Self { finalized_indices, soldered_output: SolderedLabelsData::default(), proof: vec![] }
    }
}

/// Builds a deterministic placeholder CAC setup package with `n_cc` instances.
pub fn build_setup_package(n_cc: usize) -> Result<CACSetupPackage> {
    if n_cc == 0 {
        bail!("n_cc must be greater than zero");
    }
    Ok(CACSetupPackage {
        commits: (0..n_cc).map(|index| CACInstanceCommit::sample(index as u8)).collect(),
    })
}

/// Builds a real random BABE/CAC setup package bound to the supplied Groth16 statement.
pub fn build_real_setup_package(
    n_cc: usize,
    vk: &Groth16VerifyingKey<Bn254>,
    public_inputs: &[Fr],
) -> Result<(CACSetupPackage, BabeVerifierPrivateState)> {
    if n_cc == 0 {
        bail!("n_cc must be greater than zero");
    }
    ensure_real_gc_assets_configured()?;
    let verifier = catch_unwind(AssertUnwindSafe(|| BABEVerifier::new(n_cc, vk, public_inputs)))
        .map_err(|_| anyhow::anyhow!("real BABE verifier setup panicked while loading GC assets"))?
        .map_err(anyhow::Error::msg)?;
    let package = from_real_package(&verifier.commit());
    let private_state = BabeVerifierPrivateState {
        instance_seeds: verifier.instances.iter().map(|instance| instance.seed).collect(),
        temp_val: verifier.temp_val,
        statement_digest: statement_digest(vk, public_inputs)?,
    };

    Ok((package, private_state))
}

/// Reconstructs the real Verifier instances and creates CAC opening/soldering output data.
pub fn open_real_setup_and_solder(
    private_state: &BabeVerifierPrivateState,
    package: &CACSetupPackage,
    finalized_indices: &[usize],
    vk: &Groth16VerifyingKey<Bn254>,
    public_inputs: &[Fr],
) -> Result<(Vec<(usize, u64)>, Vec<FinalizedInstanceData>, SolderingData)> {
    ensure_real_gc_assets_configured()?;
    if private_state.statement_digest != statement_digest(vk, public_inputs)? {
        bail!("BABE setup statement does not match persisted verifier state");
    }
    validate_finalized_indices(package, finalized_indices)?;
    let verifier = restore_real_verifier(private_state, vk, public_inputs)?;
    if from_real_package(&verifier.commit()) != *package {
        bail!("persisted BABE verifier state does not reproduce setup package");
    }
    // TODO: soldering.soldering_proof should use the real proof
    let (opened, finalized, soldering, _) =
        verifiable_circuit_babe::babe::babe_verifier_open_and_solder(&verifier, finalized_indices);
    Ok((
        opened,
        finalized
            .iter()
            .map(|data| from_real_finalized(data, package))
            .collect::<Result<Vec<_>>>()?,
        from_real_soldering(&soldering),
    ))
}

/// Verifies real CAC openings and commitments, then rejects unavailable Ziren proof validation.
pub fn verify_real_setup(
    package: &CACSetupPackage,
    opened: &[(usize, u64)],
    finalized: &[FinalizedInstanceData],
    soldering: &SolderingData,
    vk: &Groth16VerifyingKey<Bn254>,
    public_inputs: &[Fr],
) -> Result<()> {
    let real_package = to_real_package(package);
    let real_finalized = finalized
        .iter()
        .map(to_real_finalized)
        .collect::<Result<Vec<RealFinalizedInstanceData>>>()?;

    verify_opened_instances(&real_package, opened, vk, public_inputs)
        .map_err(anyhow::Error::msg)?;
    verify_finalized_instances(&real_package, &real_finalized).map_err(anyhow::Error::msg)?;

    let real_soldering = to_real_soldering(soldering);
    BABEProver::verify_soldering_output(&real_package, &real_soldering)
        .map_err(anyhow::Error::msg)?;

    // TODO: use real Ziren soldering proof verification
    bail!("real Ziren soldering proof verification is not integrated; refuse setup completion")
}

/// Derives finalized circuit indices using the real BABE/CAC Fiat-Shamir selection.
pub fn derive_finalized_indices(package: &CACSetupPackage, m_cc: usize) -> Result<Vec<usize>> {
    let n_cc = package.commits.len();
    if m_cc == 0 || m_cc > n_cc {
        bail!("invalid m_cc {m_cc} for n_cc {n_cc}");
    }
    Ok(cac_finalize_indices(&to_real_package(package), m_cc))
}

/// Opens non-finalized placeholder instances and returns finalized data plus soldering data.
pub fn open_and_solder(
    package: &CACSetupPackage,
    finalized_indices: &[usize],
) -> Result<(Vec<(usize, u64)>, Vec<FinalizedInstanceData>, SolderingData)> {
    let finalized_set = finalized_indices.iter().copied().collect::<HashSet<_>>();
    if finalized_set.len() != finalized_indices.len() {
        bail!("duplicate finalized index");
    }
    if finalized_indices.iter().any(|index| *index >= package.commits.len()) {
        bail!("finalized index out of range");
    }
    let opened = (0..package.commits.len())
        .filter(|index| !finalized_set.contains(index))
        .map(|index| (index, deterministic_seed(index)))
        .collect::<Vec<_>>();
    let finalized =
        finalized_indices.iter().map(|index| FinalizedInstanceData::sample(*index)).collect();
    let soldering = SolderingData::sample(finalized_indices.to_vec());
    Ok((opened, finalized, soldering))
}

/// Validates placeholder opened, finalized, and soldering data consistency.
pub fn verify_setup(
    package: &CACSetupPackage,
    opened: &[(usize, u64)],
    finalized: &[FinalizedInstanceData],
    soldering: &SolderingData,
) -> Result<()> {
    let n_cc = package.commits.len();
    let finalized_set = finalized.iter().map(|data| data.index).collect::<HashSet<_>>();
    if finalized_set.len() != finalized.len() {
        bail!("duplicate finalized data");
    }
    for (index, seed) in opened {
        if *index >= n_cc {
            bail!("opened index {index} out of range");
        }
        if finalized_set.contains(index) {
            bail!("index {index} cannot be both opened and finalized");
        }
        if *seed != deterministic_seed(*index) {
            bail!("opened seed mismatch for index {index}");
        }
    }
    if soldering.finalized_indices != finalized.iter().map(|data| data.index).collect::<Vec<_>>() {
        bail!("soldering finalized indices mismatch");
    }
    for data in finalized {
        if data.index >= n_cc {
            bail!("finalized index {} out of range", data.index);
        }
        if data.wire_hashes.len() != INPUT_WIRE_NUM {
            bail!("finalized index {} has invalid wire hash count", data.index);
        }
    }
    Ok(())
}

/// Extracts one graph slot owned by `verifier_pubkey` from finalized setup data.
pub fn extract_gc_circuit_data(
    finalized: &[FinalizedInstanceData],
    soldering: &SolderingData,
    verifier_pubkey: bitcoin::PublicKey,
) -> Result<BitvmGcCircuitData> {
    if finalized.len() != 1 {
        bail!("each verifier must contribute exactly one finalized GC slot");
    }
    if soldering.finalized_indices != finalized.iter().map(|data| data.index).collect::<Vec<_>>() {
        bail!("soldering finalized indices mismatch");
    }
    let data = &finalized[0];
    let wire_hashes: [WireHash; INPUT_WIRE_NUM] =
        data.wire_hashes.clone().try_into().map_err(|wire_hashes: Vec<WireHash>| {
            anyhow::anyhow!(
                "BABE input label count {} is incompatible with GOAT verifier connector wire count {INPUT_WIRE_NUM}",
                wire_hashes.len()
            )
        })?;
    Ok(BitvmGcCircuitData { verifier_pubkey, final_msg_hash: data.final_msg_hash, wire_hashes })
}

/// Builds a placeholder BABE assert witness from serialized proof bytes.
pub fn build_assert_witness(proof_bytes: &[u8]) -> Result<BabeAssertWitness> {
    if proof_bytes.is_empty() {
        bail!("operator proof is empty");
    }
    Ok(BabeAssertWitness {
        pi1: hash32(proof_bytes).to_vec(),
        lamport_sig: (0usize..LAMPORT_SIG_COUNT)
            .map(|index| hash16_with_index(proof_bytes, index))
            .collect(),
    })
}

/// Builds a placeholder verifier challenge witness from an assert witness.
pub fn build_challenge_assert_witness(
    verifier_state: &BabeVerifierState,
    assert_witness: &BabeAssertWitness,
    verifier_index: usize,
) -> Result<BabeChallengeAssertWitness> {
    if verifier_index >= verifier_state.finalized_indices.len() {
        bail!("verifier index {verifier_index} out of range");
    }
    if assert_witness.pi1.is_empty() || assert_witness.lamport_sig.is_empty() {
        bail!("invalid assert witness");
    }
    Ok(BabeChallengeAssertWitness {
        verifier_index,
        input_labels: (0usize..INPUT_WIRE_NUM)
            .map(|index| hash16_with_index(&assert_witness.pi1, index))
            .collect(),
        lamport_sig: assert_witness.lamport_sig.clone(),
    })
}

/// Builds a placeholder wrongly-challenged witness for the challenged verifier index.
pub fn build_wrongly_challenged_witness(
    prover_state: &BabeProverState,
    challenge_witness: &BabeChallengeAssertWitness,
) -> Result<BabeWronglyChallengedWitness> {
    build_wrongly_challenged_witness_from_h_msgs(&prover_state.h_msgs, challenge_witness)
}

/// Builds a placeholder wrongly-challenged witness directly from finalized message hashes.
pub fn build_wrongly_challenged_witness_from_h_msgs(
    h_msgs: &[[u8; 20]],
    challenge_witness: &BabeChallengeAssertWitness,
) -> Result<BabeWronglyChallengedWitness> {
    let Some(msg) = h_msgs.get(challenge_witness.verifier_index) else {
        bail!("challenge verifier index out of range");
    };
    Ok(BabeWronglyChallengedWitness {
        verifier_index: challenge_witness.verifier_index,
        msg: msg.to_vec(),
    })
}

fn ensure_real_gc_assets_configured() -> Result<()> {
    for name in ["GC_GATES_PATH", "GC_INDICES_PATH"] {
        let path = PathBuf::from(
            std::env::var(name)
                .map_err(|_| anyhow::anyhow!("{name} is required for real BABE setup"))?,
        );
        if !path.is_file() {
            bail!("{name} does not point to a readable file: {}", path.display());
        }
    }
    Ok(())
}

fn statement_digest(vk: &Groth16VerifyingKey<Bn254>, public_inputs: &[Fr]) -> Result<[u8; 32]> {
    let mut bytes = Vec::new();
    vk.serialize_compressed(&mut bytes)?;
    for public_input in public_inputs {
        public_input.serialize_compressed(&mut bytes)?;
    }
    Ok(hash32(&bytes))
}

fn restore_real_verifier(
    state: &BabeVerifierPrivateState,
    vk: &Groth16VerifyingKey<Bn254>,
    public_inputs: &[Fr],
) -> Result<BABEVerifier> {
    let instances = state
        .instance_seeds
        .iter()
        .map(|seed| {
            let mut instance = BABEInstance::new_from_seed(*seed);
            instance.enc_setup(vk, public_inputs).map_err(anyhow::Error::msg)?;
            Ok(instance)
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(BABEVerifier { instances, temp_val: state.temp_val })
}

fn validate_finalized_indices(
    package: &CACSetupPackage,
    finalized_indices: &[usize],
) -> Result<()> {
    let finalized_set = finalized_indices.iter().copied().collect::<HashSet<_>>();
    if finalized_set.len() != finalized_indices.len() {
        bail!("duplicate finalized index");
    }
    if finalized_indices.is_empty() {
        bail!("at least one finalized index is required");
    }
    if finalized_indices.iter().any(|index| *index >= package.commits.len()) {
        bail!("finalized index out of range");
    }
    Ok(())
}

fn from_real_package(package: &RealCACSetupPackage) -> CACSetupPackage {
    CACSetupPackage { commits: package.commits.iter().map(from_real_commit).collect() }
}

fn from_real_commit(commit: &RealCACInstanceCommit) -> CACInstanceCommit {
    CACInstanceCommit {
        epk: commit.epk.clone(),
        constant_commits: commit.constant_commits,
        h_msg: commit.h_msg,
        h_ct_setup: commit.h_ct_setup,
        com_adaptor: commit.com_adaptor,
        com_gc: commit.com_gc,
    }
}

fn to_real_package(package: &CACSetupPackage) -> RealCACSetupPackage {
    RealCACSetupPackage {
        commits: package
            .commits
            .iter()
            .map(|commit| RealCACInstanceCommit {
                epk: commit.epk.clone(),
                constant_commits: commit.constant_commits,
                h_msg: commit.h_msg,
                h_ct_setup: commit.h_ct_setup,
                com_adaptor: commit.com_adaptor,
                com_gc: commit.com_gc,
            })
            .collect(),
    }
}

fn from_real_finalized(
    finalized: &RealFinalizedInstanceData,
    package: &CACSetupPackage,
) -> Result<FinalizedInstanceData> {
    let commit = package
        .commits
        .get(finalized.index)
        .ok_or_else(|| anyhow::anyhow!("finalized index {} out of range", finalized.index))?;
    let wire_hashes = commit
        .epk
        .iter()
        .map(|pair| WireHash { false_label_hash: pair[0], true_label_hash: pair[1] })
        .collect();
    Ok(FinalizedInstanceData {
        index: finalized.index,
        final_msg_hash: commit.h_msg,
        wire_hashes,
        gc_commitment: commit.com_gc,
        adaptor_commitment: commit.com_adaptor,
        ct_setup_commitment: commit.h_ct_setup,
        real_data: Some(RealFinalizedPayload {
            gc_ciphertexts: finalized
                .gc_ciphertexts
                .iter()
                .map(|ciphertext| ciphertext.map(|label| label.0))
                .collect(),
            adaptor_table: from_real_adaptor_table(&finalized.adaptor_table),
            ct_setup: SerializableSetupCt {
                ct2_r_delta_g2: finalized.ct_setup.ct2_r_delta_g2.clone(),
                ct3_masked_msg: finalized.ct_setup.ct3_masked_msg.clone(),
            },
            constant_labels: [finalized.constant_labels[0].0, finalized.constant_labels[1].0],
        }),
    })
}

fn to_real_finalized(finalized: &FinalizedInstanceData) -> Result<RealFinalizedInstanceData> {
    let payload = finalized.real_data.as_ref().ok_or_else(|| {
        anyhow::anyhow!("finalized index {} lacks real BABE payload", finalized.index)
    })?;
    Ok(RealFinalizedInstanceData {
        index: finalized.index,
        gc_ciphertexts: payload.gc_ciphertexts.iter().map(|value| value.map(S)).collect(),
        adaptor_table: to_real_adaptor_table(&payload.adaptor_table)?,
        ct_setup: RealSetupCt {
            ct2_r_delta_g2: payload.ct_setup.ct2_r_delta_g2.clone(),
            ct3_masked_msg: payload.ct_setup.ct3_masked_msg.clone(),
        },
        constant_labels: [S(payload.constant_labels[0]), S(payload.constant_labels[1])],
    })
}

fn from_real_adaptor_table(table: &RealSparseAdaptorTable) -> SerializableSparseAdaptorTable {
    SerializableSparseAdaptorTable {
        entries: table
            .entries
            .iter()
            .map(|entry| SerializableSparseAdaptorEntry {
                x: from_real_adaptor_row(&entry.x),
                y: from_real_adaptor_row(&entry.y),
                z: from_real_adaptor_row(&entry.z),
            })
            .collect(),
    }
}

fn from_real_adaptor_row(row: &RealSparseAdaptorRow) -> SerializableSparseAdaptorRow {
    let mut offset = Vec::new();
    row.offset.serialize_compressed(&mut offset).expect("serialize adaptor offset");
    SerializableSparseAdaptorRow { cts: row.cts.clone(), offset }
}

fn to_real_adaptor_table(table: &SerializableSparseAdaptorTable) -> Result<RealSparseAdaptorTable> {
    Ok(RealSparseAdaptorTable {
        entries: table
            .entries
            .iter()
            .map(|entry| {
                Ok(RealSparseAdaptorEntry {
                    x: to_real_adaptor_row(&entry.x)?,
                    y: to_real_adaptor_row(&entry.y)?,
                    z: to_real_adaptor_row(&entry.z)?,
                })
            })
            .collect::<Result<Vec<_>>>()?,
    })
}

fn to_real_adaptor_row(row: &SerializableSparseAdaptorRow) -> Result<RealSparseAdaptorRow> {
    Ok(RealSparseAdaptorRow {
        cts: row.cts.clone(),
        offset: Fq::deserialize_compressed(row.offset.as_slice())?,
    })
}

fn from_real_soldering(soldering: &RealSolderingData) -> SolderingData {
    let output = &soldering.soldering_proof.soldered_output;
    SolderingData {
        finalized_indices: soldering.finalized_indices.clone(),
        soldered_output: SolderedLabelsData {
            base_commitment: output.base_commitment.clone(),
            deltas: output.deltas.clone(),
            commitments: output.commitments.clone(),
        },
        proof: vec![],
    }
}

fn to_real_soldering(soldering: &SolderingData) -> RealSolderingData {
    RealSolderingData {
        finalized_indices: soldering.finalized_indices.clone(),
        soldering_proof: RealSolderingProof {
            soldered_output: RealSolderedLabelsData {
                base_commitment: soldering.soldered_output.base_commitment.clone(),
                deltas: soldering.soldered_output.deltas.clone(),
                commitments: soldering.soldered_output.commitments.clone(),
            },
            _proof: PhantomData,
        },
    }
}

fn deterministic_seed(index: usize) -> u64 {
    u64::from_le_bytes(hash32(&(index as u64).to_le_bytes())[0..8].try_into().expect("8 bytes"))
}

fn hash20(data: &[u8]) -> [u8; 20] {
    let hash = hash32(data);
    hash[0..20].try_into().expect("20 bytes")
}

fn hash16(data: &[u8]) -> [u8; 16] {
    let hash = hash32(data);
    hash[0..16].try_into().expect("16 bytes")
}

fn hash16_with_index(data: &[u8], index: usize) -> [u8; 16] {
    let mut bytes = Vec::with_capacity(data.len() + std::mem::size_of::<u64>());
    bytes.extend_from_slice(data);
    bytes.extend_from_slice(&(index as u64).to_le_bytes());
    hash16(&bytes)
}

fn hash32(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}
