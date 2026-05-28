use std::collections::HashSet;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;

use anyhow::{Result, bail};
use ark_bn254::{Bn254, Fq, Fr};
use ark_groth16::VerifyingKey as Groth16VerifyingKey;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bitvm::signatures::{Wots, Wots64};
use garbled_snark_verifier::bag::S;
use goat::assert_scripts::{
    INPUT_WIRE_NUM, OperatorAssertPublicKey, OperatorAssertSecretKey, WireHash, label_hash,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use soldering_host::BabeBundle;
pub use soldering_host::BabeBundleBuilder;
use verifiable_circuit_babe::babe::{
    BabeBtcSig, LAMPORT_N, ProverSetupState, VerifierSetupState, WeKnownPi1SetupCt as RealSetupCt,
    babe_prover_assert, babe_prover_presign, babe_verifier_challenge_assert_cac,
    babe_verifier_presign,
};
use verifiable_circuit_babe::cac::{
    CACSetupPackage as RealCACSetupPackage, FinalizedInstanceData as RealFinalizedInstanceData,
    cac_finalize_indices,
};
use verifiable_circuit_babe::gc::{
    SparseAdaptorEntry as RealSparseAdaptorEntry, SparseAdaptorRow as RealSparseAdaptorRow,
    SparseAdaptorTable as RealSparseAdaptorTable,
};
use verifiable_circuit_babe::instance::BABEInstance;
use verifiable_circuit_babe::instance::commit::CACInstanceCommit as RealCACInstanceCommit;
use verifiable_circuit_babe::prover::BABEProver;
use verifiable_circuit_babe::soldering::{
    SolderingData as RealSolderingData, SolderingProof as RealSolderingProof,
};
use verifiable_circuit_babe::transactions::{
    TxAssertWitness, TxChallengeAssertWitness as RealTxChallengeAssertWitness,
};
use verifiable_circuit_babe::utils::pi1_to_wots64_msg;
use verifiable_circuit_babe::verifier::BABEVerifier;

use crate::types::BitvmGcCircuitData;

/// Number of Wots64 digit signatures expected by the remote GOAT connector.
pub const WOTS_SIG_COUNT: usize = Wots64::TOTAL_DIGIT_LEN as usize;
pub const BABE_N_CC: usize = 181;
// TODO: use verifiable_circuit_babe::babe::M_CC instead
pub const BABE_M_CC: usize = 4;

pub type OpenedInstanceSeeds = Vec<(usize, u64)>;
pub type FinalizedInstances = Vec<FinalizedInstanceData>;
pub type SetupAndSolderingData = (OpenedInstanceSeeds, FinalizedInstances, SolderingData);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CACSetupPackage {
    pub commits: Vec<CACInstanceCommit>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CACInstanceCommit {
    pub epk: Vec<[[u8; 20]; 2]>,
    pub wots_padding_epk: [[[u8; 20]; 2]; 4],
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
    pub wots_padding_zero_labels: [[u8; 16]; 4],
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
    pub wots_sig: Vec<[u8; 21]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BabeChallengeAssertWitness {
    pub verifier_index: usize,
    pub input_labels: Vec<[u8; 16]>,
    pub wots_sig: Vec<[u8; 21]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BabeWronglyChallengedWitness {
    pub verifier_index: usize,
    pub final_msgs: Vec<Vec<u8>>,
}

impl CACInstanceCommit {
    /// Builds deterministic placeholder setup commitments for tests and wiring.
    pub fn sample(seed: u8) -> Self {
        let epk = (0..LAMPORT_N)
            .map(|wire| [hash20(&[seed, wire as u8, 0]), hash20(&[seed, wire as u8, 1])])
            .collect();
        Self {
            epk,
            wots_padding_epk: padding_wire_hashes(),
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
    soldering_builder: &BabeBundleBuilder,
    private_state: &BabeVerifierPrivateState,
    package: &CACSetupPackage,
    finalized_indices: &[usize],
    vk: &Groth16VerifyingKey<Bn254>,
    public_inputs: &[Fr],
) -> Result<SetupAndSolderingData> {
    ensure_real_gc_assets_configured()?;
    if private_state.statement_digest != statement_digest(vk, public_inputs)? {
        bail!("BABE setup statement does not match persisted verifier state");
    }
    validate_finalized_indices(package, finalized_indices)?;
    let verifier = restore_real_verifier(private_state, vk, public_inputs)?;
    if from_real_package(&verifier.commit()) != *package {
        bail!("persisted BABE verifier state does not reproduce setup package");
    }
    let bundle = soldering_builder
        .babe_verifier_open_and_solder(&verifier, finalized_indices)
        .map_err(anyhow::Error::msg)?;
    Ok((
        bundle.opened,
        bundle
            .finalized
            .iter()
            .map(|data| from_real_finalized(data, package))
            .collect::<Result<Vec<_>>>()?,
        from_real_soldering(&bundle.soldering)?,
    ))
}

/// Verifies real CAC openings, commitments, and the native Ziren soldering proof.
pub fn verify_real_setup(
    soldering_builder: &BabeBundleBuilder,
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

    let bundle = BabeBundle {
        opened: opened.to_vec(),
        finalized: real_finalized,
        soldering: to_real_soldering(soldering)?,
        temp_hashlock: [0u8; 20],
    };
    soldering_builder
        .babe_prover_verify_setup(&real_package, &bundle, vk, public_inputs)
        .map_err(anyhow::Error::msg)
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
) -> Result<SetupAndSolderingData> {
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
    if finalized.len() != BABE_M_CC {
        bail!("each verifier must contribute exactly {BABE_M_CC} finalized BABE instances");
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
    Ok(BitvmGcCircuitData {
        verifier_pubkey,
        final_msg_hashlocks: finalized.iter().map(|data| data.final_msg_hash).collect(),
        wire_hashes,
    })
}

/// Builds the native BABE assertion witness from the validated wrapper Groth16 proof.
pub fn build_assert_witness(
    proof: &ark_groth16::Proof<Bn254>,
    assert_secret_key: &OperatorAssertSecretKey,
) -> Result<BabeAssertWitness> {
    if assert_secret_key.is_empty() {
        bail!("operator WOTS secret key must not be empty");
    }
    let real_witness = babe_prover_assert(proof, assert_secret_key);
    Ok(BabeAssertWitness { pi1: real_witness.pi1, wots_sig: real_witness.wots_sig.to_vec() })
}

pub fn assert_wots_message(assert_witness: &BabeAssertWitness) -> Result<[u8; 64]> {
    let pi1 = ark_bn254::G1Affine::deserialize_compressed(assert_witness.pi1.as_slice())
        .map_err(|error| anyhow::anyhow!("invalid BABE pi1 in assert witness: {error}"))?;
    Ok(pi1_to_wots64_msg(&pi1))
}

/// Builds a placeholder verifier challenge witness from an assert witness.
pub fn build_challenge_assert_witness(
    verifier_state: &BabeVerifierState,
    assert_witness: &BabeAssertWitness,
    verifier_index: usize,
) -> Result<BabeChallengeAssertWitness> {
    if verifier_state.finalized_indices.len() != BABE_M_CC {
        bail!("verifier state must contain exactly {BABE_M_CC} finalized BABE instances");
    }
    if assert_witness.pi1.is_empty() || assert_witness.wots_sig.is_empty() {
        bail!("invalid assert witness");
    }
    Ok(BabeChallengeAssertWitness {
        verifier_index,
        input_labels: (0usize..INPUT_WIRE_NUM)
            .map(|index| hash16_with_index(&assert_witness.pi1, index))
            .collect(),
        wots_sig: assert_witness.wots_sig.clone(),
    })
}

/// Verifies a native operator assertion and reveals the real base-instance labels.
#[allow(clippy::too_many_arguments)]
pub fn build_real_challenge_assert_witness(
    private_state: &BabeVerifierPrivateState,
    package: &CACSetupPackage,
    finalized_indices: &[usize],
    vk: &Groth16VerifyingKey<Bn254>,
    public_inputs: &[Fr],
    operator_wots_pubkey: &OperatorAssertPublicKey,
    assert_witness: &BabeAssertWitness,
    verifier_index: usize,
) -> Result<BabeChallengeAssertWitness> {
    if finalized_indices.len() != BABE_M_CC {
        bail!("verifier state must contain exactly {BABE_M_CC} finalized BABE instances");
    }
    let verifier = restore_real_verifier(private_state, vk, public_inputs)?;
    if from_real_package(&verifier.commit()) != *package {
        bail!("persisted BABE verifier state does not reproduce setup package");
    }
    let real_assert_witness = TxAssertWitness {
        pi1: assert_witness.pi1.clone(),
        wots_sig: to_real_wots_sig(&assert_witness.wots_sig)?,
    };
    let real_verifier_state = VerifierSetupState {
        verifier,
        package: to_real_package(package),
        finalized_indices: finalized_indices.to_vec(),
        wots_pk_p: *operator_wots_pubkey,
        presigs_p: babe_prover_presign(),
    };
    let real_witness = babe_verifier_challenge_assert_cac(
        &real_assert_witness,
        &real_verifier_state,
        BabeBtcSig::ProverPresigChallengeAssert,
    )
    .ok_or_else(|| anyhow::anyhow!("operator BABE assertion WOTS signature is invalid"))?;
    Ok(BabeChallengeAssertWitness {
        verifier_index,
        input_labels: real_witness.input_labels,
        wots_sig: real_witness.wots_sig.to_vec(),
    })
}

/// Builds a wrongly-challenged witness from every recovered finalized-message preimage.
pub fn build_wrongly_challenged_witness(
    prover_state: &BabeProverState,
    challenge_witness: &BabeChallengeAssertWitness,
    final_msgs: Vec<Vec<u8>>,
) -> Result<BabeWronglyChallengedWitness> {
    build_wrongly_challenged_witness_from_preimages(
        &prover_state.h_msgs,
        challenge_witness,
        final_msgs,
    )
}

/// Evaluates the native BABE garbled circuit and returns all finalized hashlock preimages.
pub fn recover_real_wrongly_challenged_witness(
    prover_state: &BabeProverState,
    challenge_witness: &BabeChallengeAssertWitness,
    proof: &ark_groth16::Proof<Bn254>,
) -> Result<BabeWronglyChallengedWitness> {
    let real_state = ProverSetupState {
        wots_sk_p: vec![],
        finalized: prover_state
            .finalized
            .iter()
            .map(to_real_finalized)
            .collect::<Result<Vec<_>>>()?,
        soldering: to_real_soldering(&prover_state.soldering)?,
        h_msgs: prover_state.h_msgs.clone(),
        presigs_v: babe_verifier_presign(),
    };
    let real_challenge = RealTxChallengeAssertWitness {
        input_labels: challenge_witness.input_labels.clone(),
        wots_sig: to_real_wots_sig(&challenge_witness.wots_sig)?,
        sig_v: BabeBtcSig::VerifierLiveSig,
        sig_p: BabeBtcSig::ProverPresigChallengeAssert,
    };
    recover_all_finalized_messages(
        prover_state,
        challenge_witness,
        proof,
        &real_state,
        &real_challenge,
    )
}

/// Builds a wrongly-challenged witness after validating all finalized preimages.
pub fn build_wrongly_challenged_witness_from_preimages(
    h_msgs: &[[u8; 20]],
    challenge_witness: &BabeChallengeAssertWitness,
    final_msgs: Vec<Vec<u8>>,
) -> Result<BabeWronglyChallengedWitness> {
    if h_msgs.len() != BABE_M_CC {
        bail!("wrongly challenged setup must contain exactly {BABE_M_CC} finalized hashlocks");
    }
    if final_msgs.len() != h_msgs.len() {
        bail!("wrongly challenged witness must provide every finalized preimage");
    }
    for (position, (final_msg, expected_hash)) in final_msgs.iter().zip(h_msgs).enumerate() {
        if label_hash(final_msg) != *expected_hash {
            bail!("message at finalized position {position} is not a valid preimage");
        }
    }
    Ok(BabeWronglyChallengedWitness {
        verifier_index: challenge_witness.verifier_index,
        final_msgs,
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
        wots_padding_epk: padding_wire_hashes(),
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
    if commit.epk.len() != LAMPORT_N {
        bail!(
            "finalized index {} has {} BABE input commitments; expected {LAMPORT_N}",
            finalized.index,
            commit.epk.len()
        );
    }
    let mut wire_hashes = Vec::with_capacity(INPUT_WIRE_NUM);
    wire_hashes.extend(commit.epk[..254].iter().map(to_wire_hash));
    wire_hashes.extend(commit.wots_padding_epk[..2].iter().map(to_wire_hash));
    wire_hashes.extend(commit.epk[254..].iter().map(to_wire_hash));
    wire_hashes.extend(commit.wots_padding_epk[2..].iter().map(to_wire_hash));
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
            wots_padding_zero_labels: [[0u8; 16]; 4],
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

fn from_real_soldering(soldering: &RealSolderingData) -> Result<SolderingData> {
    let output = soldering.soldering_proof.output().map_err(anyhow::Error::msg)?;
    Ok(SolderingData {
        finalized_indices: soldering.finalized_indices.clone(),
        soldered_output: SolderedLabelsData {
            base_commitment: output.base_commitment.clone(),
            deltas: output.deltas.clone(),
            commitments: output.commitments.clone(),
        },
        proof: bincode::serialize(&soldering.soldering_proof.proof)?,
    })
}

fn to_real_soldering(soldering: &SolderingData) -> Result<RealSolderingData> {
    if soldering.proof.is_empty() {
        bail!("soldering proof is empty");
    }
    Ok(RealSolderingData {
        finalized_indices: soldering.finalized_indices.clone(),
        soldering_proof: RealSolderingProof { proof: bincode::deserialize(&soldering.proof)? },
    })
}

fn recover_all_finalized_messages(
    prover_state: &BabeProverState,
    challenge_witness: &BabeChallengeAssertWitness,
    proof: &ark_groth16::Proof<Bn254>,
    real_state: &ProverSetupState,
    real_challenge: &RealTxChallengeAssertWitness,
) -> Result<BabeWronglyChallengedWitness> {
    if real_state.finalized.len() != prover_state.h_msgs.len() {
        bail!("BABE prover state finalized data and hash count differ");
    }
    if real_state.finalized.is_empty() {
        bail!("BABE prover state has no finalized instances");
    }

    let base_input_labels = pi1_labels_from_challenge(&real_challenge.input_labels)?;
    let soldered_output = &prover_state.soldering.soldered_output;
    if soldered_output.base_commitment.len() != base_input_labels.len() {
        bail!(
            "soldering base commitment count {} does not match BABE input label count {}",
            soldered_output.base_commitment.len(),
            base_input_labels.len()
        );
    }

    let prover = BABEProver::new(proof.clone());
    let final_msgs = real_state
        .finalized
        .iter()
        .zip(&prover_state.h_msgs)
        .enumerate()
        .map(|(position, (finalized, expected_hash))| {
            let input_labels =
                soldered_input_labels(&base_input_labels, soldered_output, position)?;
            recover_finalized_message(
                &prover,
                proof,
                finalized,
                &input_labels,
                *expected_hash,
                position,
            )
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(BabeWronglyChallengedWitness {
        verifier_index: challenge_witness.verifier_index,
        final_msgs,
    })
}

fn pi1_labels_from_challenge(input_labels: &[[u8; 16]]) -> Result<Vec<S>> {
    if input_labels.len() == LAMPORT_N {
        return Ok(input_labels.iter().copied().map(S).collect());
    }
    if input_labels.len() != INPUT_WIRE_NUM {
        bail!(
            "challenge witness has {} input labels; expected {LAMPORT_N} or {INPUT_WIRE_NUM}",
            input_labels.len()
        );
    }
    Ok(input_labels[..254].iter().chain(&input_labels[256..510]).copied().map(S).collect())
}

fn soldered_input_labels(
    base_input_labels: &[S],
    soldered_output: &SolderedLabelsData,
    finalized_position: usize,
) -> Result<Vec<S>> {
    if finalized_position == 0 {
        return Ok(base_input_labels.to_vec());
    }
    let deltas = soldered_output.deltas.get(finalized_position - 1).ok_or_else(|| {
        anyhow::anyhow!("missing soldering deltas for finalized position {finalized_position}")
    })?;
    if deltas.len() != base_input_labels.len() {
        bail!(
            "soldering delta count {} does not match BABE input label count {}",
            deltas.len(),
            base_input_labels.len()
        );
    }

    Ok(base_input_labels
        .iter()
        .enumerate()
        .map(|(wire, &base_label)| {
            let (delta_false, delta_true) = deltas[wire];
            if hash32(&base_label.0) == soldered_output.base_commitment[wire].0 {
                base_label ^ S(delta_false)
            } else {
                base_label ^ S(delta_true)
            }
        })
        .collect())
}

fn recover_finalized_message(
    prover: &BABEProver,
    proof: &ark_groth16::Proof<Bn254>,
    finalized: &RealFinalizedInstanceData,
    input_labels: &[S],
    expected_hash: [u8; 20],
    finalized_position: usize,
) -> Result<Vec<u8>> {
    let mut full_labels = Vec::with_capacity(2 + input_labels.len());
    full_labels.push(finalized.constant_labels[0]);
    full_labels.push(finalized.constant_labels[1]);
    full_labels.extend_from_slice(input_labels);

    let (mut circuit, gc_output_indices) = verifiable_circuit_babe::gc::read_fresh_circuit();
    let ct_prove = prover.compute_ct_prove(
        &mut circuit,
        &gc_output_indices,
        &full_labels,
        &finalized.gc_ciphertexts,
        &finalized.adaptor_table,
    );
    let msg = BABEProver::compute_msg(proof, &ct_prove, &finalized.ct_setup)
        .map_err(anyhow::Error::msg)?;
    let final_msg = msg.to_vec();
    if label_hash(&final_msg) != expected_hash {
        bail!(
            "recovered message at finalized position {finalized_position} does not match hashlock"
        );
    }
    Ok(final_msg)
}

fn to_real_wots_sig(wots_sig: &[[u8; 21]]) -> Result<<Wots64 as Wots>::Signature> {
    wots_sig.try_into().map_err(|_| {
        anyhow::anyhow!(
            "WOTS signature has {} digit signatures; expected {WOTS_SIG_COUNT}",
            wots_sig.len()
        )
    })
}

fn padding_wire_hashes() -> [[[u8; 20]; 2]; 4] {
    let false_hash = label_hash(&vec![0u8; 16]);
    let true_hash = label_hash(&vec![1u8; 16]);
    [[false_hash, true_hash]; 4]
}

fn deterministic_seed(index: usize) -> u64 {
    u64::from_le_bytes(hash32(&(index as u64).to_le_bytes())[0..8].try_into().expect("8 bytes"))
}

fn to_wire_hash(pair: &[[u8; 20]; 2]) -> WireHash {
    WireHash { false_label_hash: pair[0], true_label_hash: pair[1] }
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
