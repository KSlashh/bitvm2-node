use ark_bn254::Fr;
use ark_crypto_primitives::snark::CircuitSpecificSetupSNARK;
use ark_groth16::Groth16;
use bitvm_gc::babe_adapter::{
    BabeChallengeAssertWitness, BabeProverState, BabeVerifierState, CACInstanceCommit,
    CACSetupPackage, FinalizedInstanceData, LAMPORT_SIG_COUNT, SolderingData, build_assert_witness,
    build_challenge_assert_witness, build_real_setup_package, build_setup_package,
    build_wrongly_challenged_witness, build_wrongly_challenged_witness_from_h_msgs,
    derive_finalized_indices, extract_gc_circuit_data, open_and_solder, open_real_setup_and_solder,
    verify_real_setup, verify_setup,
};
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;
use std::collections::HashSet;
use std::str::FromStr;
use verifiable_circuit_babe::babe::DummyMulCircuit;

fn verifier_pubkey() -> bitcoin::PublicKey {
    bitcoin::PublicKey::from_str(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    )
    .expect("public key")
}

#[test]
#[ignore = "requires GC_GATES_PATH and GC_INDICES_PATH runtime assets"]
fn real_setup_restores_private_state_and_refuses_unverified_soldering_proof() {
    let mut rng = ChaCha12Rng::seed_from_u64(42);
    let a = Fr::from(3_u64);
    let b = Fr::from(7_u64);
    let (_, vk) = Groth16::<ark_bn254::Bn254>::setup(
        DummyMulCircuit::<Fr> { a: Some(a), b: Some(b) },
        &mut rng,
    )
    .expect("groth16 setup");
    let public_inputs = vec![a * b];

    let (package, private_state) =
        build_real_setup_package(1, &vk, &public_inputs).expect("real setup");
    let restored =
        serde_json::from_slice(&serde_json::to_vec(&private_state).expect("serialize state"))
            .expect("deserialize state");
    let (opened, finalized, soldering) =
        open_real_setup_and_solder(&restored, &package, &[0], &vk, &public_inputs)
            .expect("open real setup");

    assert!(opened.is_empty());
    assert_eq!(finalized.len(), 1);
    let error = verify_real_setup(&package, &opened, &finalized, &soldering, &vk, &public_inputs)
        .expect_err("soldering proof must not be treated as verified");
    assert!(error.to_string().contains("soldering proof"));
    let graph_error = match extract_gc_circuit_data(&finalized, &soldering, verifier_pubkey()) {
        Ok(_) => panic!("wire domains must differ"),
        Err(error) => error,
    };
    assert!(graph_error.to_string().contains("incompatible with GOAT verifier connector"));
}

#[test]
fn babe_setup_payload_round_trips_and_derives_gc_data() {
    let package = CACSetupPackage {
        commits: vec![
            CACInstanceCommit::sample(1),
            CACInstanceCommit::sample(2),
            CACInstanceCommit::sample(3),
            CACInstanceCommit::sample(4),
        ],
    };

    let encoded = serde_json::to_vec(&package).expect("serialize package");
    let decoded: CACSetupPackage = serde_json::from_slice(&encoded).expect("deserialize package");
    assert_eq!(decoded, package);

    let finalized_indices = derive_finalized_indices(&decoded, 1).expect("derive finalized");
    assert_eq!(finalized_indices.len(), 1);

    let finalized = vec![FinalizedInstanceData::sample(finalized_indices[0])];
    let soldering = SolderingData::sample(finalized_indices);
    let gc_data = extract_gc_circuit_data(&finalized, &soldering, verifier_pubkey())
        .expect("extract gc data");

    assert_eq!(gc_data.verifier_pubkey, verifier_pubkey());
}

#[test]
fn each_verifier_contributes_exactly_one_gc_slot() {
    let finalized = vec![FinalizedInstanceData::sample(0), FinalizedInstanceData::sample(1)];
    let soldering = SolderingData::sample(vec![0, 1]);

    let error = match extract_gc_circuit_data(&finalized, &soldering, verifier_pubkey()) {
        Ok(_) => panic!("multiple graph slots from one verifier must be rejected"),
        Err(error) => error,
    };

    assert!(error.to_string().contains("exactly one finalized"));
}

#[test]
fn finalized_indices_reject_invalid_counts_and_cover_full_cut() {
    let package = build_setup_package(4).expect("setup package");

    assert!(derive_finalized_indices(&package, 0).is_err());
    assert!(derive_finalized_indices(&package, 5).is_err());

    let first = derive_finalized_indices(&package, 4).expect("derive full cut");
    let second = derive_finalized_indices(&package, 4).expect("derive full cut again");
    assert_eq!(first, second);
    assert_eq!(first.len(), 4);
    assert_eq!(first.iter().copied().collect::<HashSet<_>>().len(), 4);
    assert_eq!(first.iter().copied().collect::<HashSet<_>>(), HashSet::from([0, 1, 2, 3]));
}

#[test]
fn verify_setup_accepts_valid_opening_and_rejects_invalid_shapes() {
    let package = build_setup_package(4).expect("setup package");
    let finalized_indices = derive_finalized_indices(&package, 2).expect("derive finalized");
    let (opened, finalized, soldering) =
        open_and_solder(&package, &finalized_indices).expect("open and solder");

    verify_setup(&package, &opened, &finalized, &soldering).expect("valid setup");

    let mut duplicate_finalized = finalized.clone();
    duplicate_finalized.push(finalized[0].clone());
    assert!(verify_setup(&package, &opened, &duplicate_finalized, &soldering).is_err());

    let mut overlapping_opened = opened.clone();
    overlapping_opened.push((finalized[0].index, 0));
    assert!(verify_setup(&package, &overlapping_opened, &finalized, &soldering).is_err());

    let mut wrong_seed_opened = opened.clone();
    wrong_seed_opened[0].1 ^= 1;
    assert!(verify_setup(&package, &wrong_seed_opened, &finalized, &soldering).is_err());

    let mut mismatched_soldering = soldering.clone();
    mismatched_soldering.finalized_indices.reverse();
    if mismatched_soldering.finalized_indices == soldering.finalized_indices {
        mismatched_soldering.finalized_indices.push(usize::MAX);
    }
    assert!(verify_setup(&package, &opened, &finalized, &mismatched_soldering).is_err());
}

#[test]
fn witness_builders_validate_inputs_and_indices() {
    let assert_witness = build_assert_witness(b"proof").expect("assert witness");
    assert_eq!(assert_witness.lamport_sig.len(), LAMPORT_SIG_COUNT);
    assert!(build_assert_witness(&[]).is_err());

    let verifier_state = BabeVerifierState {
        package: build_setup_package(3).expect("setup package"),
        finalized_indices: vec![0, 1],
        verifier_pubkey: verifier_pubkey(),
    };
    let challenge_witness = build_challenge_assert_witness(&verifier_state, &assert_witness, 1)
        .expect("challenge witness");
    assert_eq!(challenge_witness.verifier_index, 1);
    assert!(build_challenge_assert_witness(&verifier_state, &assert_witness, 2).is_err());

    let prover_state = BabeProverState {
        package: build_setup_package(3).expect("setup package"),
        finalized: vec![FinalizedInstanceData::sample(0), FinalizedInstanceData::sample(1)],
        soldering: SolderingData::sample(vec![0, 1]),
        h_msgs: vec![[1u8; 20], [2u8; 20]],
    };
    let wrongly_challenged = build_wrongly_challenged_witness(&prover_state, &challenge_witness)
        .expect("wrongly challenged witness");
    assert_eq!(wrongly_challenged.msg, vec![2u8; 20]);

    let out_of_range_challenge =
        BabeChallengeAssertWitness { verifier_index: 3, input_labels: vec![], lamport_sig: vec![] };
    assert!(build_wrongly_challenged_witness(&prover_state, &out_of_range_challenge).is_err());
}

#[test]
fn wrongly_challenged_witness_can_be_built_directly_from_h_msgs() {
    let h_msgs = vec![[1u8; 20], [2u8; 20]];
    let challenge_witness =
        BabeChallengeAssertWitness { verifier_index: 1, input_labels: vec![], lamport_sig: vec![] };

    let from_h_msgs = build_wrongly_challenged_witness_from_h_msgs(&h_msgs, &challenge_witness)
        .expect("wrongly challenged witness");
    assert_eq!(from_h_msgs.verifier_index, 1);
    assert_eq!(from_h_msgs.msg, vec![2u8; 20]);

    let prover_state = BabeProverState {
        package: build_setup_package(2).expect("setup package"),
        finalized: vec![FinalizedInstanceData::sample(0), FinalizedInstanceData::sample(1)],
        soldering: SolderingData::sample(vec![0, 1]),
        h_msgs,
    };
    let delegated = build_wrongly_challenged_witness(&prover_state, &challenge_witness)
        .expect("delegated wrongly challenged witness");
    assert_eq!(delegated, from_h_msgs);

    let out_of_range =
        BabeChallengeAssertWitness { verifier_index: 2, input_labels: vec![], lamport_sig: vec![] };
    assert!(
        build_wrongly_challenged_witness_from_h_msgs(&prover_state.h_msgs, &out_of_range).is_err()
    );
}
