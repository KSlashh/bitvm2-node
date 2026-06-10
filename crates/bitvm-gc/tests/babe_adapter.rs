use ark_bn254::Fr;
use ark_crypto_primitives::snark::CircuitSpecificSetupSNARK;
use ark_groth16::Groth16;
use bitvm_gc::assert_scripts::{INPUT_WIRE_NUM, label_hash};
use bitvm_gc::babe_adapter::{
    BABE_M_CC, BabeBundleBuilder, BabeChallengeAssertWitness, BabeProverState, BabeVerifierState,
    CACInstanceCommit, CACSetupPackage, FinalizedInstanceData, SolderingData, WOTS_SIG_COUNT,
    build_assert_witness, build_challenge_assert_witness, build_real_setup_package,
    build_setup_package, build_wrongly_challenged_witness,
    build_wrongly_challenged_witness_from_preimages, derive_finalized_indices,
    extract_gc_circuit_data, open_and_solder, open_real_setup_and_solder, verify_real_setup,
    verify_setup,
};
use bitvm_gc::operator::generate_wots_key;
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
fn real_setup_restores_private_state_and_verifies_soldering_proof() {
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
        build_real_setup_package(BABE_M_CC, &vk, &public_inputs).expect("real setup");
    let restored =
        serde_json::from_slice(&serde_json::to_vec(&private_state).expect("serialize state"))
            .expect("deserialize state");
    let soldering_builder = BabeBundleBuilder::new();
    let finalized_indices = (0..BABE_M_CC).collect::<Vec<_>>();
    let (opened, finalized, soldering) = open_real_setup_and_solder(
        &soldering_builder,
        &restored,
        &package,
        &finalized_indices,
        &vk,
        &public_inputs,
    )
    .expect("open real setup");

    assert!(opened.is_empty());
    assert_eq!(finalized.len(), BABE_M_CC);
    verify_real_setup(
        &soldering_builder,
        &package,
        &opened,
        &finalized,
        &soldering,
        &vk,
        &public_inputs,
    )
    .expect("verify soldering proof");
    extract_gc_circuit_data(&finalized, &soldering, verifier_pubkey())
        .expect("extract native 508-wire graph data");
}

#[test]
fn babe_setup_payload_round_trips_and_derives_gc_data() {
    let package = CACSetupPackage {
        commits: (0..BABE_M_CC).map(|index| CACInstanceCommit::sample(index as u8)).collect(),
    };

    let encoded = serde_json::to_vec(&package).expect("serialize package");
    let decoded: CACSetupPackage = serde_json::from_slice(&encoded).expect("deserialize package");
    assert_eq!(decoded, package);

    let finalized_indices =
        derive_finalized_indices(&decoded, BABE_M_CC).expect("derive finalized");
    assert_eq!(finalized_indices.len(), BABE_M_CC);

    let finalized = finalized_indices
        .iter()
        .map(|index| FinalizedInstanceData::sample(*index))
        .collect::<Vec<_>>();
    let soldering = SolderingData::sample(finalized_indices);
    let gc_data = extract_gc_circuit_data(&finalized, &soldering, verifier_pubkey())
        .expect("extract gc data");

    assert_eq!(gc_data.verifier_pubkey, verifier_pubkey());
    assert_eq!(gc_data.final_msg_hashlocks.len(), BABE_M_CC);
}

#[test]
fn protocol_finalized_instances_contribute_one_base_wire_slot() {
    let finalized = (0..BABE_M_CC).map(FinalizedInstanceData::sample).collect::<Vec<_>>();
    let soldering = SolderingData::sample((0..BABE_M_CC).collect());

    let gc_data = extract_gc_circuit_data(&finalized, &soldering, verifier_pubkey())
        .expect("one verifier graph slot");

    assert_eq!(BABE_M_CC, 4);
    assert_eq!(
        gc_data.final_msg_hashlocks,
        finalized.iter().map(|data| data.final_msg_hash).collect::<Vec<_>>()
    );
    assert!(gc_data.wire_hashes.as_slice() == finalized[0].wire_hashes.as_slice());
}

#[test]
fn gc_slot_rejects_invalid_finalized_counts_and_soldering_order() {
    for count in [1, 3, 5, 8] {
        let finalized = (0..count).map(FinalizedInstanceData::sample).collect::<Vec<_>>();
        let soldering = SolderingData::sample((0..count).collect());
        let error = match extract_gc_circuit_data(&finalized, &soldering, verifier_pubkey()) {
            Ok(_) => panic!("invalid finalized count"),
            Err(error) => error,
        };
        assert!(error.to_string().contains(&format!("exactly {BABE_M_CC} finalized")));
    }

    let finalized = (0..BABE_M_CC).map(FinalizedInstanceData::sample).collect::<Vec<_>>();
    let mut indices = (0..BABE_M_CC).collect::<Vec<_>>();
    indices.swap(0, 1);
    let error = match extract_gc_circuit_data(
        &finalized,
        &SolderingData::sample(indices),
        verifier_pubkey(),
    ) {
        Ok(_) => panic!("mismatched soldering order"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("soldering finalized indices mismatch"));
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
    let (assert_secret_key, _) = generate_wots_key("graph-scoped-key");
    let proof = ark_groth16::Proof::<ark_bn254::Bn254>::default();
    let assert_witness = build_assert_witness(&proof, &assert_secret_key).expect("assert witness");
    assert_eq!(assert_witness.wots_sig.len(), WOTS_SIG_COUNT);
    assert!(!assert_witness.pi1.is_empty());
    assert!(build_assert_witness(&proof, &Vec::new()).is_err());

    let verifier_state = BabeVerifierState {
        package: build_setup_package(BABE_M_CC).expect("setup package"),
        finalized_indices: (0..BABE_M_CC).collect(),
        verifier_pubkey: verifier_pubkey(),
    };
    let challenge_witness = build_challenge_assert_witness(&verifier_state, &assert_witness, 12)
        .expect("challenge witness");
    assert_eq!(challenge_witness.verifier_index, 12);
    assert_eq!(challenge_witness.input_labels.len(), INPUT_WIRE_NUM);

    let final_msgs = (0..BABE_M_CC)
        .map(|index| format!("finalized-preimage-{index}").into_bytes())
        .collect::<Vec<_>>();
    let h_msgs = final_msgs.iter().map(label_hash).collect::<Vec<_>>();
    let prover_state = BabeProverState {
        package: build_setup_package(BABE_M_CC).expect("setup package"),
        finalized: (0..BABE_M_CC).map(FinalizedInstanceData::sample).collect(),
        soldering: SolderingData::sample((0..BABE_M_CC).collect()),
        h_msgs,
    };
    let wrongly_challenged =
        build_wrongly_challenged_witness(&prover_state, &challenge_witness, final_msgs.clone())
            .expect("wrongly challenged witness");
    assert_eq!(wrongly_challenged.verifier_index, 12);
    assert_eq!(wrongly_challenged.final_msgs, final_msgs);
    assert!(
        build_wrongly_challenged_witness(
            &prover_state,
            &challenge_witness,
            vec![b"missing-preimage".to_vec(); BABE_M_CC],
        )
        .is_err()
    );
}

#[test]
fn wrongly_challenged_witness_requires_all_finalized_preimages() {
    let final_msgs = (0..BABE_M_CC)
        .map(|index| format!("finalized-preimage-{index}").into_bytes())
        .collect::<Vec<_>>();
    let h_msgs = final_msgs.iter().map(label_hash).collect::<Vec<_>>();
    let challenge_witness =
        BabeChallengeAssertWitness { verifier_index: 0, input_labels: vec![], wots_sig: vec![] };

    let from_preimages = build_wrongly_challenged_witness_from_preimages(
        &h_msgs,
        &challenge_witness,
        final_msgs.clone(),
    )
    .expect("wrongly challenged witness");
    assert_eq!(from_preimages.verifier_index, 0);
    assert_eq!(from_preimages.final_msgs, final_msgs);

    let prover_state = BabeProverState {
        package: build_setup_package(BABE_M_CC).expect("setup package"),
        finalized: (0..BABE_M_CC).map(FinalizedInstanceData::sample).collect(),
        soldering: SolderingData::sample((0..BABE_M_CC).collect()),
        h_msgs,
    };
    let delegated = build_wrongly_challenged_witness(
        &prover_state,
        &challenge_witness,
        from_preimages.final_msgs.clone(),
    )
    .expect("delegated wrongly challenged witness");
    assert_eq!(delegated, from_preimages);

    assert!(
        build_wrongly_challenged_witness_from_preimages(
            &prover_state.h_msgs,
            &challenge_witness,
            vec![from_preimages.final_msgs[0].clone(); BABE_M_CC],
        )
        .is_err()
    );
}
