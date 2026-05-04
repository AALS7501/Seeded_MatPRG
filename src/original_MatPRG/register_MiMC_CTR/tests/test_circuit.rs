use crate::cp_snark::cp_groth16::{prepare_verifying_key, CPGroth16};
use crate::register_MiMC_CTR::{circuit::EncDataMiMCCTRCircuit, MockingCircuit, DATA_SET};
use crate::gadget::hashes::mimc7;
use ark_bn254::{Bn254, Fr};
use ark_std::{
    rand::{rngs::StdRng, RngCore, SeedableRng},
    test_rng,
    time::Instant,
};

type C = ark_ed_on_bn254::EdwardsProjective;
type GG = ark_ed_on_bn254::constraints::EdwardsVar;

#[test]
fn test_register_MiMC_CTR_circuit() {
    let mut rng = StdRng::seed_from_u64(test_rng().next_u64());
    let rc = mimc7::Parameters {
        round_constants: mimc7::parameters::get_bn256_round_constants(),
    };

    println!(
        "--- Starting CP-SNARK test for register_MiMC_CTR (DATA_LOG=6, Data_size={}) ---",
        DATA_SET.Data_size
    );

    // --- Setup ---
    let setup_start = Instant::now();
    let circuit_for_setup =
        <EncDataMiMCCTRCircuit<C, GG> as MockingCircuit<C, GG>>::generate_circuit(
            rc.clone(),
            &mut rng,
        )
        .unwrap();
    let pk = CPGroth16::<Bn254>::generate_random_parameters_with_committed(
        circuit_for_setup,
        DATA_SET.Data_size,
        &mut rng,
    )
    .unwrap();
    let pvk = prepare_verifying_key::<Bn254>(&pk.vk);
    println!("Setup time: {:?}", setup_start.elapsed());

    // --- Prove ---
    let circuit_for_prove =
        <EncDataMiMCCTRCircuit<C, GG> as MockingCircuit<C, GG>>::generate_circuit(rc, &mut rng)
            .unwrap();
    let image: Vec<Fr> = vec![circuit_for_prove.H_k.unwrap()]; // CT committed via proof.cm; H_k is the only public input

    let prove_start = Instant::now();
    let proof = CPGroth16::<Bn254>::create_random_proof_with_reduction(
        circuit_for_prove,
        &pk,
        &mut rng,
    )
    .unwrap();
    println!("Prove time: {:?}", prove_start.elapsed());

    // --- Verify ---
    let verify_start = Instant::now();
    assert!(CPGroth16::<Bn254>::verify_proof(&pvk, &proof, &image).unwrap());
    println!("Verify time: {:?}", verify_start.elapsed());

    println!("--- Test for register_MiMC_CTR finished successfully ---");
}
