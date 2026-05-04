use crate::cp_snark::cp_groth16::{prepare_verifying_key, CPGroth16};
use crate::register_Poseidon_CTR::{circuit::EncDataPoseidonCTRCircuit, MockingCircuit, DATA_SET};
use crate::gadget::hashes::poseidon::parameters::get_bn254_poseidon_config;
use ark_bn254::{Bn254, Fr};
use ark_std::{
    rand::{rngs::StdRng, RngCore, SeedableRng},
    test_rng,
    time::Instant,
};

type C = ark_ed_on_bn254::EdwardsProjective;
type GG = ark_ed_on_bn254::constraints::EdwardsVar;

#[test]
fn test_register_Poseidon_CTR_circuit() {
    let mut rng = StdRng::seed_from_u64(test_rng().next_u64());
    let pc = get_bn254_poseidon_config();

    println!(
        "--- Starting CP-SNARK test for register_Poseidon_CTR (DATA_LOG=6, Data_size={}) ---",
        DATA_SET.Data_size
    );

    // --- Setup ---
    let setup_start = Instant::now();
    let circuit_for_setup =
        <EncDataPoseidonCTRCircuit<C, GG> as MockingCircuit<C, GG>>::generate_circuit(
            pc.clone(),
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
        <EncDataPoseidonCTRCircuit<C, GG> as MockingCircuit<C, GG>>::generate_circuit(pc, &mut rng)
            .unwrap();
    let image: Vec<Fr> = vec![circuit_for_prove.H_k.unwrap()];

    let prove_start = Instant::now();
    let proof = CPGroth16::<Bn254>::create_random_proof_with_reduction(circuit_for_prove, &pk, &mut rng)
        .unwrap();
    println!("Prove time: {:?}", prove_start.elapsed());

    // --- Verify ---
    let verify_start = Instant::now();
    assert!(CPGroth16::<Bn254>::verify_proof(&pvk, &proof, &image).unwrap());
    println!("Verify time: {:?}", verify_start.elapsed());

    println!("--- Test for register_Poseidon_CTR finished successfully ---");
}
