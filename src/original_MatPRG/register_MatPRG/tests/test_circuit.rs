use crate::cp_snark::cp_groth16::{prepare_verifying_key, CPGroth16};
use crate::register_MatPRG::{
    circuit::RegisterMatPRGCircuit, MockingCircuit, DATA_SET,
};
use crate::gadget::hashes::mimc7;
use ark_bn254::{Bn254, Fr};
use ark_std::{
    rand::{rngs::StdRng, SeedableRng, RngCore},
    test_rng,
    time::Instant,
};

type C = ark_ed_on_bn254::EdwardsProjective;
type GG = ark_ed_on_bn254::constraints::EdwardsVar;

fn public_image(circuit: &RegisterMatPRGCircuit<C, GG>) -> Vec<Fr> {
    let mut image = vec![circuit.H_k.unwrap()];
    image.extend(
        circuit
            .gamma
            .as_ref()
            .unwrap()
            .matrix
            .iter()
            .flat_map(|row| row.iter().copied()),
    );
    image
}

#[test]
fn test_register_MatPRG_circuit() {
    let mut rng = StdRng::seed_from_u64(test_rng().next_u64());
    let rc_vec = mimc7::parameters::get_bn256_round_constants();
    let rc = mimc7::Parameters { round_constants: rc_vec };

    println!("--- Starting CP-SNARK test for register_MatPRG (DATA_LOG=6, Data_size={}) ---", DATA_SET.Data_size);

    // --- Setup ---
    let setup_start = Instant::now();
    let matrix_a = RegisterMatPRGCircuit::<C, GG>::sample_public_matrix(&mut rng);
    let circuit_for_setup =
        RegisterMatPRGCircuit::<C, GG>::generate_circuit_with_matrix(rc.clone(), matrix_a.clone(), &mut rng)
            .unwrap();
    let pk = CPGroth16::<Bn254>::generate_random_parameters_with_committed(
        circuit_for_setup, DATA_SET.Data_size, &mut rng,
    ).unwrap();
    let pvk = prepare_verifying_key::<Bn254>(&pk.vk);
    println!("Setup time: {:?}", setup_start.elapsed());

    // --- Prove ---
    let circuit_for_prove =
        RegisterMatPRGCircuit::<C, GG>::generate_circuit_with_matrix(rc, matrix_a, &mut rng)
            .unwrap();
    let image = public_image(&circuit_for_prove);

    let prove_start = Instant::now();
    let proof = CPGroth16::<Bn254>::create_random_proof_with_reduction(circuit_for_prove, &pk, &mut rng).unwrap();
    println!("Prove time: {:?}", prove_start.elapsed());

    // --- Verify ---
    let verify_start = Instant::now();
    assert!(CPGroth16::<Bn254>::verify_proof(&pvk, &proof, &image).unwrap());
    println!("Verify time: {:?}", verify_start.elapsed());

    println!("--- Test for register_MatPRG finished successfully ---");
}
