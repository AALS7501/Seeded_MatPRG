mod test {
    use ark_bn254::Bn254;
    use ark_crypto_primitives::snark::CircuitSpecificSetupSNARK;
    use ark_crypto_primitives::snark::SNARK;
    use ark_ec::AffineRepr;
    use ark_ff::PrimeField;
    use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
    use std::mem;
    use std::time::Duration;
    use std::time::Instant;

    use ark_groth16::Groth16;
    use ark_std::rand::RngCore;
    use ark_std::rand::SeedableRng;
    use ark_std::test_rng;

    use crate::mimc;
    use crate::mimc::circuit::MimcCircuit;

    use crate::gadget::hashes::mimc7;

    type C = ark_ed_on_bn254::EdwardsProjective;
    type GG = ark_ed_on_bn254::constraints::EdwardsVar;

    type F = ark_bn254::Fr;

    #[allow(dead_code)]
    fn print_hex(f: F) {
        let decimal_number = f.into_bigint().to_string();

        // Parse the decimal number as a BigUint
        let big_int = num_bigint::BigUint::parse_bytes(decimal_number.as_bytes(), 10).unwrap();

        // Convert the BigUint to a hexadecimal string
        let hex_string = format!("{:x}", big_int);

        println!("0x{}", hex_string);
    }

    #[test]
    fn test_mimc() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let rc: mimc7::Parameters<F> = mimc7::Parameters {
            round_constants: mimc7::parameters::get_bn256_round_constants(),
        };

        let setup_time = Instant::now();

        let test_input =
            <MimcCircuit<C, GG> as mimc::MockingCircuit<C, GG>>::generate_circuit(rc, &mut rng)
                .unwrap();

        println!("Generate CRS!");

        let (pk, vk) = {
            let c = test_input.clone();
            Groth16::<Bn254>::setup(c, &mut rng).unwrap()
        };
        println!("setup time? = {:?}", setup_time.elapsed());

        let CRS_size = mem::size_of_val(&pk) + mem::size_of_val(&vk);
        println!("CRS size = {:?}", CRS_size);

        println!("Prepared verifying key!");
        let pvk = Groth16::<Bn254>::process_vk(&vk).unwrap();

        let mut image = vec![];
        image.append(&mut test_input.mimc_output.clone().unwrap());

        // let mut image: Vec<_> = &mut test_input.mimc_output.clone().unwrap();

        let c = test_input.clone();

        println!("Generate proof!");
        let proof = Groth16::<Bn254>::prove(&pk, c.clone(), &mut rng).unwrap();
        assert!(Groth16::<Bn254>::verify_with_processed_vk(&pvk, &image, &proof).unwrap());
    }
}
