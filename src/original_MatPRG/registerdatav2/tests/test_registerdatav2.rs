mod test {
    use ark_bn254::Bn254;
    use ark_crypto_primitives::snark::CircuitSpecificSetupSNARK;
    use ark_crypto_primitives::snark::SNARK;
    use ark_ff::PrimeField;
    use std::mem;
    use std::time::Instant;

    use ark_groth16::Groth16;

    use crate::cp_snark::cp_groth16::ProvingKey;
    use crate::cp_snark::cp_groth16::VerifyingKey;
    use crate::cp_snark::cp_groth16::{prepare_verifying_key, CPGroth16};

    use ark_std::rand::RngCore;
    use ark_std::rand::SeedableRng;
    use ark_std::test_rng;

    use crate::registerdatav2;
    use crate::registerdatav2::circuit::Registerdatav2Circuit;

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
    fn test_registerdatav2() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let rc: mimc7::Parameters<F> = mimc7::Parameters {
            round_constants: mimc7::parameters::get_bn256_round_constants(),
        };

        let setup_time = Instant::now();

        let test_input =
            <Registerdatav2Circuit<C, GG> as registerdatav2::MockingCircuit<C, GG>>::generate_circuit(
                rc, &mut rng,
            )
                .unwrap();

        println!("Generate CRS!");

        let (pk, vk) = {
            let c = test_input.clone();
            CPGroth16::<Bn254>::setup(c, &mut rng).unwrap()
        };
        println!("setup time? = {:?}", setup_time.elapsed());

        let CRS_size = mem::size_of_val(&pk) + mem::size_of_val(&vk);
        println!("CRS size = {:?}", CRS_size);

        println!("Prepared verifying key!");
        // let pvk = Groth16::<Bn254>::process_vk(&vk).unwrap();
        let pvk = prepare_verifying_key::<Bn254>(&vk);

        let mut image: Vec<_> = vec![
            // test_input.h_ct.clone().unwrap(),
            test_input.h_k.clone().unwrap(),
            test_input.ENA_writer.clone().unwrap(),
        ];

        let c = test_input.clone();

        let start = Instant::now();
        println!("Generate proof!");
        let proof = CPGroth16::<Bn254>::prove(&pk, c.clone(), &mut rng).unwrap();
        println!("proof time? = {:?}", start.elapsed());
        // let o = rand
        // let cmct = CPGroth16::<Bn254>::commit(&pvk, o, &test_input.CT).unwrap();
        let end = Instant::now();
        let res = CPGroth16::<Bn254>::verify_with_processed_vk(&pvk, &image, &proof).unwrap();
        // assert!(Groth16::<Bn254>::verify_with_processed_vk(&pvk, &image, &proof).unwrap());
        println!("verify time? = {:?}", end.elapsed());
    }
}
