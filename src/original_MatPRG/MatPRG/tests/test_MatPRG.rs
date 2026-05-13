mod test {

    use crate::gadget::hashes::mimc7;
    use crate::MatPRG;
    use crate::MatPRG::circuit::MatPRGCircuit;
    use ark_groth16::Groth16;

    use ark_bn254::Bn254;
    use ark_crypto_primitives::snark::CircuitSpecificSetupSNARK;
    use ark_crypto_primitives::snark::SNARK;
    use ark_ff::PrimeField;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, Write};
    use ark_std::io::Cursor;
    use ark_std::rand::RngCore;
    use ark_std::rand::SeedableRng;
    use ark_std::test_rng;
    use std::fs::File;
    use std::mem;
    use std::time::Instant;
    type C = ark_ed_on_bn254::EdwardsProjective;
    type GG = ark_ed_on_bn254::constraints::EdwardsVar;
    use crate::MatPRG::DATA_SET;
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
    fn test_MatPRG() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let rc: mimc7::Parameters<F> = mimc7::Parameters {
            round_constants: mimc7::parameters::get_bn256_round_constants(),
        };

        let setup_time = Instant::now();

        let test_input =
            <MatPRGCircuit<C, GG> as MatPRG::MockingCircuit<C, GG>>::generate_circuit(rc, &mut rng)
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

        let matrix_a_size = DATA_SET.N;
        for i in 0..matrix_a_size {
            image.append(&mut test_input.matrix_A.clone().unwrap().matrix[i]);
        }
        let c = test_input.clone();

        let start = Instant::now();
        {
            println!("Generate proof!\n\n\n\n");

            let proof = Groth16::<Bn254>::prove(&pk, c.clone(), &mut rng).unwrap();
            println!("proof time? = {:?}", start.elapsed());

            assert!(Groth16::<Bn254>::verify_with_processed_vk(&pvk, &image, &proof).unwrap());
        }
    }

    fn to_file<T>(value: &T, file_path: &str) -> Result<(), String>
    where
        T: CanonicalSerialize,
    {
        let mut cursor = Cursor::new(Vec::new());

        let dir_path = std::path::Path::new(file_path).parent().unwrap(); // Get the parent directory path
        if !dir_path.exists() {
            std::fs::create_dir_all(dir_path);
        }

        value.serialize_uncompressed(&mut cursor);

        let mut file = match File::create(file_path) {
            Ok(f) => f,
            Err(e) => return Err(e.to_string()),
        };

        file.write_all(cursor.get_ref());

        Ok(())
    }
}
