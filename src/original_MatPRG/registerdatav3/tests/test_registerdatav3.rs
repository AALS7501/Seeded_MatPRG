mod test {
    use crate::cp_snark::cp_groth16::ProvingKey;
    use crate::cp_snark::cp_groth16::VerifyingKey;
    use crate::gadget::hashes::mimc7;
    use crate::registerdatav3;
    use crate::registerdatav3::circuit::Registerdatav3Circuit;
    use ark_bn254::Bn254;
    use ark_crypto_primitives::snark::CircuitSpecificSetupSNARK;
    use ark_crypto_primitives::snark::SNARK;


    use ark_ff::PrimeField;
    use ark_serialize::{CanonicalSerialize, Write};
    use ark_std::io::Cursor;
    use ark_std::rand::RngCore;
    use ark_std::rand::SeedableRng;
    use ark_std::test_rng;
    use std::fs::File;
    use std::mem;
    use std::time::Instant;
    type C = ark_ed_on_bn254::EdwardsProjective;
    type GG = ark_ed_on_bn254::constraints::EdwardsVar;
    use crate::registerdatav3::DATA_SET;
    type F = ark_bn254::Fr;
    use crate::cp_snark::cp_groth16::{prepare_verifying_key, CPGroth16};
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
    fn test_registerdatav3() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let rc: mimc7::Parameters<F> = mimc7::Parameters {
            round_constants: mimc7::parameters::get_bn256_round_constants(),
        };

        let setup_time = Instant::now();

        let test_input =
            <Registerdatav3Circuit<C, GG> as registerdatav3::MockingCircuit<C, GG>>::generate_circuit(
                rc, &mut rng,
            )
            .unwrap();

        println!("Generate CRS!");

        let (pk, vk) = {
            let c = test_input.clone();
            CPGroth16::<Bn254>::setup(c, &mut rng).unwrap()
        };

        to_file::<ProvingKey<Bn254>>(&pk, &format!("./crs_1MB_pk")).unwrap();
        to_file::<VerifyingKey<Bn254>>(&vk, &format!("./crs_1MB_vk")).unwrap();

        println!("setup time? = {:?}", setup_time.elapsed());
        let CRS_size = mem::size_of_val(&pk) + mem::size_of_val(&vk);
        println!("CRS size = {:?}", CRS_size);

        println!("Prepared verifying key!");
        let pvk = prepare_verifying_key::<Bn254>(&vk);

        let mut image = vec![test_input.H_k.clone().unwrap()];

        print_hex(test_input.H_k.clone().unwrap());
        let c = test_input.clone();

        let start = Instant::now();
        println!("Generate proof!\n\n\n\n");

        let proof = CPGroth16::<Bn254>::prove(&pk, c.clone(), &mut rng).unwrap();
        println!("proof time? = {:?}", start.elapsed());
        // let cmct = CPGroth16::<Bn254>::commit(&pvk, o, &test_input.CT)

        let end = Instant::now();
        let res = CPGroth16::<Bn254>::verify_with_processed_vk(&pvk, &image, &proof).unwrap();
        // assert!(CPGroth16::<Bn254>::verify_with_processed_vk(&pvk, &image, &proof).unwrap());
        println!("verify time? = {:?}", end.elapsed());
    }

    fn to_file<T>(value: &T, file_path: &str) -> Result<(), String>
    where
        T: CanonicalSerialize,
    {
        let mut cursor = Cursor::new(Vec::new());

        let dir_path = std::path::Path::new(file_path).parent().unwrap(); // Get the parent directory path
        if !dir_path.exists() {
            let _ = std::fs::create_dir_all(dir_path);
        }

        let _ = value.serialize_uncompressed(&mut cursor);

        let mut file = match File::create(file_path) {
            Ok(f) => f,
            Err(e) => return Err(e.to_string()),
        };

        let _ = file.write_all(cursor.get_ref());

        Ok(())
    }
}
