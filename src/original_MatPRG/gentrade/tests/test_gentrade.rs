use ark_serialize::CanonicalSerialize;
use ark_serialize::Write;
use ark_std::io::Cursor;
use std::fs::File;
// use core::error::Error;
// use ark_std::error::Error;

mod test {
    use crate::gentrade::tests::test_gentrade::to_file;
    use ark_bn254::Bn254;
    use ark_crypto_primitives::snark::CircuitSpecificSetupSNARK;
    use ark_crypto_primitives::snark::SNARK;
    use ark_ec::AffineRepr;
    use ark_ff::PrimeField;
    use ark_groth16::ProvingKey;
    use ark_serialize::CanonicalSerialize;
    use ark_std::end_timer;
    use ark_std::start_timer;
    use std::time::Duration;
    use std::time::Instant;

    use ark_groth16::Groth16;
    use ark_std::rand::RngCore;
    use ark_std::rand::SeedableRng;
    use ark_std::test_rng;
    use std::mem;

    use crate::gentrade;
    use crate::gentrade::circuit::GenTradeCircuit;

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
    fn test_gentrade() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let rc: mimc7::Parameters<F> = mimc7::Parameters {
            round_constants: mimc7::parameters::get_bn256_round_constants(),
        };

        let test_input =
            <GenTradeCircuit<C, GG> as gentrade::MockingCircuit<C, GG>>::generate_circuit(
                rc, &mut rng,
            )
            .unwrap();

        println!("Generate CRS!");

        let setup_time = Instant::now();

        let (pk, vk) = {
            let c = test_input.clone();
            Groth16::<Bn254>::setup(c, &mut rng).unwrap()
        };

        to_file::<ProvingKey<Bn254>>(&pk, &format!("./crs.pk")).unwrap();

        // let pk_buffer = pk.serialize_compressed(writer)

        let CRS_size = mem::size_of_val(&pk) + mem::size_of_val(&vk);
        println!("CRS size = {:?}", CRS_size);

        println!("Prepared verifying key!");
        let pvk = Groth16::<Bn254>::process_vk(&vk).unwrap();

        println!("setup tim = {:?}", setup_time.elapsed());
        const SAMPLES: u32 = 1;
        let mut total_proving = Duration::new(0, 0);
        let mut total_verifying = Duration::new(0, 0);

        for _ in 0..SAMPLES {
            let mut image: Vec<_> = vec![test_input.cm.clone().unwrap()];
            image.append(&mut vec![
                *test_input.pk_buyer.clone().unwrap().x().unwrap(),
                *test_input.pk_buyer.clone().unwrap().y().unwrap(),
            ]);
            image.append(&mut vec![
                *test_input.G_r.clone().unwrap().x().unwrap(),
                *test_input.G_r.clone().unwrap().y().unwrap(),
            ]);
            image.append(&mut vec![
                *test_input.c1.clone().unwrap().x().unwrap(),
                *test_input.c1.clone().unwrap().y().unwrap(),
            ]);
            image.append(&mut test_input.CT_ord.clone().unwrap());

            let start = Instant::now();
            {
                let c = test_input.clone();

                println!("Generate proof!");
                let prover_time = start_timer!(|| "Prover time");
                let proof = Groth16::<Bn254>::prove(&pk, c.clone(), &mut rng).unwrap();
                end_timer!(prover_time);
                assert!(Groth16::<Bn254>::verify_with_processed_vk(&pvk, &image, &proof).unwrap());
            }
            total_proving += start.elapsed();
            let start = Instant::now();
            total_verifying += start.elapsed();
        }

        let proving_avg = total_proving / SAMPLES;
        let proving_avg =
            proving_avg.subsec_nanos() as f64 / 1_000_000_000f64 + (proving_avg.as_secs() as f64);

        let verifying_avg = total_verifying / SAMPLES;
        let verifying_avg = verifying_avg.subsec_nanos() as f64 / 1_000_000_000f64
            + (verifying_avg.as_secs() as f64);

        println!("Average proving time: {:?} seconds", proving_avg);
        println!("Average verifying time: {:?} seconds", verifying_avg);
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
