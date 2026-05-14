/// MatPRG-only comparison benchmark.
/// Temporary focus: original MatPRG and seeded one-shot MatPRG, including
/// the hidden key representation size used by each circuit.
///
/// Usage:
///   DATA_LOG=6 cargo bench --features "register_MatPRG,register_seeded_matprg,parallel" --bench comparison_matprg
///   cargo bench --features "register_MatPRG,register_seeded_matprg,parallel" --bench comparison_matprg
use std::io::{BufReader, Read};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use ark_bn254::{Bn254, Fr};
use ark_std::rand::{rngs::StdRng, RngCore, SeedableRng};
use ark_std::test_rng;

use zkMarket::gadget::hashes::mimc7;
use zkMarket::original_MatPRG::register_MatPRG::circuit::RegisterMatPRGCircuit;
use zkMarket::seeded_MatPRG::register_seeded_matprg::circuit::RegisterSeededMatPRGCircuit;

type C = ark_ed_on_bn254::EdwardsProjective;
type GG = ark_ed_on_bn254::constraints::EdwardsVar;

const CIRCUITS: &[&str] = &[
    "register_MatPRG",
    "register_seeded_matprg",
];
const DATA_LOGS: &[usize] = &[6, 7, 8, 9, 10, 11, 12];
const TIMEOUT_SECS: u64 = 600;
const N_ITER: usize = 10;

fn selected_circuits() -> Vec<&'static str> {
    match std::env::var("ONLY_CIRCUIT") {
        Ok(name) => CIRCUITS
            .iter()
            .copied()
            .filter(|c| *c == name)
            .collect(),
        Err(_) => CIRCUITS.to_vec(),
    }
}

fn mimc_params() -> mimc7::Parameters<Fr> {
    mimc7::Parameters {
        round_constants: mimc7::parameters::get_bn256_round_constants(),
    }
}

fn fresh_rng() -> StdRng {
    StdRng::seed_from_u64(test_rng().next_u64())
}

fn count_constraints<Circ: ark_relations::r1cs::ConstraintSynthesizer<Fr>>(c: Circ) -> usize {
    let cs = ark_relations::r1cs::ConstraintSystem::<Fr>::new_ref();
    c.generate_constraints(cs.clone()).unwrap();
    cs.num_constraints()
}

fn original_image(circuit: &RegisterMatPRGCircuit<C, GG>) -> Vec<Fr> {
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

fn seeded_image(circuit: &RegisterSeededMatPRGCircuit<C, GG>) -> Vec<Fr> {
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

fn bench_register_MatPRG(log: usize) {
    use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
    use zkMarket::cp_snark::cp_groth16::{prepare_verifying_key, CPGroth16};

    let rc = mimc_params();
    let mut rng = fresh_rng();
    let matrix_a = RegisterMatPRGCircuit::<C, GG>::sample_public_matrix(&mut rng);

    let n = count_constraints(
        RegisterMatPRGCircuit::<C, GG>::generate_circuit_with_matrix(
            rc.clone(),
            matrix_a.clone(),
            &mut rng,
        )
        .unwrap(),
    );
    eprintln!("  constraints = {n}");

    let key_bits = zkMarket::register_MatPRG::current_key_bits();
    eprintln!("  key bits = {key_bits}");

    if std::env::var("COUNT_ONLY").is_ok() {
        println!("register_MatPRG,{log},{key_bits},{n},,,");
        return;
    }

    let c1 = RegisterMatPRGCircuit::<C, GG>::generate_circuit_with_matrix(
        rc.clone(),
        matrix_a.clone(),
        &mut rng,
    )
    .unwrap();
    let t = Instant::now();
    let (pk, vk) = CPGroth16::<Bn254>::setup(c1, &mut rng).unwrap();
    let setup_ms = t.elapsed().as_secs_f64() * 1000.0;
    let pvk = prepare_verifying_key::<Bn254>(&vk);
    eprintln!("  setup = {setup_ms:.1} ms");

    let c2 = RegisterMatPRGCircuit::<C, GG>::generate_circuit_with_matrix(
        rc.clone(),
        matrix_a.clone(),
        &mut rng,
    )
    .unwrap();
    let image = original_image(&c2);
    let proof = CPGroth16::<Bn254>::prove(&pk, c2, &mut rng).unwrap();

    let prove_ms = (0..N_ITER)
        .map(|_| {
            let c = RegisterMatPRGCircuit::<C, GG>::generate_circuit_with_matrix(
                rc.clone(),
                matrix_a.clone(),
                &mut rng,
            )
            .unwrap();
            let t = Instant::now();
            CPGroth16::<Bn254>::prove(&pk, c, &mut rng).unwrap();
            t.elapsed().as_secs_f64() * 1000.0
        })
        .sum::<f64>()
        / N_ITER as f64;
    eprintln!("  prove = {prove_ms:.1} ms (mean)");

    let verify_us = (0..N_ITER)
        .map(|_| {
            let t = Instant::now();
            CPGroth16::<Bn254>::verify_with_processed_vk(&pvk, &image, &proof).unwrap();
            t.elapsed().as_micros() as f64
        })
        .sum::<f64>()
        / N_ITER as f64;
    eprintln!("  verify = {verify_us:.0} µs (mean)");

    println!(
        "register_MatPRG,{log},{key_bits},{n},{setup_ms:.1},{prove_ms:.1},{verify_us:.0}"
    );
}

fn bench_register_seeded_matprg(log: usize) {
    use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
    use zkMarket::cp_snark::cp_groth16::{prepare_verifying_key, CPGroth16};

    let rc = mimc_params();
    let mut rng = fresh_rng();
    let (matrix_a1, matrix_a2) =
        RegisterSeededMatPRGCircuit::<C, GG>::sample_public_matrices(&mut rng);

    let n = count_constraints(
        RegisterSeededMatPRGCircuit::<C, GG>::generate_circuit_with_matrices(
            rc.clone(),
            matrix_a1.clone(),
            matrix_a2.clone(),
            &mut rng,
        )
        .unwrap(),
    );
    eprintln!("  constraints = {n}");

    let key_bits = zkMarket::register_seeded_matprg::current_key_bits();
    eprintln!("  key bits = {key_bits}");

    if std::env::var("COUNT_ONLY").is_ok() {
        println!("register_seeded_matprg,{log},{key_bits},{n},,,");
        return;
    }

    let c1 = RegisterSeededMatPRGCircuit::<C, GG>::generate_circuit_with_matrices(
        rc.clone(),
        matrix_a1.clone(),
        matrix_a2.clone(),
        &mut rng,
    )
    .unwrap();
    let t = Instant::now();
    let (pk, vk) = CPGroth16::<Bn254>::setup(c1, &mut rng).unwrap();
    let setup_ms = t.elapsed().as_secs_f64() * 1000.0;
    let pvk = prepare_verifying_key::<Bn254>(&vk);
    eprintln!("  setup = {setup_ms:.1} ms");

    let c2 = RegisterSeededMatPRGCircuit::<C, GG>::generate_circuit_with_matrices(
        rc.clone(),
        matrix_a1.clone(),
        matrix_a2.clone(),
        &mut rng,
    )
    .unwrap();
    let image = seeded_image(&c2);
    let proof = CPGroth16::<Bn254>::prove(&pk, c2, &mut rng).unwrap();

    let prove_ms = (0..N_ITER)
        .map(|_| {
            let c = RegisterSeededMatPRGCircuit::<C, GG>::generate_circuit_with_matrices(
                rc.clone(),
                matrix_a1.clone(),
                matrix_a2.clone(),
                &mut rng,
            )
            .unwrap();
            let t = Instant::now();
            CPGroth16::<Bn254>::prove(&pk, c, &mut rng).unwrap();
            t.elapsed().as_secs_f64() * 1000.0
        })
        .sum::<f64>()
        / N_ITER as f64;
    eprintln!("  prove = {prove_ms:.1} ms (mean)");

    let verify_us = (0..N_ITER)
        .map(|_| {
            let t = Instant::now();
            CPGroth16::<Bn254>::verify_with_processed_vk(&pvk, &image, &proof).unwrap();
            t.elapsed().as_micros() as f64
        })
        .sum::<f64>()
        / N_ITER as f64;
    eprintln!("  verify = {verify_us:.0} µs (mean)");

    println!(
        "register_seeded_matprg,{log},{key_bits},{n},{setup_ms:.1},{prove_ms:.1},{verify_us:.0}"
    );
}

fn run_inner() {
    let circuit = std::env::var("BENCH_CIRCUIT").expect("BENCH_CIRCUIT not set");
    let log: usize = std::env::var("DATA_LOG")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(6);

    match circuit.as_str() {
        "register_MatPRG" => bench_register_MatPRG(log),
        "register_seeded_matprg" => bench_register_seeded_matprg(log),
        other => panic!("unknown circuit: {other}"),
    }
}

fn run_child(exe: &std::path::Path, circuit: &str, log: usize) -> Option<String> {
    let mut child = Command::new(exe)
        .env("BENCH_INNER", "1")
        .env("BENCH_CIRCUIT", circuit)
        .env("DATA_LOG", log.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .ok()?;

    let stdout = child.stdout.take().unwrap();
    let reader_thread = std::thread::spawn(move || {
        let mut buf = String::new();
        BufReader::new(stdout).read_to_string(&mut buf).ok();
        buf
    });

    let start = Instant::now();
    let timeout = Duration::from_secs(TIMEOUT_SECS);

    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = reader_thread.join();
                    eprintln!("[timeout] {circuit} DATA_LOG={log}");
                    return None;
                }
                std::thread::sleep(Duration::from_millis(500));
            }
            Err(e) => {
                eprintln!("[error] {e}");
                return None;
            }
        }
    };

    let output = reader_thread.join().unwrap_or_default();
    if !status.success() {
        eprintln!("[failed] {circuit} DATA_LOG={log} exit={}", status);
        return None;
    }
    output
        .lines()
        .find(|l| l.starts_with(circuit) && l.contains(','))
        .map(|l| l.to_string())
}

fn run_orchestrator() {
    let exe = std::env::current_exe().expect("cannot get current exe path");
    let filter_log: Option<usize> = std::env::var("DATA_LOG").ok().and_then(|s| s.parse().ok());
    let logs: Vec<usize> = filter_log
        .map(|l| vec![l])
        .unwrap_or_else(|| DATA_LOGS.to_vec());
    let circuits = selected_circuits();

    println!("circuit,data_log,key_bits,constraints,setup_ms,prove_ms,verify_us");
    for circuit in circuits {
        for &log in &logs {
            eprintln!("[start ] {circuit}  DATA_LOG={log}");
            let t = Instant::now();
            match run_child(&exe, circuit, log) {
                Some(line) => {
                    eprintln!(
                        "[done  ] {circuit}  DATA_LOG={log}  ({:.1}s)",
                        t.elapsed().as_secs_f64()
                    );
                    println!("{line}");
                }
                None => {
                    eprintln!(
                        "[skip  ] {circuit}  DATA_LOG={log}  ({:.1}s)",
                        t.elapsed().as_secs_f64()
                    );
                    println!("{circuit},{log},,SKIPPED,,,");
                }
            }
        }
    }
}

fn main() {
    if std::env::var("BENCH_INNER").is_ok() {
        run_inner();
    } else {
        run_orchestrator();
    }
}
