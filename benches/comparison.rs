/// Full comparison benchmark across hash-based and MatPRG-based constructions.
///
/// Usage (orchestrator mode — runs all combinations):
///   cargo bench --features "register_MatPRG,register_MiMC_CTR,register_Poseidon_CTR,parallel" \
///               --bench comparison
///
/// Each (circuit, DATA_LOG) is run in a fresh child process with a 10-minute timeout.
/// Rows where the preset is missing or the run exceeds the timeout are printed as SKIPPED.
///
/// Output format: CSV  circuit,data_log,constraints,setup_ms,prove_ms_mean,verify_us_mean  (prove/verify: N_ITER=10)
use std::io::{BufReader, Read};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use ark_bn254::{Bn254, Fr};
use ark_std::rand::{RngCore, SeedableRng, rngs::StdRng};
use ark_std::test_rng;

use zkMarket::gadget::hashes::mimc7;

type C = ark_ed_on_bn254::EdwardsProjective;
type GG = ark_ed_on_bn254::constraints::EdwardsVar;

const CIRCUITS: &[&str] = &[
    "register_MatPRG",
    "register_MiMC_CTR",
    "register_Poseidon_CTR",
];
const DATA_LOGS: &[usize] = &[6, 7, 8, 9, 10, 11, 12];
const TIMEOUT_SECS: u64 = 600; // 10 minutes per (circuit, DATA_LOG)
const N_ITER: usize = 10;

fn constraints_only_mode() -> bool {
    std::env::var("BENCH_CONSTRAINTS_ONLY").ok().as_deref() == Some("1")
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

// ── per-circuit inner benchmarks ────────────────────────────────────────────

macro_rules! bench_circuit {
    ($fn_name:ident, $module:ident, $circuit:ident, $label:literal) => {
        fn $fn_name(log: usize) {
            use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
            use zkMarket::cp_snark::cp_groth16::{CPGroth16, prepare_verifying_key};
            use zkMarket::$module::{MockingCircuit, circuit::$circuit};
            let rc = mimc_params();
            let mut rng = fresh_rng();
            let c0 =
                <$circuit<C, GG> as MockingCircuit<C, GG>>::generate_circuit(rc.clone(), &mut rng)
                    .unwrap();
            let n = count_constraints(c0);
            eprintln!("  constraints = {n}");
            if constraints_only_mode() {
                println!("{},{log},{n},0.0,0.0,0", $label);
                return;
            }
            let c1 =
                <$circuit<C, GG> as MockingCircuit<C, GG>>::generate_circuit(rc.clone(), &mut rng)
                    .unwrap();
            let t = Instant::now();
            let (pk, vk) = CPGroth16::<Bn254>::setup(c1, &mut rng).unwrap();
            let setup_ms = t.elapsed().as_secs_f64() * 1000.0;
            let pvk = prepare_verifying_key::<Bn254>(&vk);
            eprintln!("  setup = {setup_ms:.1} ms");
            let c2 =
                <$circuit<C, GG> as MockingCircuit<C, GG>>::generate_circuit(rc.clone(), &mut rng)
                    .unwrap();
            let image = vec![c2.H_k.unwrap()];
            let proof = CPGroth16::<Bn254>::prove(&pk, c2, &mut rng).unwrap();
            let prove_ms = (0..N_ITER)
                .map(|_| {
                    let c = <$circuit<C, GG> as MockingCircuit<C, GG>>::generate_circuit(
                        rc.clone(),
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
                "{},{log},{n},{setup_ms:.1},{prove_ms:.1},{verify_us:.0}",
                $label
            );
        }
    };
}

bench_circuit!(
    bench_register_MatPRG,
    register_MatPRG,
    RegisterMatPRGCircuit,
    "register_MatPRG"
);
bench_circuit!(
    bench_register_MiMC_CTR,
    register_MiMC_CTR,
    EncDataMiMCCTRCircuit,
    "register_MiMC_CTR"
);

fn bench_register_Poseidon_CTR(log: usize) {
    use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
    use zkMarket::cp_snark::cp_groth16::{CPGroth16, prepare_verifying_key};
    use zkMarket::gadget::hashes::poseidon::parameters::get_bn254_poseidon_config;
    use zkMarket::register_Poseidon_CTR::{MockingCircuit, circuit::EncDataPoseidonCTRCircuit};

    let pc = get_bn254_poseidon_config();
    let mut rng = fresh_rng();
    let c0 = <EncDataPoseidonCTRCircuit<C, GG> as MockingCircuit<C, GG>>::generate_circuit(
        pc.clone(),
        &mut rng,
    )
    .unwrap();
    let n = count_constraints(c0);
    eprintln!("  constraints = {n}");
    if constraints_only_mode() {
        println!("register_Poseidon_CTR,{log},{n},0.0,0.0,0");
        return;
    }
    let c1 = <EncDataPoseidonCTRCircuit<C, GG> as MockingCircuit<C, GG>>::generate_circuit(
        pc.clone(),
        &mut rng,
    )
    .unwrap();
    let t = Instant::now();
    let (pk, vk) = CPGroth16::<Bn254>::setup(c1, &mut rng).unwrap();
    let setup_ms = t.elapsed().as_secs_f64() * 1000.0;
    let pvk = prepare_verifying_key::<Bn254>(&vk);
    eprintln!("  setup = {setup_ms:.1} ms");
    let c2 = <EncDataPoseidonCTRCircuit<C, GG> as MockingCircuit<C, GG>>::generate_circuit(
        pc.clone(),
        &mut rng,
    )
    .unwrap();
    let image = vec![c2.H_k.unwrap()];
    let proof = CPGroth16::<Bn254>::prove(&pk, c2, &mut rng).unwrap();
    let prove_ms = (0..N_ITER)
        .map(|_| {
            let c = <EncDataPoseidonCTRCircuit<C, GG> as MockingCircuit<C, GG>>::generate_circuit(
                pc.clone(),
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
    println!("register_Poseidon_CTR,{log},{n},{setup_ms:.1},{prove_ms:.1},{verify_us:.0}");
}

// ── inner worker ────────────────────────────────────────────────────────────

fn run_inner() {
    let circuit = std::env::var("BENCH_CIRCUIT").expect("BENCH_CIRCUIT not set");
    let log: usize = std::env::var("DATA_LOG")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(6);
    match circuit.as_str() {
        "register_MatPRG" => bench_register_MatPRG(log),
        "register_MiMC_CTR" => bench_register_MiMC_CTR(log),
        "register_Poseidon_CTR" => bench_register_Poseidon_CTR(log),
        other => panic!("unknown circuit: {other}"),
    }
}

// ── orchestrator ────────────────────────────────────────────────────────────

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

    println!("circuit,data_log,constraints,setup_ms,prove_ms,verify_us");
    for &circuit in CIRCUITS {
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
                    println!("{circuit},{log},SKIPPED,,,");
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
