/// Benchmark for registerdata v1~v5 proof generation.
///
/// Usage:
///   DATA_LOG=5  cargo bench --features registerdata,parallel --bench registerdata
///   DATA_LOG=7  cargo bench --features registerdata,parallel --bench registerdata
///
/// DATA_LOG controls data size (≈ 2^n KB, default n=5 = 32KB).
/// Each version is benchmarked: setup (CRS keygen) once, then prove N_ITER times.
use std::time::Instant;

use ark_bn254::Bn254;
use ark_crypto_primitives::snark::CircuitSpecificSetupSNARK;
use ark_crypto_primitives::snark::SNARK;
use ark_std::rand::RngCore;
use ark_std::rand::SeedableRng;
use ark_std::test_rng;

use zkMarket::gadget::hashes::mimc7;

type C = ark_ed_on_bn254::EdwardsProjective;
type GG = ark_ed_on_bn254::constraints::EdwardsVar;
type F = ark_bn254::Fr;

const N_ITER: usize = 10;

fn data_log() -> usize {
    std::env::var("DATA_LOG")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5)
}

fn version() -> Option<usize> {
    std::env::var("VERSION").ok().and_then(|s| s.parse().ok())
}

fn mimc_params() -> mimc7::Parameters<F> {
    mimc7::Parameters {
        round_constants: mimc7::parameters::get_bn256_round_constants(),
    }
}

fn bench_ms(durations: &[std::time::Duration]) -> (f64, f64, f64) {
    let ms: Vec<f64> = durations.iter().map(|d| d.as_secs_f64() * 1000.0).collect();
    let mean = ms.iter().sum::<f64>() / ms.len() as f64;
    let min = ms.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = ms.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    (mean, min, max)
}

// ── v1 ──────────────────────────────────────────────────────────────────────

fn bench_v1() {
    use ark_groth16::Groth16;
    use zkMarket::registerdatav1::{self, circuit::RegisterdataCircuit};

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    let circuit =
        <RegisterdataCircuit<C, GG> as registerdatav1::MockingCircuit<C, GG>>::generate_circuit(
            mimc_params(),
            &mut rng,
        )
        .unwrap();

    let t = Instant::now();
    let (pk, _vk) = Groth16::<Bn254>::setup(circuit.clone(), &mut rng).unwrap();
    println!("[v1] setup:  {:.1} ms", t.elapsed().as_secs_f64() * 1000.0);

    let mut durations = Vec::with_capacity(N_ITER);
    for _ in 0..N_ITER {
        let t = Instant::now();
        Groth16::<Bn254>::prove(&pk, circuit.clone(), &mut rng).unwrap();
        durations.push(t.elapsed());
    }
    let (mean, min, max) = bench_ms(&durations);
    println!(
        "[v1] prove:  mean={:.1} ms  min={:.1} ms  max={:.1} ms  (n={})",
        mean, min, max, N_ITER
    );
}

// ── v2 ──────────────────────────────────────────────────────────────────────

fn bench_v2() {
    use zkMarket::cp_snark::cp_groth16::CPGroth16;
    use zkMarket::registerdatav2::{self, circuit::Registerdatav2Circuit};

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    let circuit =
        <Registerdatav2Circuit<C, GG> as registerdatav2::MockingCircuit<C, GG>>::generate_circuit(
            mimc_params(),
            &mut rng,
        )
        .unwrap();

    let t = Instant::now();
    let (pk, _vk) = CPGroth16::<Bn254>::setup(circuit.clone(), &mut rng).unwrap();
    println!("[v2] setup:  {:.1} ms", t.elapsed().as_secs_f64() * 1000.0);

    let mut durations = Vec::with_capacity(N_ITER);
    for _ in 0..N_ITER {
        let t = Instant::now();
        CPGroth16::<Bn254>::prove(&pk, circuit.clone(), &mut rng).unwrap();
        durations.push(t.elapsed());
    }
    let (mean, min, max) = bench_ms(&durations);
    println!(
        "[v2] prove:  mean={:.1} ms  min={:.1} ms  max={:.1} ms  (n={})",
        mean, min, max, N_ITER
    );
}

// ── v3 ──────────────────────────────────────────────────────────────────────

fn bench_v3() {
    use zkMarket::cp_snark::cp_groth16::CPGroth16;
    use zkMarket::registerdatav3::{self, circuit::Registerdatav3Circuit};

    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    let circuit =
        <Registerdatav3Circuit<C, GG> as registerdatav3::MockingCircuit<C, GG>>::generate_circuit(
            mimc_params(),
            &mut rng,
        )
        .unwrap();

    let t = Instant::now();
    let (pk, _vk) = CPGroth16::<Bn254>::setup(circuit.clone(), &mut rng).unwrap();
    println!("[v3] setup:  {:.1} ms", t.elapsed().as_secs_f64() * 1000.0);

    let mut durations = Vec::with_capacity(N_ITER);
    for _ in 0..N_ITER {
        let t = Instant::now();
        CPGroth16::<Bn254>::prove(&pk, circuit.clone(), &mut rng).unwrap();
        durations.push(t.elapsed());
    }
    let (mean, min, max) = bench_ms(&durations);
    println!(
        "[v3] prove:  mean={:.1} ms  min={:.1} ms  max={:.1} ms  (n={})",
        mean, min, max, N_ITER
    );
}

// ────────────────────────────────────────────────────────────────────────────

fn main() {
    let log = data_log();
    let ver = version();

    let versions: Vec<usize> = match ver {
        Some(v) => vec![v],
        None => vec![1, 2, 3],
    };

    println!(
        "=== registerdata bench  DATA_LOG={}  ({} KB)  versions={:?}  n_iter={} ===\n",
        log,
        (1usize << log),
        versions,
        N_ITER
    );

    for v in &versions {
        match v {
            1 => bench_v1(),
            2 => bench_v2(),
            3 => bench_v3(),
            _ => eprintln!("unknown version: {}", v),
        }
        println!();
    }

    println!("done.");
}
