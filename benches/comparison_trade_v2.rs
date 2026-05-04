use std::io::{BufReader, Read};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_ec::AffineRepr;
use ark_groth16::Groth16;
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_std::rand::{rngs::StdRng, RngCore, SeedableRng};
use ark_std::test_rng;
use ark_std::UniformRand;

use zkMarket::gadget::hashes::mimc7;
use zkMarket::gadget::hybrid_key_transport::pack_bits_to_fields;

type C = ark_ed_on_bn254::EdwardsProjective;
type GG = ark_ed_on_bn254::constraints::EdwardsVar;

const CIRCUITS: &[&str] = &[
    "gentrade_v2",
    "accepttrade_v2_original",
    "accepttrade_v2_seeded",
];
const DATA_LOGS: &[usize] = &[6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19];
const TIMEOUT_SECS: u64 = 600;
const N_ITER: usize = 5;

fn mimc_params() -> mimc7::Parameters<Fr> {
    mimc7::Parameters {
        round_constants: mimc7::parameters::get_bn256_round_constants(),
    }
}

fn fresh_rng() -> StdRng {
    StdRng::seed_from_u64(test_rng().next_u64())
}

fn count_constraints<Circ: ConstraintSynthesizer<Fr>>(c: Circ) -> usize {
    let cs = ark_relations::r1cs::ConstraintSystem::<Fr>::new_ref();
    c.generate_constraints(cs.clone()).unwrap();
    cs.num_constraints()
}

fn payload_original(rng: &mut StdRng) -> Vec<Fr> {
    (0..zkMarket::register_MatPRG::current_key_payload_len())
        .map(|_| Fr::rand(rng))
        .collect()
}

fn payload_recursive(rng: &mut StdRng) -> Vec<Fr> {
    let seed_bits: Vec<bool> =
        (0..zkMarket::register_seeded_matprg::current_key_bits())
            .map(|_| (rng.next_u32() & 1) == 1)
            .collect();
    pack_bits_to_fields::<Fr>(&seed_bits, 248)
}

fn bench_gentrade_v2(log: usize) {
    use zkMarket::gentrade_v2::{circuit::GenTradeV2Circuit, MockingCircuit};

    let rc = mimc_params();
    let mut rng = fresh_rng();

    let n = count_constraints(
        <GenTradeV2Circuit<C, GG> as MockingCircuit<C, GG>>::generate_circuit(rc.clone(), &mut rng)
            .unwrap(),
    );
    let c1 =
        <GenTradeV2Circuit<C, GG> as MockingCircuit<C, GG>>::generate_circuit(rc.clone(), &mut rng)
            .unwrap();
    let t = Instant::now();
    let (pk, vk) = Groth16::<Bn254>::setup(c1, &mut rng).unwrap();
    let setup_ms = t.elapsed().as_secs_f64() * 1000.0;
    let pvk = Groth16::<Bn254>::process_vk(&vk).unwrap();

    let c2 =
        <GenTradeV2Circuit<C, GG> as MockingCircuit<C, GG>>::generate_circuit(rc.clone(), &mut rng)
            .unwrap();
    let mut image = vec![c2.cm.unwrap(), c2.fee.unwrap()];
    image.extend([
        *c2.pk_buyer.unwrap().x().unwrap(),
        *c2.pk_buyer.unwrap().y().unwrap(),
        *c2.pk_seller.unwrap().x().unwrap(),
        *c2.pk_seller.unwrap().y().unwrap(),
        *c2.G_r.unwrap().x().unwrap(),
        *c2.G_r.unwrap().y().unwrap(),
        *c2.c1.unwrap().x().unwrap(),
        *c2.c1.unwrap().y().unwrap(),
    ]);
    image.extend(c2.CT_ord.clone().unwrap());
    let proof = Groth16::<Bn254>::prove(&pk, c2.clone(), &mut rng).unwrap();

    let prove_ms = (0..N_ITER)
        .map(|_| {
            let c = <GenTradeV2Circuit<C, GG> as MockingCircuit<C, GG>>::generate_circuit(
                rc.clone(),
                &mut rng,
            )
            .unwrap();
            let t = Instant::now();
            Groth16::<Bn254>::prove(&pk, c, &mut rng).unwrap();
            t.elapsed().as_secs_f64() * 1000.0
        })
        .sum::<f64>()
        / N_ITER as f64;
    let verify_us = (0..N_ITER)
        .map(|_| {
            let t = Instant::now();
            Groth16::<Bn254>::verify_with_processed_vk(&pvk, &image, &proof).unwrap();
            t.elapsed().as_micros() as f64
        })
        .sum::<f64>()
        / N_ITER as f64;

    println!("gentrade_v2,{log},0,{n},{setup_ms:.1},{prove_ms:.1},{verify_us:.0}");
}

fn bench_accepttrade_v2_original(log: usize) {
    use zkMarket::accepttrade_v2::circuit::AcceptTradeV2Circuit;

    let rc = mimc_params();
    let mut rng = fresh_rng();
    let payload = payload_original(&mut rng);
    let key_bits = zkMarket::register_MatPRG::current_key_bits();

    let n = count_constraints(
        AcceptTradeV2Circuit::<C, GG>::generate_circuit_with_payload(
            rc.clone(),
            32,
            payload.clone(),
            &mut rng,
        )
        .unwrap(),
    );
    let c1 = AcceptTradeV2Circuit::<C, GG>::generate_circuit_with_payload(
        rc.clone(),
        32,
        payload.clone(),
        &mut rng,
    )
    .unwrap();
    let t = Instant::now();
    let (pk, vk) = Groth16::<Bn254>::setup(c1, &mut rng).unwrap();
    let setup_ms = t.elapsed().as_secs_f64() * 1000.0;
    let pvk = Groth16::<Bn254>::process_vk(&vk).unwrap();

    let c2 = AcceptTradeV2Circuit::<C, GG>::generate_circuit_with_payload(
        rc.clone(),
        32,
        payload,
        &mut rng,
    )
    .unwrap();
    let mut image = vec![
        c2.rt.unwrap(),
        c2.nf.unwrap(),
        c2.cmAzeroth.unwrap(),
        c2.hk.unwrap(),
        c2.addrseller.unwrap(),
        *c2.pkseller.unwrap().x().unwrap(),
        *c2.pkseller.unwrap().y().unwrap(),
        *c2.rel_G_r.unwrap().x().unwrap(),
        *c2.rel_G_r.unwrap().y().unwrap(),
        *c2.rel_c1.unwrap().x().unwrap(),
        *c2.rel_c1.unwrap().y().unwrap(),
    ];
    image.extend(c2.CT_k.clone().unwrap());
    let proof = Groth16::<Bn254>::prove(&pk, c2.clone(), &mut rng).unwrap();

    let prove_ms = (0..N_ITER)
        .map(|_| {
            let payload = payload_original(&mut rng);
            let c = AcceptTradeV2Circuit::<C, GG>::generate_circuit_with_payload(
                rc.clone(),
                32,
                payload,
                &mut rng,
            )
            .unwrap();
            let t = Instant::now();
            Groth16::<Bn254>::prove(&pk, c, &mut rng).unwrap();
            t.elapsed().as_secs_f64() * 1000.0
        })
        .sum::<f64>()
        / N_ITER as f64;
    let verify_us = (0..N_ITER)
        .map(|_| {
            let t = Instant::now();
            Groth16::<Bn254>::verify_with_processed_vk(&pvk, &image, &proof).unwrap();
            t.elapsed().as_micros() as f64
        })
        .sum::<f64>()
        / N_ITER as f64;

    println!(
        "accepttrade_v2_original,{log},{key_bits},{n},{setup_ms:.1},{prove_ms:.1},{verify_us:.0}"
    );
}

fn bench_accepttrade_v2_seeded(log: usize) {
    use zkMarket::accepttrade_v2::circuit::AcceptTradeV2Circuit;
    assert!(
        zkMarket::register_seeded_matprg::one_shot_feasible(),
        "seeded MatPRG is infeasible for DATA_LOG={log}"
    );

    let rc = mimc_params();
    let mut rng = fresh_rng();
    let payload = payload_recursive(&mut rng);
    let key_bits = zkMarket::register_seeded_matprg::current_key_bits();

    let n = count_constraints(
        AcceptTradeV2Circuit::<C, GG>::generate_circuit_with_payload(
            rc.clone(),
            32,
            payload.clone(),
            &mut rng,
        )
        .unwrap(),
    );
    let c1 = AcceptTradeV2Circuit::<C, GG>::generate_circuit_with_payload(
        rc.clone(),
        32,
        payload.clone(),
        &mut rng,
    )
    .unwrap();
    let t = Instant::now();
    let (pk, vk) = Groth16::<Bn254>::setup(c1, &mut rng).unwrap();
    let setup_ms = t.elapsed().as_secs_f64() * 1000.0;
    let pvk = Groth16::<Bn254>::process_vk(&vk).unwrap();

    let c2 = AcceptTradeV2Circuit::<C, GG>::generate_circuit_with_payload(
        rc.clone(),
        32,
        payload,
        &mut rng,
    )
    .unwrap();
    let mut image = vec![
        c2.rt.unwrap(),
        c2.nf.unwrap(),
        c2.cmAzeroth.unwrap(),
        c2.hk.unwrap(),
        c2.addrseller.unwrap(),
        *c2.pkseller.unwrap().x().unwrap(),
        *c2.pkseller.unwrap().y().unwrap(),
        *c2.rel_G_r.unwrap().x().unwrap(),
        *c2.rel_G_r.unwrap().y().unwrap(),
        *c2.rel_c1.unwrap().x().unwrap(),
        *c2.rel_c1.unwrap().y().unwrap(),
    ];
    image.extend(c2.CT_k.clone().unwrap());
    let proof = Groth16::<Bn254>::prove(&pk, c2.clone(), &mut rng).unwrap();

    let prove_ms = (0..N_ITER)
        .map(|_| {
            let payload = payload_recursive(&mut rng);
            let c = AcceptTradeV2Circuit::<C, GG>::generate_circuit_with_payload(
                rc.clone(),
                32,
                payload,
                &mut rng,
            )
            .unwrap();
            let t = Instant::now();
            Groth16::<Bn254>::prove(&pk, c, &mut rng).unwrap();
            t.elapsed().as_secs_f64() * 1000.0
        })
        .sum::<f64>()
        / N_ITER as f64;
    let verify_us = (0..N_ITER)
        .map(|_| {
            let t = Instant::now();
            Groth16::<Bn254>::verify_with_processed_vk(&pvk, &image, &proof).unwrap();
            t.elapsed().as_micros() as f64
        })
        .sum::<f64>()
        / N_ITER as f64;

    println!(
        "accepttrade_v2_seeded,{log},{key_bits},{n},{setup_ms:.1},{prove_ms:.1},{verify_us:.0}"
    );
}

fn run_inner() {
    let circuit = std::env::var("BENCH_CIRCUIT").expect("BENCH_CIRCUIT not set");
    let log: usize = std::env::var("DATA_LOG")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(6);
    match circuit.as_str() {
        "gentrade_v2" => bench_gentrade_v2(log),
        "accepttrade_v2_original" => bench_accepttrade_v2_original(log),
        "accepttrade_v2_seeded" => bench_accepttrade_v2_seeded(log),
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

    println!("circuit,data_log,key_bits,constraints,setup_ms,prove_ms,verify_us");
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
