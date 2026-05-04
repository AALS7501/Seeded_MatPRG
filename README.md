# Seeded_MatPRG

A Rust implementation of the original and seeded MatPRG circuit libraries used in the zkMarket setting.

## Repository layout

The source tree is organized around the original and seeded MatPRG code paths:

- `src/cp_snark/`: shared CP-Groth16 commit-and-prove backend
- `src/gadget/`: shared hash, Merkle-tree, public-key encryption, symmetric-encryption, and key-transport gadgets
- `src/original_MatPRG/`: the original zkMarket MatPRG code path and baseline circuits
- `src/seeded_MatPRG/`: the compact-key seeded MatPRG code path

Within these folders:

- `src/original_MatPRG/` contains the original MatPRG relation, original trade circuits, MiMC/Poseidon registration baselines, and the legacy `registerdata` variants used for historical comparison.
- `src/seeded_MatPRG/` contains the seeded MatPRG implementation used in the paper: `register_seeded_matprg` and the updated trade circuits that transport the short seed rather than the full binary key matrix.

The repository ignores `bench_results/`; benchmark artifacts are kept local and are not tracked in Git.

## Paper

- [zkMarket](https://eprint.iacr.org/2024/1775.pdf)

## What is new in the seeded MatPRG code path

Compared with the original zkMarket implementation, the seeded MatPRG path adds:

- a short-seed register circuit that derives the MatPRG key matrix inside the proof,
- parameter presets for the compact-key seeded MatPRG construction used in the paper,
- updated trade circuits that carry the short seed across later proof steps, and
- hybrid key-transport helpers used to wrap the released seed payload for the buyer.

The repository no longer keeps the older seeded experimental variants. The seeded code path that remains in `src/seeded_MatPRG/` is `register_seeded_matprg`, the construction used by the paper.

---

## Gadgets

### Hashes

- `mimc7`
- `poseidon` (BN254)

### Merkle Tree

### Public Encryption

- `ElGamal encryption`

### Symmetric Encryption

Two symmetric encryption schemes are supported, both with R1CS gadget support.

#### MiMC7-CTR (baseline)

A simple stream cipher using MiMC7 in counter mode:

```
CT[i] = data[i] + TwoToOneMiMC(data_key, i)     # i = 0, 1, 2, ...
```

Each block requires one MiMC7 hash evaluation (~365 R1CS constraints per block), so constraint count scales linearly with data size. This serves as the baseline.

#### MatPRG-based encryption

Encrypts data using a pseudorandom matrix product:

```
R   = A · K          (A: N×M field matrix, K: M×l binary matrix)
CT  = data + R
```

The matrix K acts as a PRG output (stretched key). Security relies on the **DSIS assumption** over binary matrices. Constraint count is dominated by the Freivalds check for A·K, which is much cheaper than per-block hashing.

---

## CP-SNARK

A custom Groth16 variant that supports **commit-and-prove**. The first `committed_size` witness variables are committed via `proof.cm`, allowing the verifier to bind to the ciphertext without seeing it. See `src/cp_snark/`.

---

## RegisterData Circuits

The three paper-facing CP-Groth16 registration circuits described below share the same public interface:

- **Public input**: `H_k` — key commitment
- **Committed witness**: `CT` — ciphertext (bound to proof via `proof.cm`)
- **Private witnesses**: plaintext data, key material, `sk_seller`

The circuits differ in how they encrypt data and how the encryption key is structured.

### register_MiMC_CTR — Baseline

Uses MiMC7-CTR directly. Simple but expensive: each of the `Data_size` blocks requires a separate MiMC hash constraint.

```
CT[i]  = data[i] + TwoToOneMiMC(data_key, i)
H_k    = MiMC(data_key || sk_seller)
```

Each preset is selected by `DATA_LOG`. The labels `64 KB`, `128 KB`, ..., `4 MB` are tier names, while `Data_size` gives the exact number of field elements encrypted by the circuit at that preset.

### register_MatPRG — zkMarket paper

Implements the MatPRG-based scheme from the zkMarket paper. The encryption key `data_key` is bit-decomposed into a binary matrix K inside the circuit. A public matrix A (N×M) and K (M×Key_len binary) produce the keystream R = A·K.

```
K      = bit_decompose(data_key)    # M × Key_len binary, computed in-circuit
R      = A · K                      # N × Key_len keystream
CT     = data + R
H_k    = MiMC(data_key || sk_seller)
```

The Freivalds trick (A·K·γ = R·γ for random γ) is used to verify the matrix product with O(N+K) constraints instead of O(N·M·K).

**Parameters** (selected by `DATA_LOG`):

| DATA_LOG | Tier | Data_size | N | M | K | Key_len |
|---|---|---|---|---|---|---|
| 6 | 64 KB | 2048 | 46 | 56 | 46 | 11 |
| 7 | 128 KB | 4096 | 64 | 74 | 64 | 19 |
| 8 | 256 KB | 9182 | 96 | 106 | 96 | 40 |
| 9 | 512 KB | 16000 | 130 | 140 | 130 | 72 |
| 10 | 1 MB | 32000 | 180 | 190 | 180 | 134 |
| 11 | 2 MB | 62000 | 250 | 260 | 250 | 254 |
| 12 | 4 MB | 124000 | 355 | 365 | 355 | 507 |

### register_seeded_matprg — Seeded MatPRG used in the paper

This is the compact-key seeded MatPRG construction used in the paper. Instead of witnessing the full binary matrix, the circuit takes a short binary seed, computes a field-valued intermediate vector, keeps a fixed number of lower bits from each field element, and parses those bits into the binary key matrix required by the outer MatPRG step.

```
seed_bits   -> Y = A1 · seed_bits
low_t(Y)    -> binary key bits
K_seed      -> parsed binary matrix
R           = A2 · K_seed
CT          = data + R
H_k         = MiMC(seed_bits || sk_seller)
```

The seeded trade circuits in `src/seeded_MatPRG/accepttrade_v2` and `src/seeded_MatPRG/gentrade_v2` transport this short seed payload instead of the original explicit key matrix.

For this circuit, `M1` is the witnessed seed length in bits, `M2 × K` is the size of the expanded binary key matrix used by the outer MatPRG step, and `N1 × Low_bits` is the number of bits produced by the truncation step before parsing. In the paper-facing presets, `M1` is kept at least 128 bits to rule out parameter choices in which the public seed space can be directly enumerated. This is only a concrete admissibility floor for the reported presets, not a standalone claim that the construction achieves an independent 128-bit security level from the seed length alone.

**Parameters** (selected by `DATA_LOG`):

| DATA_LOG | Tier | Data_size | N | M1 (seed bits) | M2 | K | N1 | Low_bits |
|---|---|---|---|---|---|---|---|---|
| 5 | 32 KB | 1024 | 32 | 53 | 42 | 32 | 52 | 26 |
| 6 | 64 KB | 2048 | 13 | 128 | 14 | 158 | 18 | 123 |
| 7 | 128 KB | 4096 | 20 | 128 | 21 | 205 | 35 | 123 |
| 8 | 256 KB | 9182 | 24 | 128 | 25 | 383 | 78 | 123 |
| 9 | 512 KB | 16000 | 27 | 136 | 28 | 593 | 135 | 123 |
| 10 | 1 MB | 32000 | 50 | 273 | 51 | 640 | 272 | 120 |
| 11 | 2 MB | 62000 | 80 | 533 | 81 | 775 | 532 | 118 |
| 12 | 4 MB | 124000 | 116 | 1061 | 117 | 1069 | 1060 | 118 |
| 15 | 32 MB | 1000000 | 1000 | 8817 | 1005 | 1000 | 8816 | 114 |
| 16 | 64 MB | 2000000 | 1000 | 17633 | 1005 | 2000 | 17632 | 114 |

---

## Tests

```bash
# register_MatPRG
DATA_LOG=6 cargo test --release -- register_MatPRG::tests::test_register_MatPRG_circuit --exact --show-output

# seeded trade/register path
DATA_LOG=6 cargo test --release --features "register_MatPRG,register_seeded_matprg,accepttrade_v2,gentrade_v2" -- --show-output

# register_MiMC_CTR
DATA_LOG=6 cargo test --release -- register_MiMC_CTR::tests::test_register_MiMC_CTR_circuit --exact --show-output
```

---

## Benchmark

### Comparison benchmark

Runs the original MatPRG, MiMC-CTR, and Poseidon-CTR register circuits across `DATA_LOG=6..=12`, each in an isolated child process with a 10-minute timeout. Setup is measured once; prove and verify are averaged over 10 iterations. DATA_LOG values with no preset are printed as `SKIPPED`.

```bash
# All DATA_LOG values (6..=12)
cargo bench --bench comparison

# Single DATA_LOG
DATA_LOG=6 cargo bench --bench comparison
```

Output format: CSV — `circuit,data_log,constraints,setup_ms,prove_ms_mean,verify_us_mean`

### MatPRG-only benchmark

Compares the original MatPRG register circuit with `register_seeded_matprg`, the seeded circuit used in the paper.

```bash
DATA_LOG=6 cargo bench --bench comparison_matprg
```

---

## Legacy — RegisterData v1–v3

Circuits from the zkMarket paper evaluation (kept for reference).

| Version | Hash | Encryption | SNARK | Description |
|---|---|---|---|---|
| v1 | MiMC7 | Randomized | Groth16 | Per-block random encryption, baseline |
| v2 | MiMC7 | Randomized | CP-Groth16 | CP-SNARK applied to v1 |
| v3 | MiMC7 | Randomized | CP-Groth16 | CP-SNARK + MatPRG encryption |

### Tests

```bash
cargo test --release --features registerdata,parallel -- registerdatav1::tests::test_registerdatav1::test::test_registerdatav1 --exact --show-output
cargo test --release --features registerdata,parallel -- registerdatav2::tests::test_registerdatav2::test::test_registerdatav2 --exact --show-output
cargo test --release --features registerdata,parallel -- registerdatav3::tests::test_registerdatav3::test::test_registerdatav3 --exact --show-output
```

### Benchmark

```bash
DATA_LOG=5 cargo bench --features registerdata,parallel --bench registerdata
DATA_LOG=7 VERSION=3 cargo bench --features registerdata,parallel --bench registerdata
```
