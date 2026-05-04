use crate::Error;
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::prelude::{CurveVar, GroupOpsBounds};
use std::sync::LazyLock;
pub mod circuit;
#[cfg(test)]
mod tests;

pub trait MockingCircuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    type F;
    type HashParam;
    type H;
    type Output;

    fn generate_circuit<R: ark_std::rand::Rng>(
        round_constants: Self::HashParam,
        rng: &mut R,
    ) -> Result<Self::Output, Error>;
}

#[derive(Clone, Copy)]
pub struct Data_size {
    pub N: usize,
    pub M: usize,
    pub Data_size: usize,
    pub K: usize,
    pub Key_len: usize,
}

// Pass DATA_LOG=n to select a preset where data size ≈ 2^n KB (default n=5, 32KB).
//
// Valid n values and approximate sizes:
//   5 →  32KB   6 →  64KB   7 → 128KB   8 → 256KB   9 → 512KB
//  10 →   1MB  11 →   2MB  12 →   4MB  15 →  32MB  16 →  64MB
const PRESETS: &[(usize, Data_size)] = &[
    (16, Data_size { N: 1000, M: 1005, K: 2000, Data_size: 2000000, Key_len: 8000 }),
    (15, Data_size { N: 1000, M: 1005, K: 1000, Data_size: 1000000, Key_len: 4000 }),
    (12, Data_size { N:  355, M:  365, K:  355, Data_size:  124000, Key_len:  507 }),
    (11, Data_size { N:  250, M:  260, K:  250, Data_size:   62000, Key_len:  254 }),
    (10, Data_size { N:  180, M:  190, K:  180, Data_size:   32000, Key_len:  134 }),
    ( 9, Data_size { N:  130, M:  140, K:  130, Data_size:   16000, Key_len:   72 }),
    ( 8, Data_size { N:   96, M:  106, K:   96, Data_size:    9182, Key_len:   40 }),
    ( 7, Data_size { N:   64, M:   74, K:   64, Data_size:    4096, Key_len:   19 }),
    ( 6, Data_size { N:   46, M:   56, K:   46, Data_size:    2048, Key_len:   11 }),
    ( 5, Data_size { N:   32, M:   42, K:   32, Data_size:    1024, Key_len:    7 }),
];

// KEY LEN = (M * K) / 256 + 1;  Data size = N * K
pub(crate) static DATA_SET: LazyLock<Data_size> = LazyLock::new(|| {
    let log: usize = std::env::var("DATA_LOG")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);
    PRESETS.iter()
        .find(|(n, _)| *n == log)
        .map(|(_, p)| *p)
        .unwrap_or_else(|| {
            let valid: Vec<usize> = PRESETS.iter().map(|(n, _)| *n).collect();
            panic!("No preset for DATA_LOG={log}. Valid values: {valid:?}");
        })
});
