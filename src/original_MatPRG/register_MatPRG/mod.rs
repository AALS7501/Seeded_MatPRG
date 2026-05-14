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

#[derive(Clone, Copy, Debug)]
pub struct DataConfig {
    pub N: usize,
    pub M: usize,
    pub Data_size: usize,
    pub K: usize,
    pub Key_len: usize,
}

impl DataConfig {
    pub const fn explicit_key_bits(&self) -> usize {
        self.M * self.K
    }

    pub const fn payload_len_from_bits(bits: usize) -> usize {
        bits.div_ceil(256)
    }
}

// Pass DATA_LOG=n to select a preset where data size ≈ 2^n KB (default n=5, 32KB).
//
// Valid n values and approximate sizes:
//   5 →  32KB   6 →  64KB   7 → 128KB   8 → 256KB   9 → 512KB
//  10 →   1MB  11 →   2MB  12 →   4MB  15 →  32MB  16 →  64MB
const PRESETS: &[(usize, DataConfig)] = &[
    (16, DataConfig { N: 1000, M: 1005, K: 2000, Data_size: 2000000, Key_len: 8000 }),
    (15, DataConfig { N: 1000, M: 1005, K: 1000, Data_size: 1000000, Key_len: 4000 }),
    (12, DataConfig { N:  766, M:  894, K:  162, Data_size:  124000, Key_len:  566 }),
    (11, DataConfig { N:  766, M:  894, K:   81, Data_size:   62000, Key_len:  283 }),
    (10, DataConfig { N:  762, M:  890, K:   42, Data_size:   32000, Key_len:  147 }),
    ( 9, DataConfig { N:  762, M:  890, K:   21, Data_size:   16000, Key_len:   74 }),
    ( 8, DataConfig { N:  766, M:  894, K:   12, Data_size:    9182, Key_len:   42 }),
    ( 7, DataConfig { N:  683, M:  811, K:    6, Data_size:    4096, Key_len:   20 }),
    ( 6, DataConfig { N:  683, M:  811, K:    3, Data_size:    2048, Key_len:   10 }),
    ( 5, DataConfig { N:   32, M:   42, K:   32, Data_size:    1024, Key_len:    7 }),
];

fn env_usize(name: &str) -> Option<usize> {
    std::env::var(name).ok()?.parse().ok()
}

pub(crate) static DATA_SET: LazyLock<DataConfig> = LazyLock::new(|| {
    if let (Some(N), Some(M), Some(Data_size), Some(K)) = (
        env_usize("ORIG_PARAM_N"),
        env_usize("ORIG_PARAM_M"),
        env_usize("ORIG_PARAM_DATA_SIZE"),
        env_usize("ORIG_PARAM_K"),
    ) {
        let explicit_bits = M * K;
        let Key_len = env_usize("ORIG_PARAM_KEY_LEN")
            .unwrap_or_else(|| DataConfig::payload_len_from_bits(explicit_bits));
        return DataConfig {
            N,
            M,
            Data_size,
            K,
            Key_len,
        };
    }

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

pub fn current_key_bits() -> usize {
    DATA_SET.explicit_key_bits()
}

pub fn current_key_payload_len() -> usize {
    DATA_SET.Key_len
}
