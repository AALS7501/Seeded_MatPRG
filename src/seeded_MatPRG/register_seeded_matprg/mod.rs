use crate::Error;
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::prelude::{CurveVar, GroupOpsBounds};
use std::sync::LazyLock;

pub mod circuit;

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
    pub M1: usize,
    pub M2: usize,
    pub Data_size: usize,
    pub K: usize,
    pub N1: usize,
    pub Low_bits: usize,
}

impl DataConfig {
    pub const fn recursive_seed_bits(&self) -> usize {
        self.M1
    }

    pub const fn expanded_key_bits(&self) -> usize {
        self.M2 * self.K
    }

    pub const fn truncation_output_bits(&self) -> usize {
        self.N1 * self.Low_bits
    }

    pub const fn one_shot_feasible(&self) -> bool {
        self.truncation_output_bits() >= self.expanded_key_bits()
    }
}

const PRESETS: &[(usize, DataConfig)] = &[
    (
        16,
        DataConfig {
            N: 1000,
            M1: 17633,
            M2: 1005,
            K: 2000,
            N1: 17632,
            Low_bits: 114,
            Data_size: 2000000,
        },
    ),
    (
        15,
        DataConfig {
            N: 1000,
            M1: 8817,
            M2: 1005,
            K: 1000,
            N1: 8816,
            Low_bits: 114,
            Data_size: 1000000,
        },
    ),
    (
        12,
        DataConfig {
            N: 116,
            M1: 1061,
            M2: 117,
            K: 1069,
            N1: 1060,
            Low_bits: 118,
            Data_size: 124000,
        },
    ),
    (
        11,
        DataConfig {
            N: 80,
            M1: 533,
            M2: 81,
            K: 775,
            N1: 532,
            Low_bits: 118,
            Data_size: 62000,
        },
    ),
    (
        10,
        DataConfig {
            N: 50,
            M1: 273,
            M2: 51,
            K: 640,
            N1: 272,
            Low_bits: 120,
            Data_size: 32000,
        },
    ),
    (
        9,
        DataConfig {
            N: 27,
            M1: 136,
            M2: 28,
            K: 593,
            N1: 135,
            Low_bits: 123,
            Data_size: 16000,
        },
    ),
    (
        8,
        DataConfig {
            N: 24,
            M1: 128,
            M2: 25,
            K: 383,
            N1: 78,
            Low_bits: 123,
            Data_size: 9182,
        },
    ),
    (
        7,
        DataConfig {
            N: 20,
            M1: 128,
            M2: 21,
            K: 205,
            N1: 35,
            Low_bits: 123,
            Data_size: 4096,
        },
    ),
    (
        6,
        DataConfig {
            N: 13,
            M1: 128,
            M2: 14,
            K: 158,
            N1: 18,
            Low_bits: 123,
            Data_size: 2048,
        },
    ),
    (
        5,
        DataConfig {
            N: 32,
            M1: 53,
            M2: 42,
            K: 32,
            N1: 52,
            Low_bits: 26,
            Data_size: 1024,
        },
    ),
];

fn env_usize(name: &str) -> Option<usize> {
    std::env::var(name).ok()?.parse().ok()
}

pub(crate) static DATA_SET: LazyLock<DataConfig> = LazyLock::new(|| {
    if let (
        Some(N),
        Some(M1),
        Some(M2),
        Some(Data_size),
        Some(K),
        Some(N1),
        Some(Low_bits),
    ) = (
        env_usize("PARAM_N"),
        env_usize("PARAM_M1"),
        env_usize("PARAM_M2"),
        env_usize("PARAM_DATA_SIZE"),
        env_usize("PARAM_K"),
        env_usize("PARAM_N1"),
        env_usize("PARAM_LOW_BITS"),
    ) {
        return DataConfig {
            N,
            M1,
            M2,
            Data_size,
            K,
            N1,
            Low_bits,
        };
    }

    let log: usize = std::env::var("DATA_LOG")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);
    PRESETS
        .iter()
        .find(|(n, _)| *n == log)
        .map(|(_, p)| *p)
        .unwrap_or_else(|| {
            let valid: Vec<usize> = PRESETS.iter().map(|(n, _)| *n).collect();
            panic!("No preset for DATA_LOG={log}. Valid values: {valid:?}");
        })
});

pub fn current_key_bits() -> usize {
    DATA_SET.recursive_seed_bits()
}

pub fn one_shot_feasible() -> bool {
    DATA_SET.one_shot_feasible()
}

pub fn current_low_bits() -> usize {
    DATA_SET.Low_bits
}
