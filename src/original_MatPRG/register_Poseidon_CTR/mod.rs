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
        params: Self::HashParam,
        rng: &mut R,
    ) -> Result<Self::Output, Error>;
}

#[derive(Clone, Copy)]
pub struct DataConfig {
    pub Data_size: usize,
}

// Pass DATA_LOG=n to select data size ≈ 2^n KB (default n=6, 64KB).
//   6 →  64KB   7 → 128KB   8 → 256KB   9 → 512KB  10 → 1MB  11 → 2MB  12 → 4MB
pub(crate) static DATA_SET: LazyLock<DataConfig> = LazyLock::new(|| {
    let log: usize = std::env::var("DATA_LOG")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(6);
    DataConfig { Data_size: (1usize << log) * 1024 / 32 }
});
