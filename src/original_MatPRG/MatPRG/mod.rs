use crate::Error;
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::prelude::{CurveVar, GroupOpsBounds};
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

pub struct Data_size {
    pub N: usize,
    pub M: usize,
    pub Data_size: usize,
    pub K: usize,
    pub Key_len: usize,
}

// 64MB
// pub(crate) static DATA_SET: Data_size = Data_size {
//     N: 1000,
//     M: 1005,
//     Data_size: 2000000,
//     K: 2000,
//     Key_len: 8000,
// };

// 36MB
// pub(crate) static DATA_SET: Data_size = Data_size {
//     N: 1065,
//     M: 1075,
//     Data_size: 1125000,
//     K: 1065,
//     Key_len: 4473,
// };

// 32MB
// pub(crate) static DATA_SET: Data_size = Data_size {
//     N: 1000,
//     M: 1005,
//     Data_size: 1000000,
//     K: 1000,
//     Key_len: 4000,
// };

// 4MB
// pub(crate) static DATA_SET: Data_size = Data_size {
//     N: 355,
//     M: 365,
//     Data_size: 124000,
//     K: 355,
//     Key_len: 507,
// };

// 2MB
// pub(crate) static DATA_SET: Data_size = Data_size {
//     N: 250,
//     M: 260,
//     Data_size: 62000,
//     K: 250,
//     Key_len: 254,
// };

// 1MB 32400
pub(crate) static DATA_SET: Data_size = Data_size {
    N: 180,
    M: 190,
    Data_size: 32000,
    K: 180,
    Key_len: 134,
};

//0.5MB 16900
// pub(crate) static DATA_SET: Data_size = Data_size {
//     N: 130,
//     M: 140,
//     Data_size: 16000,
//     K: 130,
//     Key_len: 72,
// };

//64KB 2100개
// pub(crate) static DATA_SET: Data_size = Data_size {
//     N: 46,
//     M: 56,
//     Data_size: 2048,
//     K: 46,
//     Key_len: 11,
// };

// 32KB 1024
// pub(crate) static DATA_SET: Data_size = Data_size {
//     N: 32,
//     M: 42,
//     Data_size: 1024,
//     K: 32,
//     Key_len: 7,
// };

// KEY LEN = (M * K) / 256 + 1;
// Data size = N * K
