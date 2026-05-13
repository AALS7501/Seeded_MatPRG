use std::borrow::Borrow;

use ark_crypto_primitives::Error;
use ark_std::hash::Hash;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

pub mod constraints;

pub mod mimc7;
pub mod poseidon;

pub trait CRHScheme {
    type Input: ?Sized;
    type Output: Clone
        + Eq
        + core::fmt::Debug
        + Hash
        + Default
        + CanonicalSerialize
        + CanonicalDeserialize;
    type Parameters: Clone;

    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error>;
}

pub trait TwoToOneCRHScheme {
    type Input: ?Sized;
    type Output;
    type Parameters: Clone;

    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, Error>;

    fn compress<T: Borrow<Self::Output>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, Error>;
}
