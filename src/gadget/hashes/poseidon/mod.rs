pub mod constraints;
pub mod parameters;

use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, PoseidonSponge};
use ark_crypto_primitives::sponge::{Absorb, CryptographicSponge};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{borrow::Borrow, marker::PhantomData};

use crate::gadget::hashes::{CRHScheme, TwoToOneCRHScheme};
use crate::Error;

// #[cfg(feature = "r1cs")]
// pub mod constraints;

pub struct PoseidonHash<F: PrimeField + Absorb> {
    field_phantom: PhantomData<F>,
}

impl<F: PrimeField + Absorb> CRHScheme for PoseidonHash<F> {
    type Input = [F];
    type Output = F;
    type Parameters = PoseidonConfig<F>;

    // fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
    //     // automatic generation of parameters are not implemented yet
    //     // therefore, the developers must specify the parameters themselves
    //     unimplemented!()
    // }

    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error> {
        let input = input.borrow();

        let mut sponge = PoseidonSponge::new(parameters);
        sponge.absorb(&input);
        let res = sponge.squeeze_field_elements::<F>(1);
        Ok(res[0])
    }
}

#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PoseidonHashOutputWrapper<F: PrimeField>(pub <PoseidonHash<F> as CRHScheme>::Output)
where
    F: PrimeField + Absorb;

impl<F> From<<PoseidonHash<F> as CRHScheme>::Output> for PoseidonHashOutputWrapper<F>
where
    F: PrimeField + Absorb,
{
    fn from(value: <PoseidonHash<F> as CRHScheme>::Output) -> Self {
        Self(value)
    }
}

pub struct TwoToOneCRH<F: PrimeField + Absorb> {
    field_phantom: PhantomData<F>,
}

impl<F: PrimeField + Absorb> TwoToOneCRHScheme for TwoToOneCRH<F> {
    type Input = F;
    type Output = F;
    type Parameters = PoseidonConfig<F>;

    // fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
    //     // automatic generation of parameters are not implemented yet
    //     // therefore, the developers must specify the parameters themselves
    //     unimplemented!()
    // }

    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, Error> {
        Self::compress(parameters, left_input, right_input)
    }

    fn compress<T: Borrow<Self::Output>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, Error> {
        let left_input = left_input.borrow();
        let right_input = right_input.borrow();

        let mut sponge = PoseidonSponge::new(parameters);
        sponge.absorb(left_input);
        sponge.absorb(right_input);
        let res = sponge.squeeze_field_elements::<F>(1);
        Ok(res[0])
    }
}