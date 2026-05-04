use crate::gadget::hashes::mimc7;
use crate::gadget::public_encryptions::elgamal;
use crate::gadget::public_encryptions::AsymmetricEncryptionScheme;
use crate::gadget::symmetric_encrytions::symmetric;
use crate::gadget::symmetric_encrytions::SymmetricEncryption;
use crate::Error;
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_std::{rand::Rng, UniformRand};

#[derive(Clone)]
pub struct HybridWrappedPayload<C: CurveGroup>
where
    C::BaseField: PrimeField + Absorb,
{
    pub encapsulated_point: elgamal::Ciphertext<C>,
    pub payload_ct: Vec<symmetric::Ciphertext<C::BaseField>>,
}

#[derive(Clone)]
pub struct HybridWrappingWitness<C: CurveGroup>
where
    C::BaseField: PrimeField + Absorb,
{
    pub payload_point: elgamal::Plaintext<C>,
    pub payload_key: symmetric::SymmetricKey<C::BaseField>,
    pub elgamal_randomness: elgamal::Randomness<C>,
}

fn point_x_key<C: CurveGroup>(
    point: &elgamal::Plaintext<C>,
) -> Result<symmetric::SymmetricKey<C::BaseField>, Error>
where
    C::BaseField: PrimeField + Absorb,
{
    let x = point
        .x()
        .copied()
        .ok_or_else(|| -> Error {
            From::from("point at infinity cannot be used as transport payload")
        })?;
    Ok(symmetric::SymmetricKey { k: x })
}

pub fn pack_bits_to_fields<F: PrimeField>(bits: &[bool], chunk_bits: usize) -> Vec<F> {
    bits.chunks(chunk_bits)
        .map(|chunk| {
            let mut acc = F::zero();
            let mut coeff = F::one();
            for bit in chunk {
                if *bit {
                    acc += coeff;
                }
                coeff = coeff.double();
            }
            acc
        })
        .collect()
}

pub fn wrap_payload_for_recipient<C, R>(
    rc: mimc7::Parameters<C::BaseField>,
    elgamal_params: &elgamal::Parameters<C>,
    recipient_pk: &elgamal::PublicKey<C>,
    payload: &[C::BaseField],
    rng: &mut R,
) -> Result<(HybridWrappedPayload<C>, HybridWrappingWitness<C>), Error>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    R: Rng,
{
    let payload_point = C::rand(rng).into_affine();
    let payload_key = point_x_key::<C>(&payload_point)?;
    let elgamal_randomness = elgamal::Randomness::rand(rng);

    let encapsulated_point = elgamal::ElGamal::<C>::encrypt(
        elgamal_params,
        recipient_pk,
        &payload_point,
        &elgamal_randomness,
    )?;

    let payload_ct = payload
        .iter()
        .enumerate()
        .map(|(i, msg)| {
            symmetric::SymmetricEncryptionScheme::encrypt(
                rc.clone(),
                symmetric::Randomness {
                    r: C::BaseField::from(i as u64),
                },
                payload_key.clone(),
                symmetric::Plaintext { m: *msg },
            )
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok((
        HybridWrappedPayload {
            encapsulated_point,
            payload_ct,
        },
        HybridWrappingWitness {
            payload_point,
            payload_key,
            elgamal_randomness,
        },
    ))
}

pub fn unwrap_payload_for_recipient<C>(
    rc: mimc7::Parameters<C::BaseField>,
    elgamal_params: &elgamal::Parameters<C>,
    recipient_sk: &elgamal::SecretKey<C>,
    wrapped: &HybridWrappedPayload<C>,
) -> Result<Vec<C::BaseField>, Error>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
{
    let payload_point = elgamal::ElGamal::<C>::decrypt(
        elgamal_params,
        recipient_sk,
        &wrapped.encapsulated_point,
    )?;
    let payload_key = point_x_key::<C>(&payload_point)?;

    wrapped
        .payload_ct
        .iter()
        .map(|ct| {
            symmetric::SymmetricEncryptionScheme::decrypt(rc.clone(), payload_key.clone(), ct.clone())
                .map(|pt| pt.m)
        })
        .collect()
}
