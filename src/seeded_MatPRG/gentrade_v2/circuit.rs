use crate::Error;
use crate::gadget::hashes;
use crate::gadget::hashes::constraints::CRHSchemeGadget;
use crate::gadget::hashes::mimc7;
use crate::gadget::hashes::mimc7::constraints::MiMCGadget;
use crate::gadget::public_encryptions::AsymmetricEncryptionGadget;
use crate::gadget::public_encryptions::AsymmetricEncryptionScheme;
use crate::gadget::public_encryptions::elgamal;
use crate::gadget::public_encryptions::elgamal::constraints::ElGamalEncGadget;
use crate::gadget::symmetric_encrytions::SymmetricEncryption;
use crate::gadget::symmetric_encrytions::constraints::SymmetricEncryptionGadget;
use crate::gadget::symmetric_encrytions::symmetric;
use crate::gadget::symmetric_encrytions::symmetric::constraints::SymmetricEncryptionSchemeGadget;

use ark_crypto_primitives::sponge::Absorb;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::{fields::fp::FpVar, prelude::AllocVar};
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
use ark_std::marker::PhantomData;

use super::MockingCircuit;

pub type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;

#[allow(non_snake_case)]
#[derive(Clone)]
pub struct GenTradeV2Circuit<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>>
where
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    pub rc: mimc7::Parameters<C::BaseField>,
    pub G: elgamal::Parameters<C>,

    pub cm: Option<C::BaseField>,
    pub fee: Option<C::BaseField>,
    pub pk_buyer: Option<elgamal::PublicKey<C>>,
    pub pk_seller: Option<elgamal::PublicKey<C>>,
    pub CT_ord: Option<Vec<C::BaseField>>,
    pub h_k: Option<C::BaseField>,
    pub G_r: Option<C::Affine>,
    pub c1: Option<C::Affine>,

    pub r: Option<C::BaseField>,
    pub CT_ord_key: Option<elgamal::Plaintext<C>>,
    pub CT_ord_key_x: Option<symmetric::SymmetricKey<C::BaseField>>,
    pub CT_r: Option<elgamal::Randomness<C>>,

    pub _curve_var: PhantomData<GG>,
}

#[allow(non_snake_case)]
impl<C, GG> ConstraintSynthesizer<C::BaseField> for GenTradeV2Circuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<C::BaseField>,
    ) -> Result<(), SynthesisError> {
        let rc = hashes::mimc7::constraints::ParametersVar::new_constant(
            ark_relations::ns!(cs, "round constants"),
            self.rc,
        )?;
        let G = elgamal::constraints::ParametersVar::new_constant(
            ark_relations::ns!(cs, "generator"),
            self.G,
        )?;

        let cm = FpVar::new_input(cs.clone(), || {
            self.cm.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let fee = FpVar::new_input(cs.clone(), || {
            self.fee.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let pk_buyer = elgamal::constraints::PublicKeyVar::new_input(
            ark_relations::ns!(cs, "pk_buyer"),
            || self.pk_buyer.ok_or(SynthesisError::AssignmentMissing),
        )?;
        let pk_seller = elgamal::constraints::PublicKeyVar::new_input(
            ark_relations::ns!(cs, "pk_seller"),
            || self.pk_seller.ok_or(SynthesisError::AssignmentMissing),
        )?;
        let c1 = elgamal::constraints::OutputVar::new_input(ark_relations::ns!(cs, "c1"), || {
            Ok((self.G_r.unwrap(), self.c1.unwrap()))
        })?;
        let CT_ord_raw: Vec<FpVar<C::BaseField>> =
            Vec::new_input(ark_relations::ns!(cs, "CT_ord"), || {
                self.CT_ord.ok_or(SynthesisError::AssignmentMissing)
            })?;
        let CT_ord = vec![
            symmetric::constraints::CiphertextVar {
                c: CT_ord_raw[0].clone(),
                r: FpVar::Constant(C::BaseField::from(0u64)),
            },
            symmetric::constraints::CiphertextVar {
                c: CT_ord_raw[1].clone(),
                r: FpVar::Constant(C::BaseField::from(1u64)),
            },
            symmetric::constraints::CiphertextVar {
                c: CT_ord_raw[2].clone(),
                r: FpVar::Constant(C::BaseField::from(2u64)),
            },
            symmetric::constraints::CiphertextVar {
                c: CT_ord_raw[3].clone(),
                r: FpVar::Constant(C::BaseField::from(3u64)),
            },
            symmetric::constraints::CiphertextVar {
                c: CT_ord_raw[4].clone(),
                r: FpVar::Constant(C::BaseField::from(4u64)),
            },
        ];

        let r = FpVar::new_witness(ark_relations::ns!(cs, "r"), || Ok(self.r.unwrap()))?;
        let h_k = FpVar::new_witness(ark_relations::ns!(cs, "h_k"), || Ok(self.h_k.unwrap()))?;
        let CT_ord_key = elgamal::constraints::PlaintextVar::new_witness(
            ark_relations::ns!(cs, "CT_ord_key"),
            || self.CT_ord_key.ok_or(SynthesisError::AssignmentMissing),
        )?;
        let CT_ord_key_x = symmetric::constraints::SymmetricKeyVar::new_witness(
            ark_relations::ns!(cs, "CT_ord_key_x"),
            || self.CT_ord_key_x.ok_or(SynthesisError::AssignmentMissing),
        )?;
        let CT_r = elgamal::constraints::RandomnessVar::new_witness(
            ark_relations::ns!(cs, "CT_r"),
            || self.CT_r.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let buyer_bits = pk_buyer.pk.to_bits_le()?;
        let pk_buyer_x = Boolean::le_bits_to_fp_var(&buyer_bits[..buyer_bits.len() / 2])?;
        let pk_buyer_y = Boolean::le_bits_to_fp_var(&buyer_bits[buyer_bits.len() / 2..])?;

        let seller_bits = pk_seller.pk.to_bits_le()?;
        let pk_seller_x = Boolean::le_bits_to_fp_var(&seller_bits[..seller_bits.len() / 2])?;

        let key_bits = CT_ord_key.plaintext.to_bits_le()?;
        let key_x = Boolean::le_bits_to_fp_var(&key_bits[..key_bits.len() / 2])?;
        key_x.enforce_equal(&CT_ord_key_x.k)?;

        let expected_order_ct =
            ElGamalEncGadget::<C, GG>::encrypt(&G, &CT_ord_key, &CT_r, &pk_seller)?;
        c1.enforce_equal(&expected_order_ct)?;

        let order_plain = vec![
            pk_buyer_x.clone(),
            pk_buyer_y.clone(),
            r.clone(),
            fee.clone(),
            h_k.clone(),
        ];
        for (i, m) in order_plain.iter().enumerate() {
            let randomness = symmetric::constraints::RandomnessVar::new_constant(
                ark_relations::ns!(cs, "rand"),
                symmetric::Randomness {
                    r: C::BaseField::from(i as u64),
                },
            )?;
            let c = SymmetricEncryptionSchemeGadget::<C::BaseField>::encrypt(
                rc.clone(),
                randomness,
                CT_ord_key_x.clone(),
                symmetric::constraints::PlaintextVar { m: m.clone() },
            )
            .map_err(|_| SynthesisError::Unsatisfiable)?;
            c.enforce_equal(&CT_ord[i])?;
        }

        let cm_input = vec![
            pk_seller_x.clone(),
            r.clone(),
            fee.clone(),
            h_k.clone(),
            pk_buyer_x.clone(),
        ];
        let expected_cm = MiMCGadget::<C::BaseField>::evaluate(&rc, &cm_input)?;
        cm.enforce_equal(&expected_cm)?;

        Ok(())
    }
}

#[allow(non_snake_case)]
impl<C, GG> MockingCircuit<C, GG> for GenTradeV2Circuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    type F = C::BaseField;
    type HashParam = mimc7::Parameters<Self::F>;
    type H = mimc7::MiMC<Self::F>;
    type Output = GenTradeV2Circuit<C, GG>;

    fn generate_circuit<R: ark_std::rand::Rng>(
        round_constants: Self::HashParam,
        rng: &mut R,
    ) -> Result<Self::Output, Error> {
        use crate::gadget::hashes::CRHScheme;
        use crate::gadget::public_encryptions::elgamal::ElGamal;
        use ark_std::{One, UniformRand};

        let generator = C::generator().into_affine();
        let elgamal_param = elgamal::Parameters { generator };
        let rc = round_constants;

        let fee = Self::F::one();
        let r = Self::F::one();
        let h_k = Self::F::one();
        let (pk_buyer, _): (elgamal::PublicKey<C>, elgamal::SecretKey<C>) =
            ElGamal::keygen(&elgamal_param, rng)?;
        let (pk_seller, _): (elgamal::PublicKey<C>, elgamal::SecretKey<C>) =
            ElGamal::keygen(&elgamal_param, rng)?;

        let (pk_buyer_x, pk_buyer_y) = pk_buyer.xy().unwrap();
        let pk_buyer_x = Self::F::from_bigint(pk_buyer_x.into_bigint()).unwrap();
        let pk_buyer_y = Self::F::from_bigint(pk_buyer_y.into_bigint()).unwrap();
        let (pk_seller_x, _) = pk_seller.xy().unwrap();
        let pk_seller_x = Self::F::from_bigint(pk_seller_x.into_bigint()).unwrap();

        let cm = Self::H::evaluate(
            &rc,
            vec![pk_seller_x, r, fee, h_k, pk_buyer_x],
        )?;

        let CT_ord_key = C::rand(rng).into_affine();
        let CT_ord_key_x = symmetric::SymmetricKey {
            k: Self::F::from_bigint(CT_ord_key.x().unwrap().into_bigint()).unwrap(),
        };
        let CT_r = elgamal::Randomness(C::ScalarField::rand(rng));
        let (G_r, c1) = ElGamal::encrypt(&elgamal_param, &pk_seller, &CT_ord_key, &CT_r)?;

        let order_plain = vec![pk_buyer_x, pk_buyer_y, r, fee, h_k];
        let mut CT_ord = Vec::with_capacity(order_plain.len());
        for (i, m) in order_plain.iter().enumerate() {
            let c = symmetric::SymmetricEncryptionScheme::encrypt(
                rc.clone(),
                symmetric::Randomness {
                    r: Self::F::from(i as u64),
                },
                CT_ord_key_x.clone(),
                symmetric::Plaintext { m: *m },
            )?;
            CT_ord.push(c.c);
        }

        Ok(GenTradeV2Circuit {
            rc,
            G: elgamal_param,
            cm: Some(cm),
            fee: Some(fee),
            pk_buyer: Some(pk_buyer),
            pk_seller: Some(pk_seller),
            CT_ord: Some(CT_ord),
            h_k: Some(h_k),
            G_r: Some(G_r),
            c1: Some(c1),
            r: Some(r),
            CT_ord_key: Some(CT_ord_key),
            CT_ord_key_x: Some(CT_ord_key_x),
            CT_r: Some(CT_r),
            _curve_var: PhantomData,
        })
    }
}
