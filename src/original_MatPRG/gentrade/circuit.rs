use crate::gadget::hashes;
use crate::gadget::hashes::constraints::CRHSchemeGadget;
use crate::gadget::hashes::mimc7;
use crate::gadget::hashes::mimc7::constraints::MiMCGadget;
use crate::Error;

use crate::gadget::symmetric_encrytions::constraints::SymmetricEncryptionGadget;
use crate::gadget::symmetric_encrytions::symmetric;
use crate::gadget::symmetric_encrytions::symmetric::constraints::SymmetricEncryptionSchemeGadget;

use crate::gadget::public_encryptions::elgamal;
use crate::gadget::public_encryptions::elgamal::constraints::ElGamalEncGadget;
use crate::gadget::public_encryptions::AsymmetricEncryptionGadget;

use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::{fields::fp::FpVar, prelude::AllocVar};
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
use ark_std::marker::PhantomData;

use super::MockingCircuit;

pub type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;
#[allow(non_snake_case)]
#[derive(Clone)]

pub struct GenTradeCircuit<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>>
where
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    // constant
    pub rc: mimc7::Parameters<C::BaseField>,
    pub G: elgamal::Parameters<C>,

    // statement
    pub cm: Option<C::BaseField>,
    pub fee: Option<C::BaseField>,
    pub pk_buyer: Option<elgamal::PublicKey<C>>,
    pub pk_seller: Option<elgamal::PublicKey<C>>,
    pub CT_ord: Option<Vec<C::BaseField>>,
    pub h_k: Option<C::BaseField>,
    pub G_r: Option<C::Affine>,
    pub c1: Option<C::Affine>,

    // witnesses
    pub r: Option<C::BaseField>,
    pub CT_ord_key: Option<elgamal::Plaintext<C>>,
    pub CT_ord_key_x: Option<symmetric::SymmetricKey<C::BaseField>>,
    pub CT_r: Option<elgamal::Randomness<C>>,

    // directionSelector
    // intermediateHashWires
    pub _curve_var: PhantomData<GG>,
}

#[allow(non_snake_case)]
impl<C, GG> ConstraintSynthesizer<C::BaseField> for GenTradeCircuit<C, GG>
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
        // constants
        let rc = hashes::mimc7::constraints::ParametersVar::new_constant(
            ark_relations::ns!(cs, "round constants"),
            self.rc,
        )?;
        let G = elgamal::constraints::ParametersVar::new_constant(
            ark_relations::ns!(cs, "generator"),
            self.G,
        )?;

        // statement
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
        })
        .unwrap();

        let CT_ord: Vec<FpVar<C::BaseField>> =
            Vec::new_input(ark_relations::ns!(cs, "CT_ord"), || {
                self.CT_ord.ok_or(SynthesisError::AssignmentMissing)
            })?;

        let CT_ord = vec![
            symmetric::constraints::CiphertextVar {
                c: CT_ord[0].clone(),
                r: FpVar::zero(),
            },
            symmetric::constraints::CiphertextVar {
                c: CT_ord[1].clone(),
                r: FpVar::one(),
            },
            symmetric::constraints::CiphertextVar {
                c: CT_ord[2].clone(),
                r: FpVar::one() + FpVar::one(),
            },
            symmetric::constraints::CiphertextVar {
                c: CT_ord[3].clone(),
                r: FpVar::one() + FpVar::one() + FpVar::one(),
            },
            symmetric::constraints::CiphertextVar {
                c: CT_ord[4].clone(),
                r: FpVar::one() + FpVar::one() + FpVar::one() + FpVar::one(),
            },
        ];

        // witness

        let r = FpVar::new_witness(ark_relations::ns!(cs, "r"), || Ok(self.r.unwrap())).unwrap();
        let h_k =
            FpVar::new_witness(ark_relations::ns!(cs, "h_k"), || Ok(self.h_k.unwrap())).unwrap();

        let binding = pk_buyer.clone().pk.to_bits_le()?;
        let pk_buyer_point_x = Boolean::le_bits_to_fp_var(&binding[..binding.len() / 2])?;
        let pk_buyer_point_y = Boolean::le_bits_to_fp_var(&binding[binding.len() / 2..])?;

        let pk_seller = elgamal::constraints::PublicKeyVar::new_witness(
            ark_relations::ns!(cs, "pk_seller"),
            || self.pk_seller.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let CT_ord_key: elgamal::constraints::PlaintextVar<C, GG> =
            elgamal::constraints::PlaintextVar::new_witness(
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

        // relation

        //check fee

        let hash_input = [
            r.clone(),
            fee.clone(),
            h_k.clone(),
            pk_buyer_point_x.clone(),
        ]
        .to_vec();
        let hash_output = MiMCGadget::<C::BaseField>::evaluate(&rc, &hash_input).unwrap();

        // check CT x
        let check_CT_k_point_x = CT_ord_key.plaintext.to_bits_le()?;
        let check_CT_k_point_x =
            Boolean::le_bits_to_fp_var(&check_CT_k_point_x[..check_CT_k_point_x.len() / 2])?;
        check_CT_k_point_x.enforce_equal(&CT_ord_key_x.k)?;

        println!(
            "check_CT_k_point_x: {:?}",
            check_CT_k_point_x.is_eq(&CT_ord_key_x.k)?.value()
        );

        // check c1
        let check_c_1 =
            ElGamalEncGadget::<C, GG>::encrypt(&G.clone(), &CT_ord_key.clone(), &CT_r, &pk_seller)
                .unwrap();

        c1.enforce_equal(&check_c_1)?;
        println!("c1: {:?}", c1.is_eq(&check_c_1)?.value());

        //check SE.Enc
        let Order: Vec<FpVar<C::BaseField>> = vec![
            pk_buyer_point_x.clone(),
            pk_buyer_point_y.clone(),
            r.clone(),
            fee.clone(),
            h_k.clone(),
        ];

        for (i, m) in Order.iter().enumerate() {
            let randomness = symmetric::constraints::RandomnessVar::new_constant(
                ark_relations::ns!(cs, "randomness"),
                symmetric::Randomness {
                    r: C::BaseField::from_bigint((i as u64).into()).unwrap(),
                },
            )?;

            let c = SymmetricEncryptionSchemeGadget::<C::BaseField>::encrypt(
                rc.clone(),
                randomness,
                CT_ord_key_x.clone(),
                symmetric::constraints::PlaintextVar { m: m.clone() },
            )
            .unwrap();

            c.enforce_equal(&CT_ord[i])?;
            println!("c: {:?}", c.is_eq(&CT_ord[i])?.value());
        }

        cm.enforce_equal(&hash_output)?;
        println!("cm: {:?}", cm.is_eq(&hash_output)?.value());

        println!("total constraints num = {:?}", cs.num_constraints());

        Ok(())
    }
}

#[allow(non_snake_case)]
impl<C, GG> MockingCircuit<C, GG> for GenTradeCircuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    type F = C::BaseField;
    type HashParam = mimc7::Parameters<Self::F>;
    type H = mimc7::MiMC<Self::F>;
    type Output = GenTradeCircuit<C, GG>;

    fn generate_circuit<R: ark_std::rand::Rng>(
        round_constants: Self::HashParam,
        rng: &mut R,
    ) -> Result<Self::Output, Error> {
        use crate::gadget::hashes::CRHScheme;
        use crate::gadget::public_encryptions::elgamal::ElGamal;
        use crate::gadget::public_encryptions::AsymmetricEncryptionScheme;
        use crate::gadget::symmetric_encrytions::SymmetricEncryption;

        use ark_ec::AffineRepr;
        use ark_std::One;
        use ark_std::UniformRand;

        let generator = C::generator().into_affine();
        let rc: mimc7::Parameters<<<C as CurveGroup>::Affine as AffineRepr>::BaseField> =
            round_constants;
        let elgamal_param: elgamal::Parameters<C> = elgamal::Parameters {
            generator: generator.clone(),
        };

        let fee: Self::F = Self::F::one();

        // cm check

        let r: Self::F = Self::F::one();
        let h_k: Self::F = Self::F::one();
        let (pk_buyer, _) = ElGamal::keygen(&elgamal_param, rng).unwrap();
        let (pk_seller, _) = ElGamal::keygen(&elgamal_param, rng).unwrap();

        let (pk_buyer_point_x, pk_buyer_point_y) = pk_buyer.xy().unwrap();
        let pk_buyer_point_x = Self::F::from_bigint(pk_buyer_point_x.into_bigint()).unwrap();

        let cm = Self::H::evaluate(
            &rc.clone(),
            [r, fee, h_k, pk_buyer_point_x.clone()].to_vec(),
        )
        .unwrap();

        //CT check

        let CT_ord_key = C::rand(rng).into_affine();
        let CT_ord_key_x = CT_ord_key.x().unwrap();
        let CT_ord_key_x = symmetric::SymmetricKey { k: *CT_ord_key_x };
        let mut CT_ord: Vec<_> = Vec::new();

        let CT_r = C::ScalarField::rand(rng);

        let random: elgamal::Randomness<C> = elgamal::Randomness { 0: CT_r };

        let Order = vec![
            pk_buyer_point_x.clone(),
            pk_buyer_point_y.clone(),
            r.clone(),
            fee.clone(),
            h_k.clone(),
        ];

        let (G_r, c1) = ElGamal::encrypt(&elgamal_param, &pk_seller, &CT_ord_key, &random).unwrap();

        Order.iter().enumerate().for_each(|(i, m)| {
            let random = symmetric::Randomness {
                r: Self::F::from_bigint((i as u64).into()).unwrap(),
            };
            let c = symmetric::SymmetricEncryptionScheme::encrypt(
                rc.clone(),
                random,
                CT_ord_key_x.clone(),
                symmetric::Plaintext { m: m.clone() },
            )
            .unwrap();

            CT_ord.push(c.c);
        });

        Ok(GenTradeCircuit {
            //constant
            rc: rc.clone(),
            G: elgamal_param,
            // statement
            cm: Some(cm),
            fee: Some(fee),
            pk_buyer: Some(pk_buyer),
            pk_seller: Some(pk_seller),
            CT_ord: Some(CT_ord),
            h_k: Some(h_k),
            G_r: Some(G_r),
            c1: Some(c1),
            //witness
            r: Some(r),
            CT_ord_key: Some(CT_ord_key),
            CT_ord_key_x: Some(CT_ord_key_x),
            CT_r: Some(random),

            _curve_var: std::marker::PhantomData,
        })
    }
}
