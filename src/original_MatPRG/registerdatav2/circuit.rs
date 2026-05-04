use crate::gadget::hashes;
use crate::gadget::hashes::constraints::CRHSchemeGadget;
use crate::gadget::hashes::mimc7;
use crate::gadget::hashes::mimc7::constraints::MiMCGadget;
use crate::Error;

use crate::gadget::symmetric_encrytions::constraints::SymmetricEncryptionGadget;
use crate::gadget::symmetric_encrytions::symmetric;
use crate::gadget::symmetric_encrytions::symmetric::constraints::SymmetricEncryptionSchemeGadget;

use super::{MockingCircuit, DATA_SET};
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::AffineRepr;
use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::{fields::fp::FpVar, prelude::AllocVar};
use ark_relations::r1cs::OptimizationGoal::Weight;
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
use ark_std::marker::PhantomData;
// use rand::distributions::weighted::alias_method::Weight;

pub type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;
#[allow(non_snake_case)]
#[derive(Clone)]

pub struct Registerdatav2Circuit<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>>
where
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    // constant
    pub rc: mimc7::Parameters<C::BaseField>,

    // statement
    // pub h_ct: Option<C::BaseField>,
    pub h_k: Option<C::BaseField>,
    pub ENA_writer: Option<C::BaseField>,

    // witnesses
    pub data: Option<Vec<C::BaseField>>,
    pub CT_r: Option<Vec<C::BaseField>>,
    pub CT_c: Option<Vec<C::BaseField>>,
    pub k_data: Option<symmetric::SymmetricKey<C::BaseField>>,

    // directionSelector
    // intermediateHashWires
    pub _curve_var: PhantomData<GG>,
}

#[allow(non_snake_case)]
impl<C, GG> ConstraintSynthesizer<C::BaseField> for Registerdatav2Circuit<C, GG>
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
        // cs.set_optimization_goal(Weight);
        // constants
        let rc = hashes::mimc7::constraints::ParametersVar::new_constant(
            ark_relations::ns!(cs, "round constants"),
            self.rc,
        )?;

        // statement
        // let h_ct = FpVar::new_input(cs.clone(), || {
        //     self.h_ct.ok_or(SynthesisError::AssignmentMissing)
        // })?;
        let h_k = FpVar::new_input(cs.clone(), || {
            self.h_k.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let ENA_writer = FpVar::new_input(cs.clone(), || {
            self.ENA_writer.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // witness
        let data: Vec<FpVar<C::BaseField>> =
            Vec::new_witness(ark_relations::ns!(cs, "data"), || {
                self.data.ok_or(SynthesisError::AssignmentMissing)
            })?;

        let CT_r: Vec<FpVar<C::BaseField>> =
            Vec::new_witness(ark_relations::ns!(cs, "CT_r"), || {
                self.CT_r.ok_or(SynthesisError::AssignmentMissing)
            })?;

        let CT_c: Vec<FpVar<C::BaseField>> =
            Vec::new_witness(ark_relations::ns!(cs, "CT_c"), || {
                self.CT_c.ok_or(SynthesisError::AssignmentMissing)
            })?;

        let mut CT = Vec::new();
        for i in 0..CT_r.len() {
            CT.push(symmetric::constraints::CiphertextVar {
                r: CT_r[i].clone(),
                c: CT_c[i].clone(),
            })
        }

        let k_data = symmetric::constraints::SymmetricKeyVar::new_witness(
            ark_relations::ns!(cs, "k_data"),
            || self.k_data.ok_or(SynthesisError::AssignmentMissing),
        )?;

        // ㄴ

        // check h_k = Hash(ENA_writer || k_data )

        let h_k_input = [ENA_writer.clone(), k_data.k.clone()].to_vec();
        let check_h_k = MiMCGadget::<C::BaseField>::evaluate(&rc, &h_k_input).unwrap();
        h_k.enforce_equal(&check_h_k)?;

        // check h_ct = Hash(CT_data)

        // let check_h_ct = MiMCGadget::<C::BaseField>::evaluate(&rc, &CT_c).unwrap();
        // h_ct.enforce_equal(&check_h_ct)?;

        // check CT_data = SE.Enc(k_data,data);
        for i in 1..CT.len() {
            let random = symmetric::constraints::RandomnessVar { r: CT[i].r.clone() };
            let CT_i = SymmetricEncryptionSchemeGadget::<C::BaseField>::encrypt(
                rc.clone(),
                random,
                k_data.clone(),
                symmetric::constraints::PlaintextVar { m: data[i].clone() },
            )
                .unwrap();
            CT_r[i].enforce_equal(&CT_i.r)?;
            CT_c[i].enforce_equal(&CT_i.c)?;
        }
        println!("Total Constraints num = {:?}", cs.num_constraints());

        Ok(())
    }
}

#[allow(non_snake_case)]
impl<C, GG> MockingCircuit<C, GG> for Registerdatav2Circuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    type F = C::BaseField;
    type HashParam = mimc7::Parameters<Self::F>;
    type H = mimc7::MiMC<Self::F>;
    type Output = Registerdatav2Circuit<C, GG>;

    fn generate_circuit<R: ark_std::rand::Rng>(
        round_constants: Self::HashParam,
        rng: &mut R,
    ) -> Result<Self::Output, Error> {
        use crate::gadget::hashes::CRHScheme;
        use crate::gadget::symmetric_encrytions::SymmetricEncryption;

        use ark_std::One;
        use ark_std::UniformRand;

        let rc: mimc7::Parameters<<<C as CurveGroup>::Affine as AffineRepr>::BaseField> =
            round_constants;

        let ENA_writer: Self::F = Self::F::one();
        let sk = Self::F::rand(rng);
        let k_data: symmetric::SymmetricKey<<<C as CurveGroup>::Affine as AffineRepr>::BaseField> =
            symmetric::SymmetricKey { k: sk };

        let data_size = DATA_SET.Data_size;

        let mut data = Vec::new();
        let mut CT_r = Vec::new();
        let mut CT_c: Vec<Self::F> = Vec::new();

        for i in 0..data_size {
            let i_data = Self::F::rand(rng);
            let cin_r = Self::F::rand(rng);
            let random = symmetric::Randomness { r: cin_r };
            data.push(i_data);
            let i_CT = symmetric::SymmetricEncryptionScheme::encrypt(
                rc.clone(),
                random.clone(),
                k_data.clone(),
                symmetric::Plaintext { m: i_data },
            )
                .unwrap();
            CT_r.push(i_CT.r);
            CT_c.push(i_CT.c);
        }

        let h_k = Self::H::evaluate(&rc.clone(), [ENA_writer, sk].to_vec()).unwrap();
        // let h_ct = Self::H::evaluate(&rc.clone(), CT_c.clone()).unwrap();

        Ok(Registerdatav2Circuit {
            //constant
            rc: rc.clone(),
            // statement
            // h_ct: Some(h_ct),
            h_k: Some(h_k),
            ENA_writer: Some(ENA_writer),

            //witness
            data: Some(data),
            CT_r: Some(CT_r),
            CT_c: Some(CT_c),
            k_data: Some(k_data),

            _curve_var: std::marker::PhantomData,
        })
    }
}
