use crate::gadget::hashes::{self, constraints::CRHSchemeGadget, mimc7::{self, constraints::MiMCGadget}};
use crate::Error;
use core::borrow::Borrow;

use super::{MockingCircuit, DATA_SET};
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, Field, PrimeField};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::{alloc::{AllocVar, AllocationMode}, eq::EqGadget};
use ark_relations::r1cs::{Namespace, OptimizationGoal::Weight, ConstraintSynthesizer, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{marker::PhantomData, UniformRand};
use core::ops::Mul;

#[derive(Clone, Default, Debug, PartialEq, CanonicalDeserialize, CanonicalSerialize)]
pub struct Matrix<F: PrimeField> { pub matrix: Vec<Vec<F>> }
#[derive(Clone, Debug)]
pub struct MatrixVar<F: PrimeField> { pub matrix: Vec<Vec<FpVar<F>>> }

impl<F: PrimeField> AllocVar<Matrix<F>, F> for MatrixVar<F> {
    fn new_variable<T: Borrow<Matrix<F>>>(cs: impl Into<Namespace<F>>, f: impl FnOnce() -> Result<T, SynthesisError>, mode: AllocationMode) -> Result<Self, SynthesisError> {
        let ns = cs.into(); let cs = ns.cs();
        let matrix_value = f()?.borrow().clone();
        let vec = matrix_value.matrix.into_iter().map(|row| Vec::new_variable(cs.clone(), || Ok(row), mode)).collect::<Result<Vec<_>, _>>()?;
        Ok(Self { matrix: vec })
    }
}
impl<F: PrimeField> Matrix<F> {
    pub fn new(matrix: Vec<Vec<F>>) -> Self { Self { matrix } }
}
impl<F: PrimeField> Mul for Matrix<F> {
    type Output = Self;
    fn mul(self, other: Self) -> Self {
        let mut result = Matrix::new(vec![vec![F::ZERO; other.matrix[0].len()]; self.matrix.len()]);
        for i in 0..self.matrix.len() { for j in 0..other.matrix[0].len() { for k in 0..self.matrix[0].len() {
            result.matrix[i][j] += self.matrix[i][k] * other.matrix[k][j];
        }}}
        result
    }
}
impl<F: PrimeField> Mul for MatrixVar<F> {
    type Output = Self;
    fn mul(self, other: Self) -> Self {
        let A = self.matrix; let B = other.matrix;
        let mut result = vec![vec![FpVar::<F>::zero(); B[0].len()]; A.len()];
        for i in 0..A.len() { for j in 0..B[0].len() { for k in 0..A[0].len() {
            result[i][j] += A[i][k].clone() * B[k][j].clone();
        }}}
        MatrixVar { matrix: result }
    }
}

pub type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;

#[allow(non_snake_case)]
#[derive(Clone)]
pub struct RegisterMatPRGCircuit<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>>
where
    C::BaseField: PrimeField + Absorb,
{
    // Constants
    pub rc: mimc7::Parameters<C::BaseField>,

    // Public input
    pub H_k: Option<C::BaseField>,

    // Witnesses — CT first (committed by CP-SNARK)
    pub CT: Option<Vec<C::BaseField>>,
    pub data: Option<Vec<C::BaseField>>,
    pub matrix_A: Option<Matrix<C::BaseField>>,
    pub data_key: Option<Vec<C::BaseField>>,
    pub matrix_R: Option<Matrix<C::BaseField>>,
    pub gamma: Option<Matrix<C::BaseField>>,
    pub sk_seller: Option<C::BaseField>,

    pub _curve_var: PhantomData<GG>,
}

#[allow(non_snake_case)]
impl<C, GG> ConstraintSynthesizer<C::BaseField> for RegisterMatPRGCircuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    C::BaseField: PrimeField + Absorb,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    fn generate_constraints(self, cs: ark_relations::r1cs::ConstraintSystemRef<C::BaseField>) -> Result<(), SynthesisError> {
        cs.set_optimization_goal(Weight);

        // Constants
        let rc = hashes::mimc7::constraints::ParametersVar::new_constant(
            ark_relations::ns!(cs, "round constants"), self.rc,
        )?;

        // Public input
        let h_k = FpVar::new_input(cs.clone(), || self.H_k.ok_or(SynthesisError::AssignmentMissing))?;

        // Witnesses — CT first (committed by CP-SNARK)
        let CT: Vec<FpVar<C::BaseField>> = Vec::new_witness(cs.clone(), || self.CT.ok_or(SynthesisError::AssignmentMissing))?;
        let data: Vec<FpVar<C::BaseField>> = Vec::new_witness(cs.clone(), || self.data.ok_or(SynthesisError::AssignmentMissing))?;
        let matrix_A = MatrixVar::new_witness(cs.clone(), || self.matrix_A.ok_or(SynthesisError::AssignmentMissing))?;
        let mut data_key: Vec<FpVar<C::BaseField>> = Vec::new_witness(cs.clone(), || self.data_key.ok_or(SynthesisError::AssignmentMissing))?;
        let matrix_R = MatrixVar::new_witness(cs.clone(), || self.matrix_R.ok_or(SynthesisError::AssignmentMissing))?;
        let gamma: MatrixVar<C::BaseField> = MatrixVar::new_witness(cs.clone(), || self.gamma.ok_or(SynthesisError::AssignmentMissing))?;
        let sk_seller = FpVar::new_witness(cs.clone(), || self.sk_seller.ok_or(SynthesisError::AssignmentMissing))?;

        // 1. Key expansion: data_key → binary → matrix_K
        let mut data_key_binary: Vec<Boolean<C::BaseField>> = Vec::new();
        for i in 0..DATA_SET.Key_len {
            let bits = data_key[i].to_bits_le()?;
            let mut padded_bits = bits;
            padded_bits.resize(256, Boolean::FALSE);
            data_key_binary.extend_from_slice(&padded_bits);
        }

        let matrix_k_rows: Vec<Vec<FpVar<C::BaseField>>> = (0..DATA_SET.M)
            .map(|i| (0..DATA_SET.K).map(|j| FpVar::from(data_key_binary[i * DATA_SET.K + j].clone())).collect())
            .collect();
        let matrix_K = MatrixVar { matrix: matrix_k_rows };

        // 2. Freivalds: A·K·γ = R·γ
        let K_Gamma = matrix_K.mul(gamma.clone());
        let A_K_Gamma = matrix_A.mul(K_Gamma);
        let R_gamma = matrix_R.clone().mul(gamma);
        for i in 0..DATA_SET.N {
            A_K_Gamma.matrix[i][0].enforce_equal(&R_gamma.matrix[i][0])?;
        }

        // 3. CT = data + R
        for i in 0..DATA_SET.Data_size {
            let ks = if i < DATA_SET.K { matrix_R.matrix[0][i].clone() } else { matrix_R.matrix[i / DATA_SET.K][i % DATA_SET.K].clone() };
            (data[i].clone() + ks).enforce_equal(&CT[i])?;
        }

        // 4. H_k = MiMC(data_key || sk_seller)
        data_key.push(sk_seller);
        let check_h_k = MiMCGadget::<C::BaseField>::evaluate(&rc, &data_key)?;
        h_k.enforce_equal(&check_h_k)?;

        println!("Total Constraints: {}", cs.num_constraints());
        Ok(())
    }
}

#[allow(non_snake_case)]
impl<C, GG> MockingCircuit<C, GG> for RegisterMatPRGCircuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    C::BaseField: PrimeField + Absorb,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    type F = C::BaseField;
    type HashParam = mimc7::Parameters<Self::F>;
    type H = mimc7::MiMC<Self::F>;
    type Output = Self;

    fn generate_circuit<R: ark_std::rand::Rng>(rc: Self::HashParam, rng: &mut R) -> Result<Self, Error> {
        use crate::gadget::hashes::CRHScheme;

        let data: Vec<C::BaseField> = (0..DATA_SET.Data_size).map(|_| C::BaseField::rand(rng)).collect();
        let matrix_A_values: Vec<Vec<C::BaseField>> = (0..DATA_SET.N).map(|_| (0..DATA_SET.M).map(|_| C::BaseField::rand(rng)).collect()).collect();
        let matrix_A = Matrix::new(matrix_A_values);
        let basefield_key: Vec<C::BaseField> = (0..DATA_SET.Key_len).map(|_| C::BaseField::rand(rng)).collect();

        let mut key_bit: Vec<bool> = Vec::new();
        for f in basefield_key.iter() {
            let mut bits = f.into_bigint().to_bits_le();
            bits.resize(256, false);
            key_bit.extend_from_slice(&bits);
        }

        let matrix_K_values: Vec<Vec<C::BaseField>> = (0..DATA_SET.M).map(|i| (0..DATA_SET.K).map(|j| C::BaseField::from(key_bit[i * DATA_SET.K + j])).collect()).collect();
        let matrix_K = Matrix::new(matrix_K_values);
        let matrix_R = matrix_A.clone().mul(matrix_K);

        let CT: Vec<C::BaseField> = data.iter().enumerate().map(|(i, d)| {
            let ks = if i < DATA_SET.K { matrix_R.matrix[0][i] } else { matrix_R.matrix[i / DATA_SET.K][i % DATA_SET.K] };
            *d + ks
        }).collect();

        let sk_seller = C::BaseField::rand(rng);
        let mut key_with_sk = basefield_key.clone();
        key_with_sk.push(sk_seller);
        let h_k = Self::H::evaluate(&rc, key_with_sk)?;

        let gamma_matrix: Vec<Vec<C::BaseField>> = (0..DATA_SET.K).map(|_| vec![C::BaseField::rand(rng)]).collect();
        let gamma = Matrix::new(gamma_matrix);

        Ok(Self {
            rc,
            H_k: Some(h_k),
            CT: Some(CT),
            data: Some(data),
            matrix_A: Some(matrix_A),
            data_key: Some(basefield_key),
            matrix_R: Some(matrix_R),
            gamma: Some(gamma),
            sk_seller: Some(sk_seller),
            _curve_var: PhantomData,
        })
    }
}
