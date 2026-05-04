use crate::gadget::hashes::{
    self,
    constraints::CRHSchemeGadget,
    mimc7::{self, constraints::MiMCGadget},
    CRHScheme,
};
use crate::Error;
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget};
use ark_relations::r1cs::{ConstraintSynthesizer, OptimizationGoal::Weight, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{marker::PhantomData, UniformRand};
use std::ops::Mul;

use super::{MockingCircuit, DATA_SET};

#[derive(Clone, Default, Debug, PartialEq, ark_serialize::CanonicalDeserialize, ark_serialize::CanonicalSerialize)]
pub struct Matrix<F: PrimeField> {
    pub matrix: Vec<Vec<F>>,
}

#[derive(Clone, Debug)]
pub struct MatrixVar<F: PrimeField> {
    pub matrix: Vec<Vec<FpVar<F>>>,
}

pub type ConstraintF<C> = <<C as CurveGroup>::BaseField as ark_ff::Field>::BasePrimeField;

impl<F: PrimeField> AllocVar<Matrix<F>, F> for MatrixVar<F> {
    fn new_variable<T: std::borrow::Borrow<Matrix<F>>>(
        cs: impl Into<ark_relations::r1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::alloc::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let matrix_value = f()?.borrow().clone();
        let vec = matrix_value
            .matrix
            .into_iter()
            .map(|row| Vec::new_variable(cs.clone(), || Ok(row), mode))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { matrix: vec })
    }
}

impl<F: PrimeField> Matrix<F> {
    pub fn new(matrix: Vec<Vec<F>>) -> Self {
        Self { matrix }
    }
}

impl<F: PrimeField> Mul for Matrix<F> {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        let mut result = Matrix::new(vec![vec![F::ZERO; other.matrix[0].len()]; self.matrix.len()]);
        for i in 0..self.matrix.len() {
            for j in 0..other.matrix[0].len() {
                for k in 0..self.matrix[0].len() {
                    result.matrix[i][j] += self.matrix[i][k] * other.matrix[k][j];
                }
            }
        }
        result
    }
}

impl<F: PrimeField> Mul for MatrixVar<F> {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        let a = self.matrix;
        let b = other.matrix;
        let mut result = vec![vec![FpVar::<F>::zero(); b[0].len()]; a.len()];
        for i in 0..a.len() {
            for j in 0..b[0].len() {
                for k in 0..a[0].len() {
                    result[i][j] += a[i][k].clone() * b[k][j].clone();
                }
            }
        }
        MatrixVar { matrix: result }
    }
}

#[derive(Clone)]
struct RegisterSeededMatPRGWitness<F: PrimeField> {
    h_k: F,
    ct: Vec<F>,
    data: Vec<F>,
    matrix_A1: Matrix<F>,
    matrix_A2: Matrix<F>,
    seed_bits: Vec<bool>,
    matrix_R: Matrix<F>,
    gamma: Matrix<F>,
    sk_seller: F,
}

#[allow(non_snake_case)]
#[derive(Clone)]
pub struct RegisterSeededMatPRGCircuit<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>>
where
    C::BaseField: PrimeField + Absorb,
{
    pub rc: mimc7::Parameters<C::BaseField>,
    pub H_k: Option<C::BaseField>,
    pub CT: Option<Vec<C::BaseField>>,
    pub data: Option<Vec<C::BaseField>>,
    pub matrix_A1: Option<Matrix<C::BaseField>>,
    pub matrix_A2: Option<Matrix<C::BaseField>>,
    pub seed_bits: Option<Vec<bool>>,
    pub matrix_R: Option<Matrix<C::BaseField>>,
    pub gamma: Option<Matrix<C::BaseField>>,
    pub sk_seller: Option<C::BaseField>,
    pub _curve_var: PhantomData<GG>,
}

const HASH_PACK_BITS: usize = 248;

fn pack_bool_slice<F: PrimeField>(bits: &[bool]) -> F {
    let mut acc = F::zero();
    let mut coeff = F::one();
    for &bit in bits {
        if bit {
            acc += coeff;
        }
        coeff = coeff.double();
    }
    acc
}

fn pack_boolean_slice<F: PrimeField>(bits: &[Boolean<F>]) -> FpVar<F> {
    let mut acc = FpVar::zero();
    let mut coeff = F::one();
    for bit in bits {
        acc += FpVar::from(bit.clone()) * coeff;
        coeff = coeff.double();
    }
    acc
}

fn row_major_matrix_from_bits<F: PrimeField>(
    bits: &[Boolean<F>],
    m: usize,
    k: usize,
) -> MatrixVar<F> {
    let matrix = (0..m)
        .map(|i| {
            (0..k)
                .map(|j| FpVar::from(bits[i * k + j].clone()))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    MatrixVar { matrix }
}

fn mul_matrix_vector_prefix_rows<F: PrimeField>(
    matrix_a: &MatrixVar<F>,
    state: &[Boolean<F>],
    rows: usize,
) -> Vec<FpVar<F>> {
    (0..rows)
        .map(|i| {
            let mut acc = FpVar::<F>::zero();
            for (a_ij, bit_j) in matrix_a.matrix[i].iter().zip(state.iter()) {
                acc += a_ij.clone() * FpVar::from(bit_j.clone());
            }
            acc
        })
        .collect()
}

fn low_bits_from_field_vector<F: PrimeField>(
    y: &Matrix<F>,
    low_bits: usize,
    total_bits_needed: usize,
) -> Vec<bool> {
    let expansion_chunk_bits = F::MODULUS_BIT_SIZE as usize;
    let mut out = Vec::with_capacity(total_bits_needed);
    for row in &y.matrix {
        let mut bits = row[0].into_bigint().to_bits_le();
        bits.resize(expansion_chunk_bits, false);
        out.extend(bits.into_iter().take(low_bits));
        if out.len() >= total_bits_needed {
            break;
        }
    }
    out.truncate(total_bits_needed);
    out
}

fn sample_register_seeded_matprg_witness<C, R>(
    rc: &mimc7::Parameters<C::BaseField>,
    rng: &mut R,
) -> Result<RegisterSeededMatPRGWitness<C::BaseField>, Error>
where
    C: CurveGroup,
    C::BaseField: PrimeField + Absorb,
    R: ark_std::rand::Rng,
{
    let n = DATA_SET.N;
    let n1 = DATA_SET.N1;
    let m1 = DATA_SET.M1;
    let m2 = DATA_SET.M2;
    let k_cols = DATA_SET.K;
    let low_bits = DATA_SET.Low_bits;
    let total_bits_needed = m2 * k_cols;
    if n1 * low_bits < total_bits_needed {
        return Err(format!(
            "low-bit truncation output is too small: have {} bits, need {total_bits_needed}",
            n1 * low_bits
        )
        .into());
    }

    let data: Vec<C::BaseField> = (0..DATA_SET.Data_size)
        .map(|_| C::BaseField::rand(rng))
        .collect();
    let matrix_A1_values: Vec<Vec<C::BaseField>> = (0..n1)
        .map(|_| (0..m1).map(|_| C::BaseField::rand(rng)).collect())
        .collect();
    let matrix_A1 = Matrix::new(matrix_A1_values);
    let matrix_A2_values: Vec<Vec<C::BaseField>> = (0..n)
        .map(|_| (0..m2).map(|_| C::BaseField::rand(rng)).collect())
        .collect();
    let matrix_A2 = Matrix::new(matrix_A2_values);

    let seed_bits: Vec<bool> = (0..m1).map(|_| bool::rand(rng)).collect();
    let seed_matrix = Matrix::new(
        seed_bits
            .iter()
            .map(|&bit| vec![C::BaseField::from(bit as u64)])
            .collect::<Vec<_>>(),
    );
    let y = matrix_A1.clone().mul(seed_matrix);
    let extracted_key_bits = low_bits_from_field_vector(&y, low_bits, total_bits_needed);

    let matrix_k_values = (0..m2)
        .map(|i| {
            (0..k_cols)
                .map(|j| C::BaseField::from(extracted_key_bits[i * k_cols + j] as u64))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let matrix_K = Matrix::new(matrix_k_values);
    let matrix_R = matrix_A2.clone().mul(matrix_K);

    let ct: Vec<C::BaseField> = data
        .iter()
        .enumerate()
        .map(|(i, d)| {
            let r = if i < k_cols {
                matrix_R.matrix[0][i]
            } else {
                matrix_R.matrix[i / k_cols][i % k_cols]
            };
            *d + r
        })
        .collect();

    let sk_seller = C::BaseField::rand(rng);
    let mut hash_input: Vec<C::BaseField> = seed_bits
        .chunks(HASH_PACK_BITS)
        .map(pack_bool_slice::<C::BaseField>)
        .collect();
    hash_input.push(sk_seller);
    let h_k = mimc7::MiMC::<C::BaseField>::evaluate(rc, hash_input)?;

    let gamma_matrix: Vec<Vec<C::BaseField>> =
        (0..k_cols).map(|_| vec![C::BaseField::rand(rng)]).collect();
    let gamma = Matrix::new(gamma_matrix);

    Ok(RegisterSeededMatPRGWitness {
        h_k,
        ct,
        data,
        matrix_A1,
        matrix_A2,
        seed_bits,
        matrix_R,
        gamma,
        sk_seller,
    })
}

#[allow(non_snake_case)]
impl<C, GG> ConstraintSynthesizer<C::BaseField> for RegisterSeededMatPRGCircuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    C::BaseField: PrimeField + Absorb,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<C::BaseField>,
    ) -> Result<(), SynthesisError> {
        cs.set_optimization_goal(Weight);

        let rc = hashes::mimc7::constraints::ParametersVar::new_constant(
            ark_relations::ns!(cs, "round constants"),
            self.rc,
        )?;
        let h_k = FpVar::new_input(cs.clone(), || {
            self.H_k.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let CT: Vec<FpVar<C::BaseField>> = Vec::new_witness(cs.clone(), || {
            self.CT.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let data: Vec<FpVar<C::BaseField>> = Vec::new_witness(cs.clone(), || {
            self.data.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let seed_bits_native = self.seed_bits.clone();
        let matrix_A1 = MatrixVar::new_witness(cs.clone(), || {
            self.matrix_A1.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let matrix_A2 = MatrixVar::new_witness(cs.clone(), || {
            self.matrix_A2.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let matrix_R = MatrixVar::new_witness(cs.clone(), || {
            self.matrix_R.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let gamma: MatrixVar<C::BaseField> = MatrixVar::new_witness(cs.clone(), || {
            self.gamma.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let sk_seller = FpVar::new_witness(cs.clone(), || {
            self.sk_seller.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let n = DATA_SET.N;
        let n1 = DATA_SET.N1;
        let m2 = DATA_SET.M2;
        let k_cols = DATA_SET.K;
        let low_bits = DATA_SET.Low_bits;
        let total_bits_needed = m2 * k_cols;
        if n1 * low_bits < total_bits_needed {
            return Err(SynthesisError::Unsatisfiable);
        }

        let seed_bits: Vec<Boolean<C::BaseField>> = Vec::new_witness(cs.clone(), || {
            seed_bits_native
                .clone()
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let n0 = cs.num_constraints();
        let y = mul_matrix_vector_prefix_rows(&matrix_A1, &seed_bits, n1);
        let mut matrix_k_bits: Vec<Boolean<C::BaseField>> = Vec::with_capacity(total_bits_needed);
        for y_row in y {
            let bits = y_row.to_bits_le()?;
            for bit in bits.into_iter().take(low_bits) {
                if matrix_k_bits.len() == total_bits_needed {
                    break;
                }
                matrix_k_bits.push(bit);
            }
            if matrix_k_bits.len() == total_bits_needed {
                break;
            }
        }
        let matrix_K = row_major_matrix_from_bits(&matrix_k_bits, m2, k_cols);
        let n_truncation = cs.num_constraints() - n0;

        let n1_start = cs.num_constraints();
        let k_gamma = matrix_K.mul(gamma.clone());
        let a_k_gamma = matrix_A2.mul(k_gamma);
        let r_gamma = matrix_R.clone().mul(gamma);
        for i in 0..n {
            a_k_gamma.matrix[i][0].enforce_equal(&r_gamma.matrix[i][0])?;
        }
        let n_freivalds = cs.num_constraints() - n1_start;

        let n2 = cs.num_constraints();
        for i in 0..DATA_SET.Data_size {
            let r = if i < k_cols {
                matrix_R.matrix[0][i].clone()
            } else {
                matrix_R.matrix[i / k_cols][i % k_cols].clone()
            };
            (data[i].clone() + r).enforce_equal(&CT[i])?;
        }
        let n_enc = cs.num_constraints() - n2;

        let n3 = cs.num_constraints();
        let mut hash_input: Vec<FpVar<C::BaseField>> = seed_bits
            .chunks(HASH_PACK_BITS)
            .map(pack_boolean_slice::<C::BaseField>)
            .collect();
        hash_input.push(sk_seller);
        let check_h_k = MiMCGadget::<C::BaseField>::evaluate(&rc, &hash_input)?;
        h_k.enforce_equal(&check_h_k)?;
        let n_mimc = cs.num_constraints() - n3;

        println!("Total Constraints: {}", cs.num_constraints());
        println!("  Low-bit truncation : {n_truncation}");
        println!("  Freivalds (AKγ)   : {n_freivalds}");
        println!("  Encryption (CT)   : {n_enc}");
        println!("  MiMC hash         : {n_mimc}");
        println!("  Low bits per elem : {low_bits}");
        Ok(())
    }
}

#[allow(non_snake_case)]
impl<C, GG> MockingCircuit<C, GG> for RegisterSeededMatPRGCircuit<C, GG>
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

    fn generate_circuit<R: ark_std::rand::Rng>(
        rc: Self::HashParam,
        rng: &mut R,
    ) -> Result<Self, Error> {
        let witness = sample_register_seeded_matprg_witness::<C, _>(&rc, rng)?;

        Ok(Self {
            rc,
            H_k: Some(witness.h_k),
            CT: Some(witness.ct),
            data: Some(witness.data),
            matrix_A1: Some(witness.matrix_A1),
            matrix_A2: Some(witness.matrix_A2),
            seed_bits: Some(witness.seed_bits),
            matrix_R: Some(witness.matrix_R),
            gamma: Some(witness.gamma),
            sk_seller: Some(witness.sk_seller),
            _curve_var: PhantomData,
        })
    }
}
