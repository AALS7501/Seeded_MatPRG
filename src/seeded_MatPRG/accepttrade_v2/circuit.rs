use crate::Error;
use crate::gadget::hashes;
use crate::gadget::hashes::constraints::CRHSchemeGadget;
use crate::gadget::hashes::mimc7;
use crate::gadget::hashes::mimc7::constraints::MiMCGadget;
use crate::gadget::merkle_tree;
use crate::gadget::merkle_tree::mocking::MockingMerkleTree;
use crate::gadget::merkle_tree::{Config, IdentityDigestConverter, constraints::ConfigGadget};
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
use ark_r1cs_std::bits::boolean::Boolean;
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::{fields::fp::FpVar, prelude::AllocVar};
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
use ark_std::marker::PhantomData;
use ark_std::One;

use super::MockingCircuit;

pub type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;

pub struct FieldMTConfig<F: PrimeField> {
    _field: PhantomData<F>,
}
impl<F: PrimeField + Absorb> Config for FieldMTConfig<F> {
    type Leaf = [F];
    type LeafDigest = F;
    type LeafInnerDigestConverter = IdentityDigestConverter<F>;
    type InnerDigest = F;
    type LeafHash = mimc7::MiMC<F>;
    type TwoToOneHash = mimc7::TwoToOneMiMC<F>;
}

pub struct FieldMTConfigVar<F: PrimeField> {
    _field: PhantomData<F>,
}
impl<F> ConfigGadget<FieldMTConfig<F>, F> for FieldMTConfigVar<F>
where
    F: PrimeField + Absorb,
{
    type Leaf = [FpVar<F>];
    type LeafDigest = FpVar<F>;
    type LeafInnerConverter = IdentityDigestConverter<FpVar<F>>;
    type InnerDigest = FpVar<F>;
    type LeafHash = mimc7::constraints::MiMCGadget<F>;
    type TwoToOneHash = mimc7::constraints::TwoToOneMiMCGadget<F>;
}

#[allow(non_snake_case)]
#[derive(Clone)]
pub struct AcceptTradeV2Circuit<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>>
where
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    pub rc: mimc7::Parameters<C::BaseField>,
    pub G: elgamal::Parameters<C>,

    pub rt: Option<C::BaseField>,
    pub nf: Option<C::BaseField>,
    pub cmAzeroth: Option<C::BaseField>,
    pub hk: Option<C::BaseField>,
    pub addrseller: Option<C::BaseField>,
    pub pkseller: Option<elgamal::PublicKey<C>>,
    pub rel_G_r: Option<C::Affine>,
    pub rel_c1: Option<C::Affine>,
    pub CT_k: Option<Vec<C::BaseField>>,

    pub cm: Option<C::BaseField>,
    pub leaf_pos: Option<u32>,
    pub tree_proof: Option<merkle_tree::Path<FieldMTConfig<C::BaseField>>>,
    pub skseller: Option<C::BaseField>,
    pub pkbuyer: Option<elgamal::PublicKey<C>>,
    pub r: Option<C::BaseField>,
    pub fee: Option<C::BaseField>,
    pub oazeroth: Option<C::BaseField>,
    pub rel_key_plaintext: Option<elgamal::Plaintext<C>>,
    pub rel_key_x: Option<symmetric::SymmetricKey<C::BaseField>>,
    pub rel_key_r: Option<elgamal::Randomness<C>>,
    pub released_payload: Option<Vec<C::BaseField>>,
    pub tk_addr: Option<C::BaseField>,
    pub tk_id: Option<C::BaseField>,

    pub _curve_var: PhantomData<GG>,
}

impl<C, GG> AcceptTradeV2Circuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    pub fn generate_circuit_with_payload<R: ark_std::rand::Rng>(
        round_constants: mimc7::Parameters<C::BaseField>,
        tree_height: u64,
        released_payload: Vec<C::BaseField>,
        rng: &mut R,
    ) -> Result<Self, Error> {
        use crate::gadget::hashes::CRHScheme;
        use crate::gadget::public_encryptions::elgamal::ElGamal;
        use ark_std::{One, UniformRand};

        let generator = C::generator().into_affine();
        let elgamal_param = elgamal::Parameters { generator };
        let rc = round_constants;

        let (pkseller, _seller_dec_sk): (elgamal::PublicKey<C>, elgamal::SecretKey<C>) =
            ElGamal::keygen(&elgamal_param, rng)?;
        let (pkbuyer, _): (elgamal::PublicKey<C>, elgamal::SecretKey<C>) =
            ElGamal::keygen(&elgamal_param, rng)?;

        let skseller = C::BaseField::rand(rng);
        let r = C::BaseField::one();
        let fee = C::BaseField::one();
        let addrseller = C::BaseField::one();
        let tk_addr = C::BaseField::one();
        let tk_id = C::BaseField::one();
        let oazeroth = C::BaseField::rand(rng);

        let (pkbuyer_x_aff, pkbuyer_y_aff) = pkbuyer.xy().unwrap();
        let pkbuyer_x = C::BaseField::from_bigint(pkbuyer_x_aff.into_bigint()).unwrap();
        let pkbuyer_y = C::BaseField::from_bigint(pkbuyer_y_aff.into_bigint()).unwrap();
        let (pkseller_x_aff, _) = pkseller.xy().unwrap();
        let pkseller_x = C::BaseField::from_bigint(pkseller_x_aff.into_bigint()).unwrap();

        let hk = mimc7::MiMC::<C::BaseField>::evaluate(&rc, vec![skseller, released_payload[0]])?;
        let cm = mimc7::MiMC::<C::BaseField>::evaluate(
            &rc,
            vec![pkseller_x, r, fee, hk, pkbuyer_x],
        )?;
        let nf = mimc7::MiMC::<C::BaseField>::evaluate(&rc, vec![skseller, cm])?;
        let cmAzeroth = mimc7::MiMC::<C::BaseField>::evaluate(
            &rc,
            vec![oazeroth, tk_addr, tk_id, fee, addrseller],
        )?;

        let rel_key_plaintext = C::rand(rng).into_affine();
        let rel_key_x = symmetric::SymmetricKey {
            k: C::BaseField::from_bigint(rel_key_plaintext.x().unwrap().into_bigint()).unwrap(),
        };
        let rel_key_r = elgamal::Randomness(C::ScalarField::rand(rng));
        let (rel_G_r, rel_c1) =
            ElGamal::encrypt(&elgamal_param, &pkbuyer, &rel_key_plaintext, &rel_key_r)?;

        let mut CT_k = Vec::with_capacity(released_payload.len());
        for (i, m) in released_payload.iter().enumerate() {
            let c = symmetric::SymmetricEncryptionScheme::encrypt(
                rc.clone(),
                symmetric::Randomness {
                    r: C::BaseField::from(i as u64),
                },
                rel_key_x.clone(),
                symmetric::Plaintext { m: *m },
            )?;
            CT_k.push(c.c);
        }

        let leaf_crh_params = rc.clone();
        let two_to_one_params = leaf_crh_params.clone();
        let proof: merkle_tree::Path<FieldMTConfig<C::BaseField>> =
            merkle_tree::mocking::get_mocking_merkle_tree(tree_height);
        let rt = proof
            .get_test_root(&leaf_crh_params, &two_to_one_params, [cm])
            .unwrap();

        Ok(Self {
            rc,
            G: elgamal_param,
            rt: Some(rt),
            nf: Some(nf),
            cmAzeroth: Some(cmAzeroth),
            hk: Some(hk),
            addrseller: Some(addrseller),
            pkseller: Some(pkseller),
            rel_G_r: Some(rel_G_r),
            rel_c1: Some(rel_c1),
            CT_k: Some(CT_k),
            cm: Some(cm),
            leaf_pos: Some(0),
            tree_proof: Some(proof),
            skseller: Some(skseller),
            pkbuyer: Some(pkbuyer),
            r: Some(r),
            fee: Some(fee),
            oazeroth: Some(oazeroth),
            rel_key_plaintext: Some(rel_key_plaintext),
            rel_key_x: Some(rel_key_x),
            rel_key_r: Some(rel_key_r),
            released_payload: Some(released_payload),
            tk_addr: Some(tk_addr),
            tk_id: Some(tk_id),
            _curve_var: PhantomData,
        })
    }
}

#[allow(non_snake_case)]
impl<C, GG> ConstraintSynthesizer<C::BaseField> for AcceptTradeV2Circuit<C, GG>
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

        let rt = FpVar::new_input(cs.clone(), || self.rt.ok_or(SynthesisError::AssignmentMissing))?;
        let nf = FpVar::new_input(cs.clone(), || self.nf.ok_or(SynthesisError::AssignmentMissing))?;
        let cmAzeroth = FpVar::new_input(cs.clone(), || {
            self.cmAzeroth.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let hk = FpVar::new_input(cs.clone(), || self.hk.ok_or(SynthesisError::AssignmentMissing))?;
        let addrseller = FpVar::new_input(cs.clone(), || {
            self.addrseller.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let pkseller = elgamal::constraints::PublicKeyVar::new_input(
            ark_relations::ns!(cs, "pkseller"),
            || self.pkseller.ok_or(SynthesisError::AssignmentMissing),
        )?;
        let rel_cipher = elgamal::constraints::OutputVar::new_input(
            ark_relations::ns!(cs, "rel_cipher"),
            || Ok((self.rel_G_r.unwrap(), self.rel_c1.unwrap())),
        )?;
        let CT_k_raw: Vec<FpVar<C::BaseField>> =
            Vec::new_input(ark_relations::ns!(cs, "CT_k"), || {
                self.CT_k.ok_or(SynthesisError::AssignmentMissing)
            })?;

        let cm = FpVar::new_witness(ark_relations::ns!(cs, "cm"), || Ok(self.cm.unwrap()))?;
        let leaf_pos = UInt32::new_witness(ark_relations::ns!(cs, "leaf_pos"), || {
            self.leaf_pos.ok_or(SynthesisError::AssignmentMissing)
        })?
        .to_bits_le();
        let mut tree_proof = merkle_tree::constraints::PathVar::<
            FieldMTConfig<C::BaseField>,
            C::BaseField,
            FieldMTConfigVar<C::BaseField>,
        >::new_witness(ark_relations::ns!(cs, "path"), || {
            self.tree_proof.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let skseller = FpVar::new_witness(ark_relations::ns!(cs, "skseller"), || {
            Ok(self.skseller.unwrap())
        })?;
        let pkbuyer = elgamal::constraints::PublicKeyVar::new_witness(
            ark_relations::ns!(cs, "pkbuyer"),
            || self.pkbuyer.ok_or(SynthesisError::AssignmentMissing),
        )?;
        let r = FpVar::new_witness(ark_relations::ns!(cs, "r"), || Ok(self.r.unwrap()))?;
        let fee = FpVar::new_witness(ark_relations::ns!(cs, "fee"), || Ok(self.fee.unwrap()))?;
        let oazeroth =
            FpVar::new_witness(ark_relations::ns!(cs, "oazeroth"), || Ok(self.oazeroth.unwrap()))?;
        let rel_key_plaintext = elgamal::constraints::PlaintextVar::new_witness(
            ark_relations::ns!(cs, "rel_key_plaintext"),
            || self.rel_key_plaintext.ok_or(SynthesisError::AssignmentMissing),
        )?;
        let rel_key_x = symmetric::constraints::SymmetricKeyVar::new_witness(
            ark_relations::ns!(cs, "rel_key_x"),
            || self.rel_key_x.ok_or(SynthesisError::AssignmentMissing),
        )?;
        let rel_key_r = elgamal::constraints::RandomnessVar::new_witness(
            ark_relations::ns!(cs, "rel_key_r"),
            || self.rel_key_r.ok_or(SynthesisError::AssignmentMissing),
        )?;
        let released_payload: Vec<FpVar<C::BaseField>> =
            Vec::new_witness(ark_relations::ns!(cs, "released_payload"), || {
                self.released_payload.ok_or(SynthesisError::AssignmentMissing)
            })?;
        let tk_addr =
            FpVar::new_witness(ark_relations::ns!(cs, "tk_addr"), || Ok(self.tk_addr.unwrap()))?;
        let tk_id =
            FpVar::new_witness(ark_relations::ns!(cs, "tk_id"), || Ok(self.tk_id.unwrap()))?;

        let CT_k: Vec<_> = CT_k_raw
            .iter()
            .enumerate()
            .map(|(i, c)| symmetric::constraints::CiphertextVar {
                c: c.clone(),
                r: FpVar::Constant(C::BaseField::from(i as u64)),
            })
            .collect();

        let buyer_bits = pkbuyer.pk.to_bits_le()?;
        let pkbuyer_x = Boolean::le_bits_to_fp_var(&buyer_bits[..buyer_bits.len() / 2])?;

        let rel_key_bits = rel_key_plaintext.plaintext.to_bits_le()?;
        let rel_key_x_check = Boolean::le_bits_to_fp_var(&rel_key_bits[..rel_key_bits.len() / 2])?;
        rel_key_x_check.enforce_equal(&rel_key_x.k)?;

        let expected_release_ct =
            ElGamalEncGadget::<C, GG>::encrypt(&G, &rel_key_plaintext, &rel_key_r, &pkbuyer)?;
        rel_cipher.enforce_equal(&expected_release_ct)?;

        for (i, m) in released_payload.iter().enumerate() {
            let randomness = symmetric::constraints::RandomnessVar::new_constant(
                ark_relations::ns!(cs, "rel_rand"),
                symmetric::Randomness {
                    r: C::BaseField::from(i as u64),
                },
            )?;
            let c = SymmetricEncryptionSchemeGadget::<C::BaseField>::encrypt(
                rc.clone(),
                randomness,
                rel_key_x.clone(),
                symmetric::constraints::PlaintextVar { m: m.clone() },
            )
            .map_err(|_| SynthesisError::Unsatisfiable)?;
            c.enforce_equal(&CT_k[i])?;
        }

        let seller_bits = pkseller.pk.to_bits_le()?;
        let pkseller_x = Boolean::le_bits_to_fp_var(&seller_bits[..seller_bits.len() / 2])?;
        let expected_cm = MiMCGadget::<C::BaseField>::evaluate(
            &rc,
            &vec![pkseller_x, r.clone(), fee.clone(), hk.clone(), pkbuyer_x],
        )?;
        expected_cm.enforce_equal(&cm)?;

        let expected_hk = MiMCGadget::<C::BaseField>::evaluate(
            &rc,
            &vec![skseller.clone(), released_payload[0].clone()],
        )?;
        expected_hk.enforce_equal(&hk)?;

        let expected_cm_az = MiMCGadget::<C::BaseField>::evaluate(
            &rc,
            &vec![oazeroth, tk_addr, tk_id, fee.clone(), addrseller],
        )?;
        expected_cm_az.enforce_equal(&cmAzeroth)?;

        tree_proof.set_leaf_position(leaf_pos);
        let path_ok = tree_proof.verify_membership(&rc.clone(), &rc.clone(), &rt, &[cm.clone()])?;
        path_ok.enforce_equal(&Boolean::TRUE)?;

        let expected_nf = MiMCGadget::<C::BaseField>::evaluate(&rc, &vec![skseller, cm])?;
        expected_nf.enforce_equal(&nf)?;

        Ok(())
    }
}

#[allow(non_snake_case)]
impl<C, GG> MockingCircuit<C, GG> for AcceptTradeV2Circuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    type F = C::BaseField;
    type HashParam = mimc7::Parameters<Self::F>;
    type H = mimc7::MiMC<Self::F>;
    type Output = AcceptTradeV2Circuit<C, GG>;

    fn generate_circuit<R: ark_std::rand::Rng>(
        round_constants: Self::HashParam,
        tree_height: u64,
        rng: &mut R,
    ) -> Result<Self::Output, Error> {
        Self::generate_circuit_with_payload(
            round_constants,
            tree_height,
            vec![C::BaseField::one()],
            rng,
        )
    }
}
