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

use crate::gadget::merkle_tree;
use crate::gadget::merkle_tree::mocking::MockingMerkleTree;
use crate::gadget::merkle_tree::{constraints::ConfigGadget, Config, IdentityDigestConverter};
use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::bits::boolean::Boolean;
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::{fields::fp::FpVar, prelude::AllocVar};
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
use ark_std::marker::PhantomData;
use libc::ELAST;

use super::MockingCircuit;

pub type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;
#[allow(non_snake_case)]
#[derive(Clone)]

pub struct AcceptTradeCircuit<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>>
where
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
{
    // constant
    pub rc: mimc7::Parameters<C::BaseField>,
    pub G: elgamal::Parameters<C>,

    // statement
    pub rt: Option<C::BaseField>,
    pub nf: Option<C::BaseField>,
    pub cmAzeroth: Option<C::BaseField>,
    pub hk: Option<C::BaseField>,
    pub addrseller: Option<C::BaseField>,
    pub pkseller: Option<elgamal::PublicKey<C>>,
    pub G_r: Option<C::Affine>,
    pub c1: Option<C::Affine>,
    pub CT_k: Option<Vec<C::BaseField>>,

    // witnesses
    pub cm: Option<C::BaseField>,
    pub leaf_pos: Option<u32>,
    pub tree_proof: Option<merkle_tree::Path<FieldMTConfig<C::BaseField>>>,
    pub skseller: Option<C::BaseField>,
    pub k_data: Option<symmetric::SymmetricKey<C::BaseField>>,
    pub pkbuyer: Option<elgamal::PublicKey<C>>,
    pub r: Option<C::BaseField>,
    pub fee: Option<C::BaseField>,
    pub oazeroth: Option<C::BaseField>,
    pub CT_k_key: Option<elgamal::Plaintext<C>>,
    pub CT_k_x: Option<symmetric::SymmetricKey<C::BaseField>>,
    pub CT_k_r: Option<elgamal::Randomness<C>>,
    pub tk_addr: Option<C::BaseField>,
    pub tk_id: Option<C::BaseField>,

    // directionSelector
    // intermediateHashWires
    pub _curve_var: PhantomData<GG>,
}

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

struct FieldMTConfigVar<F: PrimeField> {
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
impl<C, GG> ConstraintSynthesizer<C::BaseField> for AcceptTradeCircuit<C, GG>
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
        let rt = FpVar::new_input(cs.clone(), || {
            self.rt.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let nf = FpVar::new_input(cs.clone(), || {
            self.nf.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let cmAzeroth = FpVar::new_input(cs.clone(), || {
            self.cmAzeroth.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let hk = FpVar::new_input(cs.clone(), || {
            self.hk.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let addrseller = FpVar::new_input(cs.clone(), || {
            self.addrseller.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let pkseller = elgamal::constraints::PublicKeyVar::new_input(
            ark_relations::ns!(cs, "pkseller"),
            || self.pkseller.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let c1 = elgamal::constraints::OutputVar::new_input(ark_relations::ns!(cs, "c1"), || {
            Ok((self.G_r.unwrap(), self.c1.unwrap()))
        })
        .unwrap();

        let CT_k: Vec<FpVar<C::BaseField>> =
            Vec::new_input(ark_relations::ns!(cs, "CT_k"), || {
                self.CT_k.ok_or(SynthesisError::AssignmentMissing)
            })?;
        let CT_k = vec![symmetric::constraints::CiphertextVar {
            c: CT_k[0].clone(),
            r: FpVar::zero(),
        }];

        // witness

        let cm = FpVar::new_witness(ark_relations::ns!(cs, "cm"), || Ok(self.cm.unwrap())).unwrap();

        let leaf_pos = UInt32::new_witness(ark_relations::ns!(cs, "leaf_pos"), || {
            self.leaf_pos.ok_or(SynthesisError::AssignmentMissing)
        })?
        .to_bits_le();

        let mut cw = merkle_tree::constraints::PathVar::<
            FieldMTConfig<C::BaseField>,
            C::BaseField,
            FieldMTConfigVar<C::BaseField>,
        >::new_witness(ark_relations::ns!(cs, "cw"), || {
            self.tree_proof.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let skseller = FpVar::new_witness(ark_relations::ns!(cs, "skseller"), || {
            Ok(self.skseller.unwrap())
        })
        .unwrap();

        let k_data = symmetric::constraints::SymmetricKeyVar::new_witness(
            ark_relations::ns!(cs, "k_data"),
            || self.k_data.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let pkbuyer = elgamal::constraints::PublicKeyVar::new_witness(
            ark_relations::ns!(cs, "pkbuyer"),
            || self.pkbuyer.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let r = FpVar::new_witness(ark_relations::ns!(cs, "r"), || Ok(self.r.unwrap())).unwrap();

        let fee =
            FpVar::new_witness(ark_relations::ns!(cs, "fee"), || Ok(self.fee.unwrap())).unwrap();

        let oazeroth = FpVar::new_witness(ark_relations::ns!(cs, "oazeroth"), || {
            Ok(self.oazeroth.unwrap())
        })
        .unwrap();

        let CT_k_key: elgamal::constraints::PlaintextVar<C, GG> =
            elgamal::constraints::PlaintextVar::new_witness(
                ark_relations::ns!(cs, "CT_k_key"),
                || self.CT_k_key.ok_or(SynthesisError::AssignmentMissing),
            )?;

        let CT_k_x = symmetric::constraints::SymmetricKeyVar::new_witness(
            ark_relations::ns!(cs, "CT_k_x"),
            || self.CT_k_x.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let CT_k_r = elgamal::constraints::RandomnessVar::new_witness(
            ark_relations::ns!(cs, "CT_k_r"),
            || self.CT_k_r.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let tk_addr = FpVar::new_witness(ark_relations::ns!(cs, "tk_addr"), || {
            Ok(self.tk_addr.unwrap())
        })
        .unwrap();

        let tk_id = FpVar::new_witness(ark_relations::ns!(cs, "tk_id"), || Ok(self.tk_id.unwrap()))
            .unwrap();

        // relation

        /////////////////////////////////////////////////////////////////
        // ctk = Enc(pkbuyer, k)

        let check_c_1 =
            ElGamalEncGadget::<C, GG>::encrypt(&G.clone(), &CT_k_key.clone(), &CT_k_r, &pkbuyer)
                .unwrap();

        println!("c1: {:?}", c1.is_eq(&check_c_1)?.value());
        c1.enforce_equal(&check_c_1)?;

        let Plain: Vec<FpVar<C::BaseField>> = vec![k_data.k.clone()];

        for (i, m) in Plain.iter().enumerate() {
            let randomness = symmetric::constraints::RandomnessVar::new_constant(
                ark_relations::ns!(cs, "randomness"),
                symmetric::Randomness {
                    r: C::BaseField::from_bigint((i as u64).into()).unwrap(),
                },
            )?;

            let c = SymmetricEncryptionSchemeGadget::<C::BaseField>::encrypt(
                rc.clone(),
                randomness,
                CT_k_x.clone(),
                symmetric::constraints::PlaintextVar { m: m.clone() },
            )
            .unwrap();

            println!("c: {:?}", c.is_eq(&CT_k[i])?.value());
            c.enforce_equal(&CT_k[i])?;
            // println!("c: {:?}", c.is_eq(&CT_k[i])?.value());
        }
        /////////////////////////////////////////////////////////////////

        /////////////////////////////////////////////////////////////////
        // check hk = HASH(skseller || k_data )

        let hk_hash_input = [skseller.clone(), k_data.k.clone()];
        let result_hk = MiMCGadget::<C::BaseField>::evaluate(&rc, &hk_hash_input).unwrap();

        println!("hk: {:?}", result_hk.is_eq(&hk)?.value());

        result_hk.enforce_equal(&hk)?;
        /////////////////////////////////////////////////////////////////

        /////////////////////////////////////////////////////////////////
        // check cm
        let binding = pkbuyer.clone().pk.to_bits_le()?;
        let pkbuyer_point_x = Boolean::le_bits_to_fp_var(&binding[..binding.len() / 2])?;

        let binding_pkseller = pkseller.clone().pk.to_bits_le()?;
        let pkseller_point_x =
            Boolean::le_bits_to_fp_var(&binding_pkseller[..binding_pkseller.len() / 2])?;

        let cm_hash_input = [
            pkseller_point_x.clone(),
            r.clone(),
            fee.clone(),
            hk.clone(),
            pkbuyer_point_x.clone(),
        ];
        let result_cm = MiMCGadget::<C::BaseField>::evaluate(&rc, &cm_hash_input).unwrap();

        println!("cm: {:?}", result_cm.is_eq(&cm)?.value());

        result_cm.enforce_equal(&cm)?;
        /////////////////////////////////////////////////////////////////

        /////////////////////////////////////////////////////////////////
        // check cmazeroth
        let cmAzeroth_hash_input = [
            oazeroth.clone(),
            tk_addr.clone(),
            tk_id.clone(),
            fee.clone(),
            addrseller.clone(),
        ];
        let result_cmAzeroth =
            MiMCGadget::<C::BaseField>::evaluate(&rc, &cmAzeroth_hash_input).unwrap();

        println!(
            "cmazeroth: {:?}",
            result_cmAzeroth.is_eq(&cmAzeroth)?.value()
        );

        result_cmAzeroth.enforce_equal(&cmAzeroth)?;
        /////////////////////////////////////////////////////////////////

        ///////////////////////////////////////////////////
        // check merkletree
        let leaf_g: Vec<_> = vec![cm.clone()];
        cw.set_leaf_position(leaf_pos.clone());

        let path_check = cw
            .verify_membership(&rc.clone(), &rc.clone(), &rt, &leaf_g)
            .unwrap();
        path_check.enforce_equal(&Boolean::constant(true))?;
        println!(
            "path_check: {:?}",
            path_check.is_eq(&Boolean::constant(true))?.value()
        );

        /////////////////////////////////////////////////////////////////

        /////////////////////////////////////////////////////////////////
        // check nf

        let nf_input = [skseller.clone(), cm.clone()];
        let result_nf = MiMCGadget::<C::BaseField>::evaluate(&rc, &nf_input).unwrap();

        println!("nf: {:?}", result_nf.is_eq(&nf)?.value());

        result_nf.enforce_equal(&nf)?;
        /////////////////////////////////////////////////////////////////

        println!("constranint num = {:?}", cs.num_constraints());
        Ok(())
    }
}

#[allow(non_snake_case)]
impl<C, GG> MockingCircuit<C, GG> for AcceptTradeCircuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    type F = C::BaseField;
    type HashParam = mimc7::Parameters<Self::F>;
    type H = mimc7::MiMC<Self::F>;
    type Output = AcceptTradeCircuit<C, GG>;

    fn generate_circuit<R: ark_std::rand::Rng>(
        round_constants: Self::HashParam,
        tree_height: u64,
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

        let sk: <<C as CurveGroup>::Affine as AffineRepr>::BaseField = Self::F::rand(rng);

        // hk
        let key_len = 8;
        let mut k_data = Vec::new();
        for _ in 0..key_len {
            k_data.push(C::BaseField::rand(rng));
        }

        // let k_data: symmetric::SymmetricKey<<<C as CurveGroup>::Affine as AffineRepr>::BaseField> =
        //     symmetric::SymmetricKey { k: sk };

        let skseller = Self::F::rand(rng);

        let mut hk_input = k_data.clone();
        hk_input.push(skseller);
        let hk = Self::H::evaluate(&rc.clone(), k_data.clone().push(skseller.clone())).unwrap();

        //cm
        let r: Self::F = Self::F::one();
        let fee: Self::F = Self::F::one();
        let (pkbuyer, _) = ElGamal::keygen(&elgamal_param, rng).unwrap();
        let (pkseller, _) = ElGamal::keygen(&elgamal_param, rng).unwrap();
        let (pkbuyer_point_x, pkbuyer_point_y) = pkbuyer.xy().unwrap();
        let pkbuyer_point_x = Self::F::from_bigint(pkbuyer_point_x.into_bigint()).unwrap();

        let (pkseller_point_x, pkseller_point_y) = pkseller.xy().unwrap();
        let pkseller_point_x = Self::F::from_bigint(pkseller_point_x.into_bigint()).unwrap();

        let cm: <<C as CurveGroup>::Affine as AffineRepr>::BaseField = Self::H::evaluate(
            &rc.clone(),
            [
                pkseller_point_x.clone(),
                r.clone(),
                fee.clone(),
                hk.clone(),
                pkbuyer_point_x.clone(),
            ]
            .to_vec(),
        )
        .unwrap();

        // make oazeroth

        let oazeroth: <<C as CurveGroup>::Affine as AffineRepr>::BaseField = Self::F::rand(rng);

        // make cm_wallet
        let addrseller: Self::F = Self::F::one();
        let tk_addr: Self::F = Self::F::one();
        let tk_id: Self::F = Self::F::one();

        let cmAzeroth = Self::H::evaluate(
            &rc.clone(),
            [
                oazeroth.clone(),
                tk_addr,
                tk_id,
                fee.clone(),
                addrseller.clone(),
            ]
            .to_vec(),
        )
        .unwrap();

        // make nf

        let nf = Self::H::evaluate(&rc.clone(), [skseller.clone(), cm.clone()].to_vec()).unwrap();

        // maek CT_k

        let CT_k_key = C::rand(rng).into_affine();
        let CT_k_x = CT_k_key.x().unwrap();
        let CT_k_x = symmetric::SymmetricKey { k: *CT_k_x };
        let mut CT_k: Vec<_> = Vec::new();

        let CT_r = C::ScalarField::rand(rng);

        let random: elgamal::Randomness<C> = elgamal::Randomness { 0: CT_r };
        let (G_r, c1) = ElGamal::encrypt(&elgamal_param, &pkbuyer, &CT_k_key, &random).unwrap();

        let mut Order = Vec::new();

        for _ in 0..key_len {
            Order.push(C::BaseField::rand(rng));
        }

        let Order = vec![k_data.k.clone()];

        Order.iter().enumerate().for_each(|(i, m)| {
            let random = symmetric::Randomness {
                r: Self::F::from_bigint((i as u64).into()).unwrap(),
            };
            let c = symmetric::SymmetricEncryptionScheme::encrypt(
                rc.clone(),
                random,
                CT_k_x.clone(),
                symmetric::Plaintext { m: m.clone() },
            )
            .unwrap();

            CT_k.push(c.c);
        });

        // Merkle tree
        println!("generate mocking tree");
        let leaf_crh_params = rc.clone();
        let two_to_one_params = leaf_crh_params.clone();

        let proof: merkle_tree::Path<FieldMTConfig<Self::F>> =
            merkle_tree::mocking::get_mocking_merkle_tree(tree_height);
        let leaf: Self::F = cm.clone();

        println!("path len = {:?}", proof.auth_path.len());

        let rt = proof
            .get_test_root(&leaf_crh_params, &two_to_one_params, [leaf])
            .unwrap();

        let i: u32 = 0;
        assert!(proof
            .verify(&leaf_crh_params, &two_to_one_params, &rt, [leaf])
            .unwrap());

        Ok(AcceptTradeCircuit {
            //constant
            rc: rc.clone(),
            G: elgamal_param,
            // statement
            rt: Some(rt),
            nf: Some(nf),
            cmAzeroth: Some(cmAzeroth),
            hk: Some(hk),
            pkseller: Some(pkseller),
            addrseller: Some(addrseller),
            G_r: Some(G_r),
            c1: Some(c1),
            CT_k: Some(CT_k),

            //witness
            cm: Some(cm),
            leaf_pos: Some(i),
            tree_proof: Some(proof),
            skseller: Some(skseller),
            k_data: Some(k_data),
            pkbuyer: Some(pkbuyer),
            r: Some(r),
            fee: Some(fee),
            oazeroth: Some(oazeroth),
            CT_k_key: Some(CT_k_key),
            CT_k_x: Some(CT_k_x),
            CT_k_r: Some(random),
            tk_addr: Some(tk_addr),
            tk_id: Some(tk_id),

            _curve_var: std::marker::PhantomData,
        })
    }
}
