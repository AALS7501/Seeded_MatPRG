use ark_std::borrow::Borrow;
use ark_std::vec;
use ark_std::vec::Vec;
use ark_ff::PrimeField;

// External crates
use crate::gadget::hashes::{CRHScheme, TwoToOneCRHScheme};
use crate::gadget::merkle_tree::{Config, DigestConverter, LeafParam, Path, TwoToOneParam};
use crate::Error;

pub trait MockingMerkleTree<P: Config> {
    fn get_test_root<L: Borrow<P::Leaf>>(
        &self,
        leaf_hash_params: &LeafParam<P>,
        two_to_one_params: &TwoToOneParam<P>,
        leaf: L,
    ) -> Result<<P as Config>::InnerDigest, Error>;
}

impl<P: Config> MockingMerkleTree<P> for Path<P> {
    fn get_test_root<L: Borrow<P::Leaf>>(
        &self,
        leaf_hash_params: &LeafParam<P>,
        two_to_one_params: &TwoToOneParam<P>,
        leaf: L,
    ) -> Result<<P as Config>::InnerDigest, Error> {
        // calculate leaf hash
        let claimed_leaf_hash = P::LeafHash::evaluate(&leaf_hash_params, leaf)?;
        // check hash along the path from bottom to root
        let (left_child, right_child) =
            select_left_right_child(self.leaf_index, &claimed_leaf_hash, &self.leaf_sibling_hash)?;

        // leaf layer to inner layer conversion
        let left_child = P::LeafInnerDigestConverter::convert(left_child)?;
        let right_child = P::LeafInnerDigestConverter::convert(right_child)?;

        let mut curr_path_node =
            P::TwoToOneHash::evaluate(&two_to_one_params, left_child, right_child)?;

        // we will use `index` variable to track the position of path
        let mut index = self.leaf_index;
        index >>= 1;

        // Check levels between leaf level and root
        for level in (0..self.auth_path.len()).rev() {
            // check if path node at this level is left or right
            let (left, right) =
                select_left_right_child(index, &curr_path_node, &self.auth_path[level])?;
            // update curr_path_node
            curr_path_node = P::TwoToOneHash::compress(&two_to_one_params, &left, &right)?;
            index >>= 1;
        }

        Ok(curr_path_node)
    }
}

fn select_left_right_child<L: Clone>(
    index: usize,
    computed_hash: &L,
    sibling_hash: &L,
) -> Result<(L, L), Error> {
    let is_left = index & 1 == 0;
    let mut left_child = computed_hash;
    let mut right_child = sibling_hash;
    if !is_left {
        core::mem::swap(&mut left_child, &mut right_child);
    }
    Ok((left_child.clone(), right_child.clone()))
}

pub fn get_mocking_merkle_tree<T: Config<LeafDigest = F, InnerDigest = F>, F: PrimeField>(
    tree_height: u64,
) -> Path<T> {
    let total_sibling_nodes: u64 = tree_height - 1;
    let mut leaves: Vec<Vec<F>> = Vec::with_capacity(total_sibling_nodes.try_into().unwrap());
    for _ in 0..total_sibling_nodes {
        let zero_filled_vector: Vec<F> = vec![F::zero(); 1];
        leaves.push(zero_filled_vector);
    }

    let flattened_leaves: Vec<F> = leaves.into_iter().flatten().collect();
    let tree_path: Path<T> = Path {
        leaf_index: 0,
        auth_path: flattened_leaves[1..].to_vec(),
        leaf_sibling_hash: flattened_leaves[0],
    };
    tree_path
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gadget::hashes::mimc7;

    use crate::gadget::merkle_tree::{Config, IdentityDigestConverter};

    use ark_std::{test_rng, UniformRand, Zero};

    type F = ark_bn254::Fr;
    type H = mimc7::MiMC<F>;
    type TwoToOneH = mimc7::TwoToOneMiMC<F>;

    struct FieldMTConfig;
    impl Config for FieldMTConfig {
        type Leaf = [F];
        type LeafDigest = F;
        type LeafInnerDigestConverter = IdentityDigestConverter<F>;
        type InnerDigest = F;
        type LeafHash = H;
        type TwoToOneHash = TwoToOneH;
    }

    #[test]
    fn test_get_mocking_merkle_tree() {
        let tree_height: u64 = 5;
        let path: Path<FieldMTConfig> = get_mocking_merkle_tree(tree_height);
        assert_eq!(path.auth_path.len(), (tree_height - 2) as usize);
        assert!(path.auth_path.iter().all(|&x| x == F::zero()));
    }

    #[test]
    fn test_get_test_root() {
        let mut rng = test_rng();
        let tree_height: u64 = 5;
        let leaf: F = F::rand(&mut rng);
        let leaf_hash_params = LeafParam::<FieldMTConfig>::default();
        let two_to_one_params = TwoToOneParam::<FieldMTConfig>::default();
        let path: Path<FieldMTConfig> = get_mocking_merkle_tree(tree_height);

        let rt = path
            .get_test_root(&leaf_hash_params, &two_to_one_params, [leaf].borrow())
            .unwrap();

        assert!(path
            .verify(&leaf_hash_params, &two_to_one_params, &rt, [leaf])
            .unwrap());
    }
}
