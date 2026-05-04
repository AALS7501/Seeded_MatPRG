mod test {
    use crate::gadget::hashes::mimc7;
    use crate::gadget::hybrid_key_transport::{
        pack_bits_to_fields, unwrap_payload_for_recipient, wrap_payload_for_recipient,
    };
    use crate::gadget::public_encryptions::elgamal::ElGamal;
    use crate::gadget::public_encryptions::AsymmetricEncryptionScheme;
    use crate::register_MatPRG;
    use crate::register_seeded_matprg;
    use ark_ec::{AffineRepr, CurveGroup, Group};
    use ark_ff::PrimeField;
    use ark_std::{rand::{RngCore, SeedableRng}, UniformRand};
    use ark_std::test_rng;

    type C = ark_ed_on_bn254::EdwardsProjective;
    type F = ark_bn254::Fr;

    #[test]
    fn test_order_key_transport_roundtrip() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let rc = mimc7::Parameters::<F> {
            round_constants: mimc7::parameters::get_bn256_round_constants(),
        };
        let elgamal_params = crate::gadget::public_encryptions::elgamal::Parameters {
            generator: C::generator().into_affine(),
        };

        let (pk_buyer, _) = ElGamal::<C>::keygen(&elgamal_params, &mut rng).unwrap();
        let (pk_seller, sk_seller) = ElGamal::<C>::keygen(&elgamal_params, &mut rng).unwrap();
        let (pk_buyer_x, pk_buyer_y) = pk_buyer.xy().unwrap();

        let order_payload = vec![
            F::from_bigint(pk_buyer_x.into_bigint()).unwrap(),
            F::from_bigint(pk_buyer_y.into_bigint()).unwrap(),
            F::from(7u64),
            F::from(11u64),
            F::from(13u64),
        ];

        let (wrapped, witness) = wrap_payload_for_recipient(
            rc.clone(),
            &elgamal_params,
            &pk_seller,
            &order_payload,
            &mut rng,
        )
        .unwrap();

        let recovered = unwrap_payload_for_recipient(
            rc.clone(),
            &elgamal_params,
            &sk_seller,
            &wrapped,
        )
        .unwrap();

        let decrypted_point =
            ElGamal::<C>::decrypt(&elgamal_params, &sk_seller, &wrapped.encapsulated_point)
                .unwrap();

        assert_eq!(recovered, order_payload);
        assert_eq!(decrypted_point, witness.payload_point);
    }

    #[test]
    fn test_original_and_seeded_key_payload_transport_under_same_data_log() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let rc = mimc7::Parameters::<F> {
            round_constants: mimc7::parameters::get_bn256_round_constants(),
        };
        let elgamal_params = crate::gadget::public_encryptions::elgamal::Parameters {
            generator: C::generator().into_affine(),
        };
        let (pk_buyer, sk_buyer) = ElGamal::<C>::keygen(&elgamal_params, &mut rng).unwrap();

        assert_eq!(register_MatPRG::DATA_SET.N, register_seeded_matprg::DATA_SET.N);
        assert_eq!(register_MatPRG::DATA_SET.K, register_seeded_matprg::DATA_SET.K);
        assert_eq!(
            register_MatPRG::DATA_SET.Data_size,
            register_seeded_matprg::DATA_SET.Data_size
        );
        assert!(register_seeded_matprg::current_key_bits() < register_MatPRG::current_key_bits());

        let original_payload = (0..register_MatPRG::DATA_SET.Key_len)
            .map(|_| F::rand(&mut rng))
            .collect::<Vec<_>>();

        let recursive_seed_bits = (0..register_seeded_matprg::DATA_SET.M1)
            .map(|_| (rng.next_u32() & 1) == 1)
            .collect::<Vec<_>>();
        let recursive_payload = pack_bits_to_fields::<F>(&recursive_seed_bits, 248);

        let (wrapped_original, _) = wrap_payload_for_recipient(
            rc.clone(),
            &elgamal_params,
            &pk_buyer,
            &original_payload,
            &mut rng,
        )
        .unwrap();
        let (wrapped_recursive, _) = wrap_payload_for_recipient(
            rc.clone(),
            &elgamal_params,
            &pk_buyer,
            &recursive_payload,
            &mut rng,
        )
        .unwrap();

        let recovered_original =
            unwrap_payload_for_recipient(rc.clone(), &elgamal_params, &sk_buyer, &wrapped_original)
                .unwrap();
        let recovered_recursive =
            unwrap_payload_for_recipient(rc.clone(), &elgamal_params, &sk_buyer, &wrapped_recursive)
                .unwrap();

        assert_eq!(recovered_original, original_payload);
        assert_eq!(recovered_recursive, recursive_payload);
        assert!(original_payload.len() >= recursive_payload.len());
    }
}
