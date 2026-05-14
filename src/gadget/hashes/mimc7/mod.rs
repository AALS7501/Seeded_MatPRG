use std::{borrow::Borrow, marker::PhantomData};

use crate::Error;
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use super::{CRHScheme, TwoToOneCRHScheme};

pub mod constraints;
pub mod parameters;

#[derive(Clone, Default, CanonicalSerialize, CanonicalDeserialize)]
pub struct Parameters<F: Field> {
    pub round_constants: Vec<F>,
}

pub struct MiMC<F: Field + Absorb> {
    _field: PhantomData<F>,
}

impl<F: Field + Absorb> MiMC<F> {
    fn round(xl: F, xr: F, rc: F) -> F {
        let mut xored = xl.add(xr).add(rc);
        let mut tmp = xored.clone();
        for _ in 0..2 {
            tmp = tmp.mul(tmp);
            xored = xored.mul(tmp);
        }

        xored
    }

    fn encrypt(params: Parameters<F>, xl: F, xr: F) -> F {
        let mut result = Self::round(xl, xr, F::zero());

        for i in 1..params.round_constants.len() {
            result = Self::round(result.clone(), xr.clone(), params.round_constants[i]);
        }

        result.add(xr.clone())
    }
}

impl<F> CRHScheme for MiMC<F>
where
    F: Field + Absorb,
{
    type Parameters = Parameters<F>;
    type Input = [F];
    type Output = F;

    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error> {
        let input = input.borrow();
        let mut output: Self::Output;
        if input.len() == 1 {
            let xl = input[0].clone();
            let xr = input[0].clone();
            output = Self::encrypt(parameters.clone(), xl, xr)
                .add(input[0])
                .add(input[0]);
        } else {
            output = input[0].clone();
            for i in 1..input.len() {
                let xl = output.clone();
                let xr = input[i].clone();

                output = Self::encrypt(parameters.clone(), xl, xr);
                output = output.add(xl).add(input[i]);
            }
        }

        Ok(output)
    }
}

pub struct TwoToOneMiMC<F: Field> {
    _field: PhantomData<F>,
}

impl<F: Field + Absorb> TwoToOneMiMC<F> {
    fn encrypt(params: Parameters<F>, xl: F, xr: F) -> F {
        MiMC::<F>::encrypt(params, xl, xr)
    }
}

impl<F> TwoToOneCRHScheme for TwoToOneMiMC<F>
where
    F: Field + Absorb,
{
    type Parameters = Parameters<F>;
    type Input = F;
    type Output = F;

    fn evaluate<T: Borrow<Self::Input>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, Error> {
        let left_input = left_input.borrow();
        let right_input = right_input.borrow();

        let xl = left_input.clone();
        let xr = right_input.clone();

        let output = Self::encrypt(parameters.clone(), xl, xr)
            .add(left_input)
            .add(right_input);

        Ok(output)
    }

    fn compress<T: Borrow<Self::Output>>(
        parameters: &Self::Parameters,
        left_input: T,
        right_input: T,
    ) -> Result<Self::Output, ark_crypto_primitives::Error> {
        // TODO sponge input
        <Self as TwoToOneCRHScheme>::evaluate(parameters, left_input.borrow(), right_input.borrow())
    }
}

#[cfg(test)]
mod test {
    use ark_bn254::Fr;
    use ark_ff::PrimeField;

    use crate::gadget::hashes::{
        mimc7::{self, parameters},
        CRHScheme, TwoToOneCRHScheme,
    };

    use super::Parameters;

    fn print_hex(f: Fr) {
        let decimal_number = f.into_bigint().to_string();

        // Parse the decimal number as a BigUint
        let big_int = num_bigint::BigUint::parse_bytes(decimal_number.as_bytes(), 10).unwrap();

        // Convert the BigUint to a hexadecimal string
        let hex_string = format!("{:x}", big_int);

        println!("0x{}", hex_string);
    }

    #[test]
    fn test_mimc() {
        let rounc_constants = parameters::get_bn256_round_constants().clone();

        let param = Parameters {
            round_constants: rounc_constants,
        };

        let xl = Fr::from(111111);
        let xr = Fr::from(111111);

        let res = mimc7::MiMC::<Fr>::evaluate(&param, [xl, xr].to_vec()).unwrap();
        print!("res:: ",);
        print_hex(res);
        let res = mimc7::TwoToOneMiMC::<Fr>::evaluate(&param, xl, xr).unwrap();
        print!("res:: ");
        print_hex(res);
        let res_compress = mimc7::TwoToOneMiMC::<Fr>::compress(&param, xl, xr).unwrap();
        assert_eq!(res_compress, res);
    }
}

// round constants
// rc[ 0]: 0xaed26d6a3f5e0ea662411ddfcde3527479de9cee7a56c656ff5f61df13a39401
// rc[ 1]: 0x2fd3f713342a30b6442ee1f0fd68277ad3a132d8e16c2941ec7b174a3cd5a8e8
// rc[ 2]: 0x0c52ba72571f8fa23851ae1abdc735493945793a7dc4bfb6359289cafff7c902
// rc[ 3]: 0x0b775ae9ca4e06bc147eeb49471b79d0631d469cc9d462752f6edd5ed7f9881c
// rc[ 4]: 0x9f5c3725c37289eba73952159cf9c220d4e72aadf79acee05fdf899f688ce32e
// rc[ 5]: 0xe8aec5648b139303f2c433a9a34f2b5e3b9d8498c97cdc6f0d418a4a8b7aa5cc
// rc[ 6]: 0x527d7389be43a5bb976d00b143f65bdda52059ece4e4b56ba1e435daafc88fb5
// rc[ 7]: 0x7febf0e40ad207fed69060809a52f82d64ab583e123cdd09c8e8d4d2a9dcda08
// rc[ 8]: 0x159a66c3cc74c0ccb15fab04665f7b754197ab54e6f823b1f5e22724a5c93988
// rc[ 9]: 0xe168f563aef7738ffeea94eeeb8fd642aa480b49a958063861ea13b8e6f502d0
// rc[10]: 0x85882afbc60a9cdd83690df7c88b874678d55003345fca208efe66efc3e95270
// rc[11]: 0x1e4424851dc882b820ca2753a069c7db07fdfc834b328aa3bac5430bf50265a0
// rc[12]: 0x12575adc28eba0b4cc7343e152f19a04ae1d2218f1cbfaf91fff6e6c7940a3e3
// rc[13]: 0x554431b9c80b23f0dec5b8e18dcc1a4071bfedcc8116ddec7bd1ad82d50d45dd
// rc[14]: 0x3c5c5212ab8777ddea48dd70952f0b9602df0bbb952e1ea538073b9c9964432d
// rc[15]: 0xf868339ec95f3fdbd1a71eeb088b98ad6ebd33ea15be671205b8163f30f613ef
// rc[16]: 0x3a1befa3816270264ccf95715dd8581fb3df8ade649b89d022f8eeef5f60e768
// rc[17]: 0xc520090bf028447866a5c326c7cb787b635121e34d9d14730553e37dc0f64928
// rc[18]: 0xbf08f1ee94f2d6d7774b2494e6f8fe524e679960a732e666562e365d57316140
// rc[19]: 0x6feb75e1d522616e028a0891dbd3270c501387a5f358fa1f460e22db15c10d51
// rc[20]: 0xea8ddd0d308cabcc28366dee563cf03d746eb1620062ba0be081ab157b2d576a
// rc[21]: 0xbb98e147fbb1b901e0300af40dff6f99b14193764dffd8aaf5fc98674b87ba26
// rc[22]: 0x5209e41effa112c60f06bb7cfd8d6935fe3fa2571a1eed15adb0723b7eed111f
// rc[23]: 0xc1ca0068d0a541cfdcff8ba8630587d2db54f2f9026178c131c73ceb6889eb8e
// rc[24]: 0x48525a21e8bcaf9f545b34eba3a14eea71800ec4477f6041385a2f723402999d
// rc[25]: 0x50de6355b9cc874a7c3d0b338704227388656a25fbfbac7c255362de40dc1c17
// rc[26]: 0xbe918a03f89de1e6f9993bebedfaee063a165ed23d138199df9ab6a70903fb92
// rc[27]: 0x7ec1494f78843f7478b2f6e5618a319e297c8fcdc246ae3fecee3b60e660d20
// rc[28]: 0xf5643938b229e677020d5b1b2a588d52f2f2151d03df48c038f6057cf2b68965
// rc[29]: 0x3385033d5865eeea602ec453e3b608361a3ef826036d98918ea95fbec3ffdfe4
// rc[30]: 0xa1a0248d82cc8d250965c4714617f0de5670a5ea540232f1e291a6d265aaf942
// rc[31]: 0x7dd8cdc7885ec724510d93e8665d4d6dcbf26be153d11bddae71f6f65f2b3882
// rc[32]: 0x9b41324ca857aaf7a80077ead6b9639e1b486b559e18ce0eb15522924b296c41
// rc[33]: 0x217a17432f14d95ebd6f20f8ba4f2ce03869a84e66f88f37b01c322f5c232a2a
// rc[34]: 0xc2450f0a56fb3e509b5c39e2574cc97ff35009491a665e126eca8978548f6bc7
// rc[35]: 0xb8c16ff1955411761183d9fc843f6f132d324ce43cf72e7b50091cfadd92659
// rc[36]: 0xfbace5b1c70921199d52489e06c847f01064e9046ddee2d1cc30aa203130884e
// rc[37]: 0x3706f5fee7a454148efe20a16ed53ad84802af2c9f8746f2b52cb6bf2aab9fbc
// rc[38]: 0xe4ebac6d8b3afd1a11e5c3564e7f308afe2000bc741f5733a5896acdd0e87b5b
// rc[39]: 0xe79a3054b7903d2091be131150dc9ca1c73cdabf7992f18e5ee2c45d64335aa5
// rc[40]: 0x9ae538c371840c7f9862a402cc18220895ab2991853b053ffde7125ac55ca961
// rc[41]: 0x19a415fc05fe4c2d21bcd2ab53937c0b9f95411e959ab15279438366ece17c2a
// rc[42]: 0x979e4c1eb0b83fa86340233586d8c387cbad0a64657916c4fa93145232b89b70
// rc[43]: 0x7044e8ce2e55e56abdc772b3ec5a376bee5cae8de7c833646c21e84375c22f64
// rc[44]: 0x4fa50c8d45a1ab37f1a08f72b810c6dd2d037b93247ca857a6806afaf37a3654
// rc[45]: 0xc05881f3c28253b254ab2d1ad5610ee2e90950d80c8d0807144df127b4678022
// rc[46]: 0x23f28f6bfc64aeb03db9e4abf60c484be5e269b8502dc23748cfca4880218256
// rc[47]: 0xd64d04f4ba3ba8a4ac19342c60f250a26f514f320b75c1fc979355a65c18bf54
// rc[48]: 0xa04c4080751ae60fadd38e4849b4628fefd22f66e16c982f95e2feaa5ab0c6de
// rc[49]: 0x58099fc4dccfc095f84d13343df3e7948f0cfc70609266f962067d361b32a567
// rc[50]: 0x6048574939b665719bdff6d4a87d0f57b553153952d6b25096019a80579de073
// rc[51]: 0x5f1571dde6a0bfd5943213f9f2a8d1077ef644f57fed8680f68f72f6b1429db4
// rc[52]: 0xba1f623b0c0828268f386700c0c8496a423e9bcf4b3cad6af478f6c6ee5077e6
// rc[53]: 0x4e96bff8f67c0084da7a15846cda431e685efa822b9bb488bbda1673612a1ce6
// rc[54]: 0xe0cc681538533056e0983ac1ae41c6a3628d93760ccc4e2b55471e50aecb8920
// rc[55]: 0x82a41a8d605f0558fb4f53af7fa6ad957b7ed80e8e50dd2ed789045b92991419
// rc[56]: 0x81014098cd70cc62d354ef1479eb56d8b1441ad23c2fbfc65226bf67533b2111
// rc[57]: 0x51068d5413cc15c6b61c0be3c4a09ff8b8bbcd844503d23722982df79943ce37
// rc[58]: 0xceb141d14e64e2b7abdb8fd2e8b3d5adc14db3bd3ed48ff2bcbf79298cc27ee3
// rc[59]: 0xbc6d07f35e245d9548043fa566ab84cba642ec66cdefaa01a3ed45c7518e87bc
// rc[60]: 0xcc3d302cf0d5d0bdefe332ab8e84f355d0ab901487b904b169cfdf3b5c0426b6
// rc[61]: 0x18c062ae07e7a6bcebd3abd03f5c9dd3e72f019736e73c5f3ec13844906eec6e
// rc[62]: 0x1fddd9572d81c3c12af17dacfbc0ae9a1d8f3137560133a855847902a5ea65e
// rc[63]: 0x8a91fd7aa62ca82f06c77e5abb4cb5d1fc622be605596476af534314e8d2b43e
// rc[64]: 0xd30cf431aa7e667d0978ae2234df2b3d09520e1302166cc94130be5724b96215
// rc[65]: 0xb3d0f55d561885c4ce353de64c6e53778d4266f0c34fae2df3a2d4d325bf565a
// rc[66]: 0x3d0f71e4577e222a7878481850e5afe8eba78cdb395f7dc1006f8df39474c4fe
// rc[67]: 0x839d2e4b1ac66e5b222b061efc15e1f7c8b605a2cefaa9eb3e24a32d5bcbc244
// rc[68]: 0xcdcc38d0d9b8368c9d27c07a5176ca6a0dc87193a9178620bf2c9dc246220aec
// rc[69]: 0xc979d87d352e60adec1546f80ee18be56902eabb4f86eec18114f9e9f0095c92
// rc[70]: 0x40c7a1ed0100522007c3f12a2118a24064c0f85197ad4fff04a5eb67757ff886
// rc[71]: 0x352b106f8b05203f71966587fe9b297b68add8eb218678f286838ab215d084fb
// rc[72]: 0xdbca068bd0aaacf85f3a8cf1595043fd0ba5a8dd5ada41002d89881324906bb6
// rc[73]: 0x222caf630ec81c43af4cc53c525e248742fd2bd16b098ff823798af422124aa0
// rc[74]: 0x6d529168673d1be5a215a0f6a82fb212eec31654e6eb887d5c2bb7e67badb0c9
// rc[75]: 0xd2d0d4bb1813d28f4d829b13e0f419e1e80485c0a829fab83d1177fe233332d3
// rc[76]: 0xe359cf8f10877b26c2a254abca5fc3f7bcadf1683f605ff343de7ac4b837ed5
// rc[77]: 0x4db0debcce2057cd10073434f01280fd472a69352f84d8d9b567a8c63b9dae3f
// rc[78]: 0x550613a139fb8dc492248e104fe662bd44d9f6424ee7d304d9af33f0d4a5ea89
// rc[79]: 0x2921f5b8e014b0c1591a772a38c9d7747f909b3a8c22aca9b5f0ef3450f210e2
// rc[80]: 0x33347995aa0d8244f5b2cb5c57039bc1b24c21705b122a106adefd7225803c42
// rc[81]: 0x3fd931f11ed347966b8759e9cc5fe2abe85df21cdda310840038a94ceecdbb9f
// rc[82]: 0xc22fc08cfb542a0cf00235ecdc9669475c9c95fe7fa6a947c8c8a7fa8b0968c0
// rc[83]: 0x6e5a7a361dd37d34e56f18bfe1e58f9d0d2a1324a65a2929ce6e727d4e1928c2
// rc[84]: 0xe57693fd871e6889d4645c07c7a102ea103aea3915f8cca38b70c200c78d41e6
// rc[85]: 0x227ee87881842b83160e52b252d030e6c497fe71f99b3be110d25a2c336540d2
// rc[86]: 0xcfe8b070c4fd1ca3a2e3a8f9a29c1c93a5888b24cdeb4a2e4ac065add56554e7
// rc[87]: 0x9f2c2ecf0d31fd9fc41e4890a221fa9fee0a075b70bded3bbb18f30680e979b5
// rc[88]: 0xeda03c33c5764cbf41b1f947eb00f80e2016c6fb73dee9abda9996a3d586ef74
// rc[89]: 0x6e0038296e55aad256f8d84f158ceeea671a981e5286470788058f0f07523e78
// rc[90]: 0x361e359068051320f561dd4a07d0bb3532ced198dc9a63c74b89f67a695259b2
