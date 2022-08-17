/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: https://github.com/KZen-networks/curv/blob/master/LICENSE
*/

//TODO: (open issue) use this struct to represent the commitment HashCommitment{comm: BigInt, r: BigInt, m: BigInt}
/// calculate commitment c = H(m,r) using SHA3 CRHF.
/// r is 256bit blinding factor, m is the commited value
pub struct HashCommitment;

use crate::curv::arithmetic::num_bigint::BigInt;

use super::traits::Commitment;
use super::SECURITY_BITS;
use crate::curv::arithmetic::num_bigint::from;
use crate::curv::arithmetic::traits::Converter;
use crate::curv::arithmetic::traits::Samplable;
use cryptoxide::digest::Digest;
use cryptoxide::sha3::Sha3;

//TODO:  using the function with BigInt's as input instead of string's makes it impossible to commit to empty message or use empty randomness
impl Commitment<BigInt> for HashCommitment {
    fn create_commitment_with_user_defined_randomness(
        message: &BigInt,
        blinding_factor: &BigInt,
    ) -> BigInt {
        let mut digest = Sha3::sha3_256();
        let bytes_message: Vec<u8> = BigInt::to_vec(&message);
        digest.input(&bytes_message);
        let bytes_blinding_factor: Vec<u8> = BigInt::to_vec(&blinding_factor);
        digest.input(&bytes_blinding_factor);

        let mut result = [0; 32];
        digest.result(&mut result);
        from(result.as_ref())
    }

    fn create_commitment(message: &BigInt) -> (BigInt, BigInt) {
        let blinding_factor = BigInt::sample(SECURITY_BITS);
        let com = HashCommitment::create_commitment_with_user_defined_randomness(
            message,
            &blinding_factor,
        );
        (com, blinding_factor)
    }
}

#[cfg(test)]
mod tests {
    use super::Commitment;
    use super::HashCommitment;
    use super::SECURITY_BITS;
    use crate::curv::arithmetic::num_bigint::from;
    use crate::curv::arithmetic::num_bigint::BigInt;
    use crate::curv::arithmetic::traits::Converter;
    use crate::curv::arithmetic::traits::Samplable;
    use cryptoxide::digest::Digest;
    use cryptoxide::sha3::Sha3;
    use num_traits::{One, Zero};

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::*;

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    #[test]
    fn test_bit_length_create_commitment() {
        let hex_len = SECURITY_BITS;
        let mut ctr_commit_len = 0;
        let mut ctr_blind_len = 0;
        let sample_size = 1000;
        for _ in 1..sample_size {
            let message = BigInt::sample(SECURITY_BITS);
            let (commitment, blind_factor) = HashCommitment::create_commitment(&message);
            if commitment.to_str_radix(2).len() == hex_len {
                ctr_commit_len = ctr_commit_len + 1;
            }
            if blind_factor.to_str_radix(2).len() == hex_len {
                ctr_blind_len = ctr_blind_len + 1;
            }
        }
        //test commitment length  - works because SHA256 output length the same as sec_bits
        // we test that the probability distribuition is according to what is expected. ideally = 0.5
        let ctr_commit_len = ctr_commit_len as f32;
        let ctr_blind_len = ctr_blind_len as f32;
        let sample_size = sample_size as f32;
        assert!(ctr_commit_len / sample_size > 0.3);
        assert!(ctr_blind_len / sample_size > 0.3);
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    #[test]
    fn test_bit_length_create_commitment_with_user_defined_randomness() {
        let message = BigInt::sample(SECURITY_BITS);
        let (_commitment, blind_factor) = HashCommitment::create_commitment(&message);
        let commitment2 =
            HashCommitment::create_commitment_with_user_defined_randomness(&message, &blind_factor);
        assert_eq!(commitment2.to_hex().len() / 2, SECURITY_BITS / 8);
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    #[test]
    fn test_random_num_generation_create_commitment_with_user_defined_randomness() {
        let message = BigInt::sample(SECURITY_BITS);
        let (commitment, blind_factor) = HashCommitment::create_commitment(&message);
        let commitment2 =
            HashCommitment::create_commitment_with_user_defined_randomness(&message, &blind_factor);
        assert_eq!(commitment, commitment2);
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    #[test]
    fn test_hashing_create_commitment_with_user_defined_randomness() {
        let mut digest = Sha3::sha3_256();
        let message = BigInt::one();
        let commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &message,
            &BigInt::zero(),
        );
        let message2: Vec<u8> = BigInt::to_vec(&message);
        digest.input(&message2);
        let bytes_blinding_factor: Vec<u8> = (&BigInt::zero()).to_bytes_be();
        digest.input(&bytes_blinding_factor);
        let mut result = [0; 32];
        digest.result(&mut result);
        let hash_result = from(result.as_ref());
        assert_eq!(&commitment, &hash_result);
    }
}
