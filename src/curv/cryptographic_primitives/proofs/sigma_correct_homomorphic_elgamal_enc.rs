#![allow(non_snake_case)]
/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: https://github.com/KZen-networks/curv/blob/master/LICENSE
*/

use super::ProofError;
use crate::curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use crate::curv::cryptographic_primitives::hashing::traits::Hash;
use crate::curv::elliptic::curves::secp256_k1::{FE, GE};
use crate::curv::elliptic::curves::traits::*;
use zeroize::Zeroize;

/// This is a proof of knowledge that a pair of group elements {D, E}
/// form a valid homomorphic ElGamal encryption (”in the exponent”) using public key Y .
/// (HEG is defined in B. Schoenmakers and P. Tuyls. Practical Two-Party Computation Based on the Conditional Gate)
/// Specifically, the witness is ω = (x, r), the statement is δ = (G, H, Y, D, E).
/// The relation R outputs 1 if D = xH+rY , E = rG (for the case of G=H this is ElGamal)
///
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct HomoELGamalProof {
    pub T: GE,
    pub A3: GE,
    pub z1: FE,
    pub z2: FE,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct HomoElGamalWitness {
    pub r: FE,
    pub x: FE,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct HomoElGamalStatement {
    pub G: GE,
    pub H: GE,
    pub Y: GE,
    pub D: GE,
    pub E: GE,
}

impl HomoELGamalProof {
    pub fn prove(w: &HomoElGamalWitness, delta: &HomoElGamalStatement) -> HomoELGamalProof {
        let mut s1: FE = ECScalar::new_random();
        let mut s2: FE = ECScalar::new_random();
        let mut A1 = delta.H.clone() * s1.clone();
        let mut A2 = delta.Y.clone() * s2.clone();
        let A3 = delta.G.clone() * s2.clone();
        let T = A1.clone() + A2.clone();
        let e = HSha256::create_hash_from_ge(&[
            &T, &A3, &delta.G, &delta.H, &delta.Y, &delta.D, &delta.E,
        ]);
        // dealing with zero field element
        let z1 = if w.x.clone() != FE::zero() {
            s1.clone() + w.x.clone() * e.clone()
        } else {
            s1.clone()
        };
        let z2 = s2.clone() + w.r.clone() * e.clone();
        s1.zeroize();
        s2.zeroize();
        A1.zeroize();
        A2.zeroize();
        HomoELGamalProof { T, A3, z1, z2 }
    }
    pub fn verify(&self, delta: &HomoElGamalStatement) -> Result<(), ProofError> {
        let e = HSha256::create_hash_from_ge(&[
            &self.T.clone(),
            &self.A3.clone(),
            &delta.G.clone(),
            &delta.H.clone(),
            &delta.Y.clone(),
            &delta.D.clone(),
            &delta.E.clone(),
        ]);
        let z1H_plus_z2Y = delta.H.clone() * self.z1.clone() + delta.Y.clone() * self.z2.clone();
        let T_plus_eD = self.T.clone() + delta.D.clone() * e.clone();
        let z2G = delta.G.clone() * self.z2.clone();
        let A3_plus_eE = self.A3.clone() + delta.E.clone() * e.clone();
        if z1H_plus_z2Y == T_plus_eD && z2G == A3_plus_eE {
            Ok(())
        } else {
            Err(ProofError)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::*;
    use crate::curv::cryptographic_primitives::proofs::PROOF_ERROR_DESCRIPTION;
    use crate::curv::elliptic::curves::secp256_k1::{FE, GE};
    use std::error::Error;

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::*;

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    #[test]
    fn test_correct_general_homo_elgamal() {
        let witness = HomoElGamalWitness {
            r: ECScalar::new_random(),
            x: ECScalar::new_random(),
        };
        let G: GE = ECPoint::generator();
        let h: FE = ECScalar::new_random();
        let H = &G * &h;
        let y: FE = ECScalar::new_random();
        let Y = &G * &y;
        let D = &H * &witness.x + Y.clone() * &witness.r;
        let E = G.clone() * &witness.r;
        let delta = HomoElGamalStatement { G, H, Y, D, E };
        let proof = HomoELGamalProof::prove(&witness, &delta);
        assert!(proof.verify(&delta).is_ok());
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    #[test]
    fn test_correct_homo_elgamal() {
        let witness = HomoElGamalWitness {
            r: FE::new_random(),
            x: FE::new_random(),
        };
        let G: GE = GE::generator();
        let y: FE = FE::new_random();
        let Y = &G * &y;
        let D = &G * &witness.x + Y.clone() * &witness.r;
        let E = G.clone() * &witness.r;
        let delta = HomoElGamalStatement {
            G: G.clone(),
            H: G,
            Y,
            D,
            E,
        };
        let proof = HomoELGamalProof::prove(&witness, &delta);
        assert!(proof.verify(&delta).is_ok());
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    #[test]
    fn test_wrong_homo_elgamal() {
        // test for E = (r+1)G
        let witness = HomoElGamalWitness {
            r: ECScalar::new_random(),
            x: ECScalar::new_random(),
        };
        let G: GE = ECPoint::generator();
        let h: FE = ECScalar::new_random();
        let H = &G * &h;
        let y: FE = ECScalar::new_random();
        let Y = &G * &y;
        let D = &H * &witness.x + Y.clone() * &witness.r;
        let E = &G * &witness.r + G.clone();
        let delta = HomoElGamalStatement { G, H, Y, D, E };
        let proof = HomoELGamalProof::prove(&witness, &delta);
        let result = proof.verify(&delta);
        assert_eq!(result.unwrap_err().description(), PROOF_ERROR_DESCRIPTION);
    }
}
