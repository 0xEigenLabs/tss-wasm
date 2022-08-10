pub mod core;
pub mod encoding;
pub mod keygen;
pub mod traits;
pub mod zkproofs;

pub use crate::paillier::core::*;
pub use crate::paillier::encoding::*;
pub use crate::paillier::keygen::*;
pub use crate::paillier::traits::*;

use std::borrow::Cow;

/// Main struct onto which most operations are added.
pub struct Paillier;

pub use crate::curv::arithmetic::num_bigint::BigInt;
/// Keypair from which encryption and decryption keys can be derived.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Keypair {
    pub p: BigInt, // TODO[Morten] okay to make non-public?

    pub q: BigInt, // TODO[Morten] okay to make non-public?
}

/// Public encryption key with no precomputed values.
///
/// Used e.g. for serialization of `EncryptionKey`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MinimalEncryptionKey {
    pub n: BigInt,
}

/// Private decryption key with no precomputed values.
///
/// Used e.g. for serialization of `DecryptionKey`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MinimalDecryptionKey {
    pub p: BigInt,

    pub q: BigInt,
}

/// Public encryption key.
#[derive(Clone, Debug, PartialEq)]
pub struct EncryptionKey {
    pub n: BigInt,  // the modulus
    pub nn: BigInt, // the modulus squared
}

/// Private decryption key.
#[derive(Clone, Debug, PartialEq)]
pub struct DecryptionKey {
    pub p: BigInt, // first prime
    pub q: BigInt, // second prime
}

/// Unencrypted message without type information.
///
/// Used mostly for internal purposes and advanced use-cases.
#[derive(Clone, Debug, PartialEq)]
pub struct RawPlaintext<'b>(pub Cow<'b, BigInt>);

/// Encrypted message without type information.
///
/// Used mostly for internal purposes and advanced use-cases.
#[derive(Clone, Debug, PartialEq)]
pub struct RawCiphertext<'b>(pub Cow<'b, BigInt>);
