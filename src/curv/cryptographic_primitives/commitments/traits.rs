/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: https://github.com/KZen-networks/curv/blob/master/LICENSE
*/

use crate::curv::arithmetic::num_bigint::BigInt;

pub trait Commitment<T> {
    fn create_commitment_with_user_defined_randomness(
        message: &BigInt,
        blinding_factor: &BigInt,
    ) -> T;

    fn create_commitment(message: &BigInt) -> (T, BigInt);
}
