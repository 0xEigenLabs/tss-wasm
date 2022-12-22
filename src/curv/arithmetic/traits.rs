/*
    Cryptography utilities

    Copyright 2018 by Kzen Networks

    This file is part of Cryptography utilities library
    (https://github.com/KZen-networks/cryptography-utils)

    Cryptography utilities is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/cryptography-utils/blob/master/LICENSE>
*/

use num_bigint::BigUint;
use std::marker::Sized;

pub trait Converter {
    fn to_vec(n: &Self) -> Vec<u8>;
    fn to_hex(&self) -> String;
    fn from_hex(n: &str) -> Self;

    fn to_bytes(value: &BigUint) -> Vec<u8>;
    fn from_bytes(bytes: &[u8]) -> Self;
}

pub trait Modulo {
    fn mod_pow(base: &Self, exponent: &Self, modulus: &Self) -> Self;
    fn mod_mul(a: &Self, b: &Self, modulus: &Self) -> Self;
    fn mod_sub(a: &Self, b: &Self, modulus: &Self) -> Self;
    fn mod_add(a: &Self, b: &Self, modulus: &Self) -> Self;
    fn mod_inv(a: &Self, modulus: &Self) -> Self;
    fn mod_test(a: &Self, modulus: &Self) -> (Self, Self, Self) where Self: Sized;
}

pub trait Samplable {
    fn sample_below(upper: &Self) -> Self;
    fn sample_range(lower: &Self, upper: &Self) -> Self;
    fn sample(bitsize: usize) -> Self;
}

pub trait NumberTests {
    fn is_zero(_: &Self) -> bool;
    fn is_even(_: &Self) -> bool;
    fn is_negative(me: &Self) -> bool;
}

pub trait EGCD
where
    Self: Sized,
{
    fn egcd(a: &Self, b: &Self) -> (Self, Self, Self);
}

pub trait BitManipulation {
    fn set_bit(&self, bit: usize, bit_val: bool) -> Self;
    fn test_bit(self: &Self, bit: usize) -> bool;
}

pub trait ConvertFrom<T> {
    fn _from(_: &T) -> Self;
}
//use std::ops::{Add, Div, Mul, Neg, Rem, Shr, Sub};
/// Provides basic arithmetic operators for BigInt
///
/// Note that BigInt also implements std::ops::{Add, Mull, ...} traits, so you can
/// use them instead.
pub trait BasicOps {
    fn pow(&self, exponent: u32) -> Self;
    fn mul(&self, other: &Self) -> Self;
    fn sub(&self, other: &Self) -> Self;
    fn add(&self, other: &Self) -> Self;
    fn abs(&self) -> Self;
}
