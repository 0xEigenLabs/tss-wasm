use super::traits::*;
use num_bigint::BigUint;
use num_integer::Integer;
use rand::thread_rng;

use num_bigint::BigInt as BN;
use num_bigint::RandBigInt;
use num_bigint::ToBigInt;
use num_traits::cast::ToPrimitive;
use num_traits::identities::Zero;
use num_traits::Num;
use num_traits::One;
use std::ops::{BitAnd, BitOr, Shl};

impl Samplable for BigUint {
    fn sample_below(upper: &Self) -> Self {
        let mut rng = thread_rng();
        rng.gen_biguint_below(upper)
    }

    fn sample(bitsize: usize) -> Self {
        let mut rng = thread_rng();
        rng.gen_biguint(bitsize)
    }

    fn sample_range(lower: &Self, upper: &Self) -> Self {
        let mut rng = thread_rng();
        rng.gen_biguint_range(lower, upper)
    }
}

impl NumberTests for BigUint {
    fn is_zero(me: &Self) -> bool {
        me.eq(&BigUint::zero())
    }
    fn is_even(me: &Self) -> bool {
        (me % BigUint::from(2 as u32)).eq(&BigUint::zero())
    }
    fn is_negative(me: &Self) -> bool {
        me < &BigUint::zero()
    }
}

impl Modulo for BigUint {
    fn mod_pow(base: &Self, exponent: &Self, modulus: &Self) -> Self {
        base.modpow(&exponent, &modulus)
    }

    fn mod_mul(a: &Self, b: &Self, modulus: &Self) -> Self {
        (a.mod_floor(modulus) * b.mod_floor(modulus)).mod_floor(modulus)
    }

    fn mod_sub(a: &Self, b: &Self, modulus: &Self) -> Self {
        let a_m = a.mod_floor(modulus);
        let b_m = b.mod_floor(modulus);

        let sub_op: BigUint = (a_m + modulus) - b_m;
        sub_op.mod_floor(modulus)
    }

    fn mod_add(a: &Self, b: &Self, modulus: &Self) -> Self {
        (a.mod_floor(modulus) + b.mod_floor(modulus)).mod_floor(modulus)
    }

    fn mod_inv(a: &Self, modulus: &Self) -> Self {
        let x = egcd(a, modulus).1; //[d,x,y]
        let x_ubn = x
            .mod_floor(&modulus.to_bigint().unwrap())
            .to_biguint()
            .unwrap();
        x_ubn
    }

    fn mod_test(a: &Self, modulus: &Self) -> (Self, Self, Self) {
        let (gcd1, x1, y1) = egcd(a, modulus);
        let gcd = gcd1.to_biguint().unwrap();
        let x = x1
            .mod_floor(&modulus.to_bigint().unwrap())
            .to_biguint()
            .unwrap();
        let y = y1
            .mod_floor(&modulus.to_bigint().unwrap())
            .to_biguint()
            .unwrap();
        (gcd, x, y)
    }
}

fn egcd(a: &BigUint, b: &BigUint) -> (BN, BN, BN) {
    let mut a = a.clone().to_bigint().unwrap();
    let mut b = b.clone().to_bigint().unwrap();

    let mut ua = BN::one();
    let mut va = BN::zero();

    let mut ub = BN::zero();
    let mut vb = BN::one();

    let mut q;
    let mut tmp;
    let mut r;

    while !b.is_zero() {
        q = &a / &b;

        r = &a % &b;

        a = b;
        b = r;

        tmp = ua;
        ua = ub.clone();
        ub = tmp - &q * &ub;

        tmp = va;
        va = vb.clone();
        vb = tmp - &q * &vb;
    }
    (a, ua, va)
}
impl ConvertFrom<BigUint> for usize {
    fn _from(x: &BigUint) -> usize {
        x.to_usize().unwrap()
    }
}

impl ConvertFrom<BigUint> for u8 {
    fn _from(x: &BigUint) -> u8 {
        x.to_u8().unwrap()
    }
}

impl ConvertFrom<BigUint> for u16 {
    fn _from(x: &BigUint) -> u16 {
        x.to_u16().unwrap()
    }
}

impl ConvertFrom<BigUint> for u32 {
    fn _from(x: &BigUint) -> u32 {
        x.to_u32().unwrap()
    }
}

impl ConvertFrom<BigUint> for u64 {
    fn _from(x: &BigUint) -> u64 {
        x.to_u64().unwrap()
    }
}

impl ConvertFrom<BigUint> for i8 {
    fn _from(x: &BigUint) -> i8 {
        x.to_i8().unwrap()
    }
}

impl ConvertFrom<BigUint> for i16 {
    fn _from(x: &BigUint) -> i16 {
        x.to_i16().unwrap()
    }
}

impl ConvertFrom<BigUint> for i32 {
    fn _from(x: &BigUint) -> i32 {
        x.to_i32().unwrap()
    }
}

impl ConvertFrom<BigUint> for i64 {
    fn _from(x: &BigUint) -> i64 {
        x.to_i64().unwrap()
    }
}

/*
impl<'a> ConvertFrom<&'a [u8]> for BigUint {
    fn _from(other: &&'a [u8]) -> BigUint {
        BigInt::from_slice(*other as &[u32])
    }
}
*/

pub fn from(bytes: &[u8]) -> BigInt {
    BigInt::from_bytes_be(bytes)
}

impl BitManipulation for BigUint {
    fn set_bit(&self, bit: usize, bit_val: bool) -> BigUint {
        let one = BigInt::from(1 as u16);
        let one_shl = one.shl(bit);
        if bit_val == false {
            return self.bitand(&one_shl);
        } else {
            return self.bitor(&one_shl);
        }
    }

    fn test_bit(self: &Self, _bit: usize) -> bool {
        return true; //stub
    }
}

pub type BigInt = BigUint;

/*
impl Serialize for BigInt {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
    {
        serializer.serialize_str(&self.to_str_radix(16))
    }
}

impl<'de> Deserialize<'de> for BigInt {
    fn deserialize<D>(deserializer: D) -> Result<BigInt, D::Error>
        where
            D: Deserializer<'de>,
    {
        deserializer.deserialize_str(BigUintVisitor)
    }
}

struct BigUintVisitor;

impl<'de> Visitor<'de> for BigUintVisitor {
    type Value = BigUint;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Secp256k1Scalar")
    }

    fn visit_str<E: de::Error>(self, s: &str) -> Result<BigInt, E> {
        let v = BigInt::from_str_radix(s, 16).expect("Failed in serde");
        Ok(v)
    }
}
*/

impl Converter for BigUint {
    fn to_bytes(value: &BigUint) -> Vec<u8> {
        let bytes: Vec<u8> = value.to_bytes_be();
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        BigUint::from_bytes_be(bytes)
    }

    fn to_vec(value: &BigUint) -> Vec<u8> {
        let bytes: Vec<u8> = value.to_bytes_be();

        bytes
    }

    fn to_hex(&self) -> String {
        self.to_str_radix(16)
    }

    fn from_hex(value: &str) -> BigUint {
        BigInt::from_str_radix(value, 16).expect("Error in serialization")
    }
}

/*
impl BasicOps for BigInt {
    fn pow(&self, exponent: u32) -> Self {
        self.num.pow(exponent).wrap()
    }

    fn mul(&self, other: &Self) -> Self {
        self * other
    }

    fn sub(&self, other: &Self) -> Self {
        self - other
    }

    fn add(&self, other: &Self) -> Self {
        self + other
    }

    fn abs(&self) -> Self {
        self.num.abs().wrap()
    }
}
*/
