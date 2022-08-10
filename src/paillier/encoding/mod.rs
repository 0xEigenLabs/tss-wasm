//! Various coding schemes to be used in conjunction with the core Paillier encryption scheme.

use std::marker::PhantomData;

use crate::curv::arithmetic::num_bigint::BigInt;
use crate::curv::arithmetic::traits::ConvertFrom;
pub mod integral;
use num_traits::One;

/// Encrypted message with type information.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EncodedCiphertext<T> {
    raw: BigInt,

    components: usize,

    _phantom: PhantomData<T>,
}

fn pack<T>(components: &[T], component_bitsize: usize) -> BigInt
where
    BigInt: From<T>,
    T: Copy,
{
    let mut packed = BigInt::from(components[0]);
    for component in &components[1..] {
        packed = packed << component_bitsize;
        packed = packed + BigInt::from(*component);
    }
    packed
}

fn unpack<T>(
    mut packed_components: BigInt,
    component_bitsize: usize,
    component_count: usize,
) -> Vec<T>
where
    T: ConvertFrom<BigInt>,
{
    let mask = BigInt::one() << component_bitsize;
    let mut components: Vec<T> = vec![];
    for _ in 0..component_count {
        let raw_component = &packed_components % &mask; // TODO replace with bitwise AND
        let component = T::_from(&raw_component);
        components.push(component);
        packed_components = &packed_components >> component_bitsize;
    }
    components.reverse();
    components
}

#[cfg(test)]
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::*;

#[cfg(test)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[test]
fn test_pack() {
    let v: Vec<u64> = vec![1, 2, 3];

    let component_bitsize = 64;

    let packed = pack(&*v, component_bitsize);
    assert_eq!(
        packed,
        BigInt::from(1 as u32) * (BigInt::from(1 as u32) << 2 * component_bitsize)
            + BigInt::from(2 as u32) * (BigInt::from(1 as u32) << 1 * component_bitsize)
            + BigInt::from(3 as u32) * (BigInt::from(1 as u32) << 0 * component_bitsize)
    );

    let unpacked: Vec<u64> = unpack(packed, component_bitsize, 3);
    assert_eq!(unpacked, v);
}
