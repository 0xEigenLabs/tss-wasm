#[macro_use]
#[cfg(not(target_arch = "wasm32"))]
extern crate criterion;

#[cfg(target_arch = "wasm32")]
extern crate wasm_bindgen;

#[cfg(all(test, target_arch = "wasm32"))]
extern crate wasm_bindgen_test;

mod common;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::*;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[test]
fn test_keygen_t1_n2() {
    common::keygen_t_n_parties(1, 2);
}

/* TODO: comment to speed up CI
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[test]
fn test_keygen_t2_n3() {
    common::keygen_t_n_parties(2, 3);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[test]
fn test_keygen_t2_n4() {
    common::keygen_t_n_parties(2, 4);
}
*/

#[cfg(not(target_arch = "wasm32"))]
pub mod bench {
    use criterion::Criterion;

    pub fn bench_full_keygen_party_one_two(c: &mut Criterion) {
        c.bench_function("keygen t=1 n=2", move |b| {
            b.iter(|| {
                super::common::keygen_t_n_parties(1, 2);
            })
        });
    }

    pub fn bench_full_keygen_party_two_three(c: &mut Criterion) {
        c.bench_function("keygen t=2 n=3", move |b| {
            b.iter(|| {
                super::common::keygen_t_n_parties(2, 3);
            })
        });
    }

    criterion_group! {
    name = keygen;
    config = Criterion::default().sample_size(super::common::BENCH_SAMPLE_SIZE);
    targets =
    self::bench_full_keygen_party_one_two,
    self::bench_full_keygen_party_two_three
    }
}

#[cfg(not(target_arch = "wasm32"))]
criterion_main!(bench::keygen);
