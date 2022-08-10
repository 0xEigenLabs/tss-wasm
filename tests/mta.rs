#![allow(non_snake_case)]

/*
Multi-party ECDSA

Copyright 2018 by Kzen Networks

This file is part of Multi-party ECDSA library
(https://github.com/KZen-networks/multi-party-ecdsa)

Multi-party ECDSA is free software: you can redistribute
it and/or modify it under the terms of the GNU General Public
License as published by the Free Software Foundation, either
version 3 of the License, or (at your option) any later version.

@license GPL-3.0+ <https://github.com/KZen-networks/multi-party-ecdsa/blob/master/LICENSE>
*/
#[cfg(target_arch = "wasm32")]
extern crate wasm_bindgen;

#[cfg(all(test, target_arch = "wasm32"))]
extern crate wasm_bindgen_test;

extern crate emerald_city;

use emerald_city::curv::elliptic::curves::secp256_k1::FE;
use emerald_city::curv::elliptic::curves::traits::*;

use emerald_city::gg_2018::mta::*;
use emerald_city::paillier::*;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::*;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[test]
fn test_mta() {
    let alice_input: FE = ECScalar::new_random();
    let keypair = Paillier::keypair();
    let (ek_alice, dk_alice) = keypair.keys();
    /*
            let p = str::parse("148677972634832330983979593310074301486537017973460461278300587514468301043894574906886127642530475786889672304776052879927627556769456140664043088700743909632312483413393134504352834240399191134336344285483935856491230340093391784574980688823380828143810804684752914935441384845195613674104960646037368551517").unwrap();
            let q = str::parse("158741574437007245654463598139927898730476924736461654463975966787719309357536545869203069369466212089132653564188443272208127277664424448947476335413293018778018615899291704693105620242763173357203898195318179150836424196645745308205164116144020613415407736216097185962171301808761138424668335445923774195463").unwrap();
            let keypair = Keypair { p, q };
            let (ek_alice, dk_alice) = keypair.keys();
    */
    let bob_input: FE = ECScalar::new_random();
    let (m_a, _) = MessageA::a(&alice_input, &ek_alice, &[]);
    let (m_b, beta, _, _) = MessageB::b(&bob_input, &ek_alice, m_a, &[]).unwrap();
    let alpha = m_b
        .verify_proofs_get_alpha(&dk_alice, &alice_input)
        .expect("wrong dlog or m_b");

    let left = alpha.0 + beta;
    let right = alice_input * bob_input;
    assert_eq!(left.get_element(), right.get_element());
}
