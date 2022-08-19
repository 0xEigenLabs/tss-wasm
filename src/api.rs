#![cfg(target_arch = "wasm32")]

use crate::log;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};

use crate::gg_2018::mta::*;
use crate::gg_2018::party_i::*;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use reqwest::Client;

use crate::curv::elliptic::curves::traits::{ECPoint, ECScalar};
use crate::curv::{
    arithmetic::num_bigint::BigInt,
    arithmetic::traits::ConvertFrom,
    arithmetic::traits::Converter,
    cryptographic_primitives::{
        proofs::sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof,
        proofs::sigma_dlog::DLogProof, secret_sharing::feldman_vss::VerifiableSS,
    },
    elliptic::curves::secp256_k1::{Secp256k1Point as Point, Secp256k1Scalar as Scalar},
};
use crate::paillier::traits::EncryptWithChosenRandomness;

use crate::paillier::EncryptionKey;
use sha2::Sha256;
use std::{fs, time};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GG18KeygenClientContext {
    addr: String,
    params: Parameters,
    party_num_int: u16,
    uuid: String,
    bc1_vec: Option<Vec<KeyGenBroadcastMessage1>>,
    decom_i: Option<KeyGenDecommitMessage1>,
    party_keys: Option<Keys>,
    y_sum: Option<crate::curv::elliptic::curves::secp256_k1::Secp256k1Point>,
    vss_scheme: Option<VerifiableSS>,
    secret_shares: Option<Vec<crate::curv::elliptic::curves::secp256_k1::Secp256k1Scalar>>,
    enc_keys: Option<Vec<Vec<u8>>>,
    party_shares: Option<Vec<Scalar>>,
    point_vec: Option<Vec<Point>>,
    dlog_proof: Option<DLogProof>,
    shared_keys: Option<SharedKeys>,
    vss_scheme_vec: Option<Vec<VerifiableSS>>,
}

fn new_client_with_headers() -> Client {
    let mut headers = HeaderMap::new();
    headers.insert(
        "Content-Type",
        HeaderValue::from_static("Content-Type:application/json; charset=utf-8"),
    );
    headers.insert(
        "Accept",
        HeaderValue::from_static("application/json; charset=utf-8"),
    );

    reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .unwrap()
}

#[wasm_bindgen]
pub async fn gg18_keygen_client_new_context(addr: String, t: usize, n: usize) -> String {
    let client = new_client_with_headers();
    let params = Parameters {
        threshold: t,
        share_count: n,
    };

    let (party_num_int, uuid) = match signup(&client, &addr).await.unwrap() {
        PartySignup { number, uuid } => (number, uuid),
    };

    serde_json::to_string(&GG18KeygenClientContext {
        addr,
        params,
        party_num_int,
        uuid,
        bc1_vec: None,
        decom_i: None,
        party_keys: None,
        y_sum: None,
        vss_scheme: None,
        secret_shares: None,
        enc_keys: None,
        party_shares: None,
        point_vec: None,
        dlog_proof: None,
        shared_keys: None,
        vss_scheme_vec: None,
    })
    .unwrap()
}

#[wasm_bindgen]
pub async fn gg18_keygen_client_round1(context: String) -> String {
    let mut context = serde_json::from_str::<GG18KeygenClientContext>(&context).unwrap();
    let client = reqwest::Client::new();
    let party_keys = Keys::create(context.party_num_int as usize);
    let (bc_i, decom_i) = party_keys.phase1_broadcast_phase3_proof_of_correct_key();

    assert!(broadcast(
        &client,
        &context.addr,
        context.party_num_int,
        "round1",
        serde_json::to_string(&bc_i).unwrap(),
        context.uuid.clone()
    )
    .await
    .is_ok());

    let round1_ans_vec = poll_for_broadcasts(
        &client,
        &context.addr,
        context.party_num_int,
        context.params.share_count as u16,
        "round1",
        context.uuid.clone(),
    )
    .await;

    let mut bc1_vec = round1_ans_vec
        .iter()
        .map(|m| serde_json::from_str::<KeyGenBroadcastMessage1>(m).unwrap())
        .collect::<Vec<_>>();

    bc1_vec.insert(context.party_num_int as usize - 1, bc_i);

    context.bc1_vec = Some(bc1_vec);
    context.party_keys = Some(party_keys);
    context.decom_i = Some(decom_i);

    serde_json::to_string(&context).unwrap()
}

#[wasm_bindgen]
pub async fn gg18_keygen_client_round2(context: String) -> String {
    let mut context = serde_json::from_str::<GG18KeygenClientContext>(&context).unwrap();
    let client = reqwest::Client::new();
    // send ephemeral public keys and check commitments correctness
    assert!(broadcast(
        &client,
        &context.addr,
        context.party_num_int,
        "round2",
        serde_json::to_string(&context.decom_i.as_ref().unwrap()).unwrap(),
        context.uuid.clone()
    )
    .await
    .is_ok());

    let round2_ans_vec = poll_for_broadcasts(
        &client,
        &context.addr,
        context.party_num_int,
        context.params.share_count as u16,
        "round2",
        context.uuid.clone(),
    )
    .await;

    let mut j = 0;
    let mut point_vec: Vec<Point> = Vec::new();
    let mut decom_vec: Vec<KeyGenDecommitMessage1> = Vec::new();
    let mut enc_keys: Vec<Vec<u8>> = Vec::new();
    for i in 1..=context.params.share_count as u16 {
        if i == context.party_num_int {
            point_vec.push(context.decom_i.as_ref().unwrap().y_i.clone());
            decom_vec.push(context.decom_i.as_ref().unwrap().clone());
        } else {
            let decom_j: KeyGenDecommitMessage1 = serde_json::from_str(&round2_ans_vec[j]).unwrap();
            point_vec.push(decom_j.y_i.clone());
            decom_vec.push(decom_j.clone());
            let key_bn: BigInt = (decom_j.y_i.clone()
                * context.party_keys.as_ref().unwrap().u_i.clone())
            .x_coor()
            .unwrap();
            let key_bytes = BigInt::to_vec(&key_bn);
            let mut template: Vec<u8> = vec![0u8; AES_KEY_BYTES_LEN - key_bytes.len()];
            template.extend_from_slice(&key_bytes[..]);
            enc_keys.push(template);
            j += 1;
        }
    }

    let (head, tail) = point_vec.split_at(1);
    let y_sum = tail.iter().fold(head[0].clone(), |acc, x| acc + x);

    let (vss_scheme, secret_shares, _index) = context
        .party_keys
        .as_ref()
        .unwrap()
        .phase1_verify_com_phase3_verify_correct_key_phase2_distribute(
            &context.params,
            &decom_vec,
            &(context.bc1_vec.as_ref().unwrap()),
        )
        .expect("invalid key");

    context.y_sum = Some(y_sum);
    context.vss_scheme = Some(vss_scheme);
    context.secret_shares = Some(secret_shares);
    context.enc_keys = Some(enc_keys);
    context.point_vec = Some(point_vec);

    serde_json::to_string(&context).unwrap()
}

#[wasm_bindgen]
pub async fn gg18_keygen_client_round3(context: String) -> String {
    let mut context = serde_json::from_str::<GG18KeygenClientContext>(&context).unwrap();
    let client = reqwest::Client::new();
    let mut j = 0;
    for (k, i) in (1..=context.params.share_count as u16).enumerate() {
        if i != context.party_num_int {
            // prepare encrypted ss for party i:
            let key_i = &context.enc_keys.as_ref().unwrap()[j];
            let plaintext =
                BigInt::to_vec(&context.secret_shares.as_ref().unwrap()[k].to_big_int());
            let aead_pack_i = aes_encrypt(key_i, &plaintext);
            assert!(sendp2p(
                &client,
                &context.addr,
                context.party_num_int,
                i,
                "round3",
                serde_json::to_string(&aead_pack_i).unwrap(),
                context.uuid.clone()
            )
            .await
            .is_ok());
            j += 1;
        }
    }

    let round3_ans_vec = poll_for_p2p(
        &client,
        &context.addr,
        context.party_num_int,
        context.params.share_count as u16,
        "round3",
        context.uuid.clone(),
    )
    .await;

    let mut j = 0;
    let mut party_shares: Vec<Scalar> = Vec::new();
    for i in 1..=context.params.share_count as u16 {
        if i == context.party_num_int {
            party_shares.push(context.secret_shares.as_ref().unwrap()[(i - 1) as usize].clone());
        } else {
            let aead_pack: AEAD = serde_json::from_str(&round3_ans_vec[j]).unwrap();
            let key_i = &context.enc_keys.as_ref().unwrap()[j];
            let out = aes_decrypt(key_i, aead_pack);
            let out_bn = BigInt::from_bytes_be(&out[..]);
            let out_fe = ECScalar::from(&out_bn);
            party_shares.push(out_fe);

            j += 1;
        }
    }

    context.party_shares = Some(party_shares);

    serde_json::to_string(&context).unwrap()
}

#[wasm_bindgen]
pub async fn gg18_keygen_client_round4(context: String) -> String {
    let mut context = serde_json::from_str::<GG18KeygenClientContext>(&context).unwrap();
    let client = reqwest::Client::new();
    assert!(broadcast(
        &client,
        &context.addr,
        context.party_num_int,
        "round4",
        serde_json::to_string(&context.vss_scheme.as_ref().unwrap()).unwrap(),
        context.uuid.clone()
    )
    .await
    .is_ok());
    let round4_ans_vec = poll_for_broadcasts(
        &client,
        &context.addr,
        context.party_num_int,
        context.params.share_count as u16,
        "round4",
        context.uuid.clone(),
    )
    .await;

    let mut j = 0;
    let mut vss_scheme_vec: Vec<VerifiableSS> = Vec::new();
    for i in 1..=context.params.share_count as u16 {
        if i == context.party_num_int {
            vss_scheme_vec.push(context.vss_scheme.as_ref().unwrap().clone());
        } else {
            let vss_scheme_j: VerifiableSS = serde_json::from_str(&round4_ans_vec[j]).unwrap();
            vss_scheme_vec.push(vss_scheme_j);
            j += 1;
        }
    }

    let (shared_keys, dlog_proof) = context
        .party_keys
        .as_ref()
        .unwrap()
        .phase2_verify_vss_construct_keypair_phase3_pok_dlog(
            &context.params,
            &context.point_vec.as_ref().unwrap(),
            &context.party_shares.as_ref().unwrap(),
            &vss_scheme_vec,
            &(context.party_num_int.clone() as usize), // FIXME
        )
        .expect("invalid vss");

    context.shared_keys = Some(shared_keys);
    context.dlog_proof = Some(dlog_proof);
    context.vss_scheme_vec = Some(vss_scheme_vec);

    serde_json::to_string(&context).unwrap()
}

#[wasm_bindgen]
pub async fn gg18_keygen_client_round5(context: String) -> String {
    let context = serde_json::from_str::<GG18KeygenClientContext>(&context).unwrap();
    let client = reqwest::Client::new();
    assert!(broadcast(
        &client,
        &context.addr,
        context.party_num_int,
        "round5",
        serde_json::to_string(&context.dlog_proof.as_ref().unwrap()).unwrap(),
        context.uuid.clone()
    )
    .await
    .is_ok());
    let round5_ans_vec = poll_for_broadcasts(
        &client,
        &context.addr,
        context.party_num_int,
        context.params.share_count as u16,
        "round5",
        context.uuid.clone(),
    )
    .await;

    let mut j = 0;
    let mut dlog_proof_vec: Vec<DLogProof> = Vec::new();
    for i in 1..=context.params.share_count as u16 {
        if i == context.party_num_int {
            dlog_proof_vec.push(context.dlog_proof.as_ref().unwrap().clone());
        } else {
            let dlog_proof_j: DLogProof = serde_json::from_str(&round5_ans_vec[j]).unwrap();
            dlog_proof_vec.push(dlog_proof_j);
            j += 1;
        }
    }
    Keys::verify_dlog_proofs(
        &context.params,
        &dlog_proof_vec,
        &context.point_vec.as_ref().unwrap(),
    )
    .expect("bad dlog proof");

    //save key to file:
    let paillier_key_vec = (0..context.params.share_count as u16)
        .map(|i| context.bc1_vec.as_ref().unwrap()[i as usize].e.clone())
        .collect::<Vec<EncryptionKey>>();

    let keygen_json = serde_json::to_string(&(
        context.party_keys.as_ref().unwrap(),
        context.shared_keys.as_ref().unwrap(),
        context.party_num_int,
        context.vss_scheme_vec.as_ref().unwrap(),
        paillier_key_vec,
        context.y_sum.as_ref().unwrap(),
    ))
    .unwrap();

    keygen_json
}

use crate::common::{
    aes_decrypt, aes_encrypt, broadcast, poll_for_broadcasts, poll_for_p2p, postb, sendp2p, Entry,
    Params, PartySignup, AEAD, AES_KEY_BYTES_LEN,
};

pub async fn signup(client: &Client, addr: &str) -> Result<PartySignup, ()> {
    let key = "signup-keygen".to_string();
    let res_body = postb(client, addr, "signupkeygen", key).await.unwrap();
    serde_json::from_str(&res_body).unwrap()
}

#[wasm_bindgen]
pub async fn gg18_keygen(t: usize, n: usize) -> String {
    let client = new_client_with_headers();
    let addr = "http://127.0.0.1:8000";
    let params = Parameters {
        threshold: t,
        share_count: n.clone(),
    };

    let PARTIES = n.clone() as u16;

    let (party_num_int, uuid) = match signup(&client, addr).await.unwrap() {
        PartySignup { number, uuid } => (number, uuid),
    };

    let party_keys = Keys::create(party_num_int as usize);
    let (bc_i, decom_i) = party_keys.phase1_broadcast_phase3_proof_of_correct_key();

    assert!(broadcast(
        &client,
        addr,
        party_num_int,
        "round1",
        serde_json::to_string(&bc_i).unwrap(),
        uuid.clone()
    )
    .await
    .is_ok());

    let round1_ans_vec = poll_for_broadcasts(
        &client,
        addr,
        party_num_int,
        PARTIES,
        "round1",
        uuid.clone(),
    )
    .await;

    let mut bc1_vec = round1_ans_vec
        .iter()
        .map(|m| serde_json::from_str::<KeyGenBroadcastMessage1>(m).unwrap())
        .collect::<Vec<_>>();

    bc1_vec.insert(party_num_int as usize - 1, bc_i);

    // send ephemeral public keys and check commitments correctness
    assert!(broadcast(
        &client,
        addr,
        party_num_int,
        "round2",
        serde_json::to_string(&decom_i).unwrap(),
        uuid.clone()
    )
    .await
    .is_ok());

    let round2_ans_vec = poll_for_broadcasts(
        &client,
        addr,
        party_num_int,
        PARTIES,
        "round2",
        uuid.clone(),
    )
    .await;

    let mut j = 0;
    let mut point_vec: Vec<Point> = Vec::new();
    let mut decom_vec: Vec<KeyGenDecommitMessage1> = Vec::new();
    let mut enc_keys: Vec<Vec<u8>> = Vec::new();
    for i in 1..=PARTIES {
        if i == party_num_int {
            point_vec.push(decom_i.y_i.clone());
            decom_vec.push(decom_i.clone());
        } else {
            let decom_j: KeyGenDecommitMessage1 = serde_json::from_str(&round2_ans_vec[j]).unwrap();
            point_vec.push(decom_j.y_i.clone());
            decom_vec.push(decom_j.clone());
            let key_bn: BigInt = (decom_j.y_i.clone() * party_keys.u_i.clone())
                .x_coor()
                .unwrap();
            let key_bytes = BigInt::to_vec(&key_bn);
            let mut template: Vec<u8> = vec![0u8; AES_KEY_BYTES_LEN - key_bytes.len()];
            template.extend_from_slice(&key_bytes[..]);
            enc_keys.push(template);
            j += 1;
        }
    }

    let (head, tail) = point_vec.split_at(1);
    let y_sum = tail.iter().fold(head[0].clone(), |acc, x| acc + x);

    let (vss_scheme, secret_shares, _index) = party_keys
        .phase1_verify_com_phase3_verify_correct_key_phase2_distribute(
            &params, &decom_vec, &bc1_vec,
        )
        .expect("invalid key");

    //////////////////////////////////////////////////////////////////////////////

    let mut j = 0;
    for (k, i) in (1..=PARTIES).enumerate() {
        if i != party_num_int {
            // prepare encrypted ss for party i:
            let key_i = &enc_keys[j];
            let plaintext = BigInt::to_vec(&secret_shares[k].to_big_int());
            let aead_pack_i = aes_encrypt(key_i, &plaintext);
            assert!(sendp2p(
                &client,
                addr,
                party_num_int,
                i,
                "round3",
                serde_json::to_string(&aead_pack_i).unwrap(),
                uuid.clone()
            )
            .await
            .is_ok());
            j += 1;
        }
    }

    let round3_ans_vec = poll_for_p2p(
        &client,
        addr,
        party_num_int,
        PARTIES,
        "round3",
        uuid.clone(),
    )
    .await;

    let mut j = 0;
    let mut party_shares: Vec<Scalar> = Vec::new();
    for i in 1..=PARTIES {
        if i == party_num_int {
            party_shares.push(secret_shares[(i - 1) as usize].clone());
        } else {
            let aead_pack: AEAD = serde_json::from_str(&round3_ans_vec[j]).unwrap();
            let key_i = &enc_keys[j];
            let out = aes_decrypt(key_i, aead_pack);
            let out_bn = BigInt::from_bytes_be(&out[..]);
            let out_fe = ECScalar::from(&out_bn);
            party_shares.push(out_fe);

            j += 1;
        }
    }

    // round 4: send vss commitments
    assert!(broadcast(
        &client,
        addr,
        party_num_int,
        "round4",
        serde_json::to_string(&vss_scheme).unwrap(),
        uuid.clone()
    )
    .await
    .is_ok());
    let round4_ans_vec = poll_for_broadcasts(
        &client,
        addr,
        party_num_int,
        PARTIES,
        "round4",
        uuid.clone(),
    )
    .await;

    let mut j = 0;
    let mut vss_scheme_vec: Vec<VerifiableSS> = Vec::new();
    for i in 1..=PARTIES {
        if i == party_num_int {
            vss_scheme_vec.push(vss_scheme.clone());
        } else {
            let vss_scheme_j: VerifiableSS = serde_json::from_str(&round4_ans_vec[j]).unwrap();
            vss_scheme_vec.push(vss_scheme_j);
            j += 1;
        }
    }

    let (shared_keys, dlog_proof) = party_keys
        .phase2_verify_vss_construct_keypair_phase3_pok_dlog(
            &params,
            &point_vec,
            &party_shares,
            &vss_scheme_vec,
            &(party_num_int.clone() as usize), // FIXME
        )
        .expect("invalid vss");

    // round 5: send dlog proof
    assert!(broadcast(
        &client,
        addr,
        party_num_int,
        "round5",
        serde_json::to_string(&dlog_proof).unwrap(),
        uuid.clone()
    )
    .await
    .is_ok());
    let round5_ans_vec = poll_for_broadcasts(
        &client,
        addr,
        party_num_int,
        PARTIES,
        "round5",
        uuid,
    )
    .await;

    let mut j = 0;
    let mut dlog_proof_vec: Vec<DLogProof> = Vec::new();
    for i in 1..=PARTIES {
        if i == party_num_int {
            dlog_proof_vec.push(dlog_proof.clone());
        } else {
            let dlog_proof_j: DLogProof = serde_json::from_str(&round5_ans_vec[j]).unwrap();
            dlog_proof_vec.push(dlog_proof_j);
            j += 1;
        }
    }
    Keys::verify_dlog_proofs(&params, &dlog_proof_vec, &point_vec).expect("bad dlog proof");

    //save key to file:
    let paillier_key_vec = (0..PARTIES)
        .map(|i| bc1_vec[i as usize].e.clone())
        .collect::<Vec<EncryptionKey>>();

    let keygen_json = serde_json::to_string(&(
        party_keys,
        shared_keys,
        party_num_int,
        vss_scheme_vec,
        paillier_key_vec,
        y_sum,
    ))
    .unwrap();

    keygen_json
}

#[wasm_bindgen]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GG18SignClientContext {
    addr: String,
    party_keys: Keys,
    shared_keys: SharedKeys,
    party_id: u16,
    vss_scheme_vec: Vec<VerifiableSS>,
    paillier_key_vector: Vec<EncryptionKey>,
    y_sum: Point,
    threshould: u16,
    party_num_int: u16,
    uuid: String,
    sign_keys: Option<SignKeys>,
    com: Option<SignBroadcastPhase1>,
    decommit: Option<SignDecommitPhase1>,
    round1_ans_vec: Option<Vec<String>>,
    signers_vec: Option<Vec<usize>>,
    round2_ans_vec: Option<Vec<String>>,
    xi_com_vec: Option<Vec<crate::curv::elliptic::curves::secp256_k1::Secp256k1Point>>,
    beta_vec: Option<Vec<Scalar>>,
    ni_vec: Option<Vec<Scalar>>,
    bc1_vec: Option<Vec<SignBroadcastPhase1>>,
    m_b_gamma_rec_vec: Option<Vec<MessageB>>,
    delta_inv: Option<crate::curv::elliptic::curves::secp256_k1::Secp256k1Scalar>,
    sigma: Option<crate::curv::elliptic::curves::secp256_k1::Secp256k1Scalar>,
    message: Vec<u8>,
    phase5_com: Option<Phase5Com1>,
    phase_5a_decom: Option<Phase5ADecom1>,
    helgamal_proof: Option<HomoELGamalProof>,
    dlog_proof_rho: Option<DLogProof>,
    commit5a_vec: Option<Vec<Phase5Com1>>,
    local_sig: Option<LocalSignature>,
    r: Option<crate::curv::elliptic::curves::secp256_k1::Secp256k1Point>,
    phase5_com2: Option<Phase5Com2>,
    phase_5d_decom2: Option<Phase5DDecom2>,
    decommit5a_and_elgamal_and_dlog_vec: Option<Vec<(Phase5ADecom1, HomoELGamalProof, DLogProof)>>,
    decommit5a_and_elgamal_and_dlog_vec_includes_i:
        Option<Vec<(Phase5ADecom1, HomoELGamalProof, DLogProof)>>,
    s_i: Option<crate::curv::elliptic::curves::secp256_k1::Secp256k1Scalar>,
    commit5c_vec: Option<Vec<Phase5Com2>>,
}

#[wasm_bindgen]
pub async fn gg18_sign_client_new_context(
    addr: String,
    t: usize,
    n: usize,
    key_store: String,
    message_str: String,
) -> String {
    let message = match hex::decode(message_str.clone()) {
        Ok(x) => x,
        Err(_e) => message_str.as_bytes().to_vec(),
    };
    // let message = &message[..];
    let client = new_client_with_headers();

    let (party_keys, shared_keys, party_id, vss_scheme_vec, paillier_key_vector, y_sum): (
        Keys,
        SharedKeys,
        u16,
        Vec<VerifiableSS>,
        Vec<EncryptionKey>,
        Point,
    ) = serde_json::from_str(&key_store).unwrap();

    //signup:
    let (party_num_int, uuid) = match signup(&client, &addr).await.unwrap() {
        PartySignup { number, uuid } => (number, uuid),
    };

    serde_json::to_string(&GG18SignClientContext {
        addr,
        party_keys,
        shared_keys,
        party_id,
        vss_scheme_vec,
        paillier_key_vector,
        y_sum,
        threshould: t as u16,
        party_num_int,
        uuid,
        sign_keys: None,
        com: None,
        decommit: None,
        round1_ans_vec: None,
        signers_vec: None,
        round2_ans_vec: None,
        xi_com_vec: None,
        beta_vec: None,
        ni_vec: None,
        bc1_vec: None,
        m_b_gamma_rec_vec: None,
        delta_inv: None,
        message, // TODO: The message is plain now
        sigma: None,
        phase5_com: None,
        phase_5a_decom: None,
        helgamal_proof: None,
        dlog_proof_rho: None,
        commit5a_vec: None,
        local_sig: None,
        r: None,
        phase5_com2: None,
        phase_5d_decom2: None,
        decommit5a_and_elgamal_and_dlog_vec: None,
        decommit5a_and_elgamal_and_dlog_vec_includes_i: None,
        s_i: None,
        commit5c_vec: None,
    })
    .unwrap()
}

#[wasm_bindgen]
pub async fn gg18_sign_client_round0(context: String) -> String {
    let mut context = serde_json::from_str::<GG18SignClientContext>(&context).unwrap();
    let client = new_client_with_headers();
    // round 0: collect signers IDs
    assert!(broadcast(
        &client,
        &context.addr,
        context.party_num_int,
        "round0",
        serde_json::to_string(&context.party_id).unwrap(),
        context.uuid.clone()
    )
    .await
    .is_ok());
    let round0_ans_vec = poll_for_broadcasts(
        &client,
        &context.addr,
        context.party_num_int,
        context.threshould + 1,
        "round0",
        context.uuid.clone(),
    )
    .await;

    let mut j = 0;
    let mut signers_vec: Vec<usize> = Vec::new();
    for i in 1..=context.threshould + 1 {
        if i == context.party_num_int {
            signers_vec.push((context.party_id - 1).into());
        } else {
            let signer_j: u16 = serde_json::from_str(&round0_ans_vec[j]).unwrap();
            signers_vec.push((signer_j - 1).into());
            j += 1;
        }
    }

    let private =
        PartyPrivate::set_private(context.party_keys.clone(), context.shared_keys.clone());

    let sign_keys = SignKeys::create(
        &private,
        &context.vss_scheme_vec[usize::from(signers_vec[usize::from(context.party_num_int - 1)])],
        signers_vec[usize::from(context.party_num_int - 1)].into(),
        &signers_vec,
    );

    let xi_com_vec = Keys::get_commitments_to_xi(&context.vss_scheme_vec);

    context.sign_keys = Some(sign_keys);
    context.signers_vec = Some(signers_vec);
    context.xi_com_vec = Some(xi_com_vec);

    serde_json::to_string(&context).unwrap()
}

#[wasm_bindgen]
pub async fn gg18_sign_client_round1(context: String) -> String {
    let mut context = serde_json::from_str::<GG18SignClientContext>(&context).unwrap();
    let client = new_client_with_headers();
    let (com, decommit) = context.sign_keys.as_ref().unwrap().phase1_broadcast();
    let (m_a_k, _) = MessageA::a(
        &context.sign_keys.as_ref().unwrap().k_i,
        &context.party_keys.ek,
        &[],
    );
    assert!(broadcast(
        &client,
        &context.addr,
        context.party_num_int,
        "round1",
        serde_json::to_string(&(com.clone(), m_a_k)).unwrap(),
        context.uuid.clone()
    )
    .await
    .is_ok());
    let round1_ans_vec = poll_for_broadcasts(
        &client,
        &context.addr,
        context.party_num_int,
        context.threshould + 1,
        "round1",
        context.uuid.clone(),
    )
    .await;

    context.com = Some(com);
    context.decommit = Some(decommit);
    context.round1_ans_vec = Some(round1_ans_vec);

    serde_json::to_string(&context).unwrap()
}

#[wasm_bindgen]
pub async fn gg18_sign_client_round2(context: String) -> String {
    let mut context = serde_json::from_str::<GG18SignClientContext>(&context).unwrap();
    let client = new_client_with_headers();
    let mut j = 0;
    let mut bc1_vec: Vec<SignBroadcastPhase1> = Vec::new();
    let mut m_a_vec: Vec<MessageA> = Vec::new();

    for i in 1..context.threshould + 2 {
        if i == context.party_num_int {
            bc1_vec.push(context.com.as_ref().unwrap().clone());
        //   m_a_vec.push(m_a_k.clone());
        } else {
            //     if signers_vec.contains(&(i as usize)) {
            let (bc1_j, m_a_party_j): (SignBroadcastPhase1, MessageA) =
                serde_json::from_str(&context.round1_ans_vec.as_ref().unwrap()[j]).unwrap();
            bc1_vec.push(bc1_j);
            m_a_vec.push(m_a_party_j);

            j += 1;
            //       }
        }
    }
    assert_eq!(context.signers_vec.as_ref().unwrap().len(), bc1_vec.len());

    //////////////////////////////////////////////////////////////////////////////
    let mut m_b_gamma_send_vec: Vec<MessageB> = Vec::new();
    let mut beta_vec: Vec<Scalar> = Vec::new();
    let mut m_b_w_send_vec: Vec<MessageB> = Vec::new();
    let mut ni_vec: Vec<Scalar> = Vec::new();
    let mut j = 0;
    for i in 1..context.threshould + 2 {
        if i != context.party_num_int {
            let (m_b_gamma, beta_gamma, _, _) = MessageB::b(
                &context.sign_keys.as_ref().unwrap().gamma_i,
                &context.paillier_key_vector
                    [usize::from(context.signers_vec.as_ref().unwrap()[usize::from(i - 1)])],
                m_a_vec[j].clone(),
                &[],
            )
            .unwrap();
            let (m_b_w, beta_wi, _, _) = MessageB::b(
                &context.sign_keys.as_ref().unwrap().w_i,
                &context.paillier_key_vector
                    [usize::from(context.signers_vec.as_ref().unwrap()[usize::from(i - 1)])],
                m_a_vec[j].clone(),
                &[],
            )
            .unwrap();
            m_b_gamma_send_vec.push(m_b_gamma);
            m_b_w_send_vec.push(m_b_w);
            beta_vec.push(beta_gamma);
            ni_vec.push(beta_wi);
            j += 1;
        }
    }

    let mut j = 0;
    for i in 1..context.threshould + 2 {
        if i != context.party_num_int {
            assert!(sendp2p(
                &client,
                &context.addr,
                context.party_num_int,
                i,
                "round2",
                serde_json::to_string(&(m_b_gamma_send_vec[j].clone(), m_b_w_send_vec[j].clone()))
                    .unwrap(),
                context.uuid.clone()
            )
            .await
            .is_ok());
            j += 1;
        }
    }

    let round2_ans_vec = poll_for_p2p(
        &client,
        &context.addr,
        context.party_num_int,
        context.threshould + 1,
        "round2",
        context.uuid.clone(),
    )
    .await;

    context.round2_ans_vec = Some(round2_ans_vec);
    context.beta_vec = Some(beta_vec);
    context.ni_vec = Some(ni_vec);
    context.bc1_vec = Some(bc1_vec);

    serde_json::to_string(&context).unwrap()
}

#[wasm_bindgen]
pub async fn gg18_sign_client_round3(context: String) -> String {
    let mut context = serde_json::from_str::<GG18SignClientContext>(&context).unwrap();
    let client = new_client_with_headers();
    let mut m_b_gamma_rec_vec: Vec<MessageB> = Vec::new();
    let mut m_b_w_rec_vec: Vec<MessageB> = Vec::new();

    for i in 0..context.threshould {
        //  if signers_vec.contains(&(i as usize)) {
        let (m_b_gamma_i, m_b_w_i): (MessageB, MessageB) =
            serde_json::from_str(&context.round2_ans_vec.as_ref().unwrap()[i as usize]).unwrap();
        m_b_gamma_rec_vec.push(m_b_gamma_i);
        m_b_w_rec_vec.push(m_b_w_i);
        //     }
    }

    let mut alpha_vec: Vec<Scalar> = Vec::new();
    let mut miu_vec: Vec<Scalar> = Vec::new();

    let mut j = 0;
    for i in 1..context.threshould + 2 {
        if i != context.party_num_int {
            let m_b = m_b_gamma_rec_vec[j].clone();

            let alpha_ij_gamma = m_b
                .verify_proofs_get_alpha(
                    &context.party_keys.dk,
                    &context.sign_keys.as_ref().unwrap().k_i,
                )
                .expect("wrong dlog or m_b");
            let m_b = m_b_w_rec_vec[j].clone();
            let alpha_ij_wi = m_b
                .verify_proofs_get_alpha(
                    &context.party_keys.dk,
                    &context.sign_keys.as_ref().unwrap().k_i,
                )
                .expect("wrong dlog or m_b");
            alpha_vec.push(alpha_ij_gamma.0);
            miu_vec.push(alpha_ij_wi.0);
            let g_w_i = Keys::update_commitments_to_xi(
                &context.xi_com_vec.as_ref().unwrap()
                    [usize::from(context.signers_vec.as_ref().unwrap()[usize::from(i - 1)])],
                &context.vss_scheme_vec
                    [usize::from(context.signers_vec.as_ref().unwrap()[usize::from(i - 1)])],
                context.signers_vec.as_ref().unwrap()[usize::from(i - 1)],
                &context.signers_vec.as_ref().unwrap(),
            );
            assert_eq!(m_b.b_proof.pk, g_w_i);
            j += 1;
        }
    }
    //////////////////////////////////////////////////////////////////////////////
    let delta_i = context
        .sign_keys
        .as_ref()
        .unwrap()
        .phase2_delta_i(&alpha_vec, &context.beta_vec.as_ref().unwrap());
    let sigma = context
        .sign_keys
        .as_ref()
        .unwrap()
        .phase2_sigma_i(&miu_vec, &context.ni_vec.as_ref().unwrap());

    assert!(broadcast(
        &client,
        &context.addr,
        context.party_num_int,
        "round3",
        serde_json::to_string(&delta_i).unwrap(),
        context.uuid.clone()
    )
    .await
    .is_ok());
    let round3_ans_vec = poll_for_broadcasts(
        &client,
        &context.addr,
        context.party_num_int,
        context.threshould + 1,
        "round3",
        context.uuid.clone(),
    )
    .await;
    let mut delta_vec: Vec<Scalar> = Vec::new();
    format_vec_from_reads(
        &round3_ans_vec,
        context.party_num_int as usize,
        delta_i,
        &mut delta_vec,
    );
    let delta_inv = SignKeys::phase3_reconstruct_delta(&delta_vec);

    context.m_b_gamma_rec_vec = Some(m_b_gamma_rec_vec);
    context.delta_inv = Some(delta_inv);
    context.sigma = Some(sigma);

    serde_json::to_string(&context).unwrap()
}

#[wasm_bindgen]
pub async fn gg18_sign_client_round4(context: String) -> String {
    let mut context = serde_json::from_str::<GG18SignClientContext>(&context).unwrap();
    let client = new_client_with_headers();
    // decommit to gamma_i
    assert!(broadcast(
        &client,
        &context.addr,
        context.party_num_int,
        "round4",
        serde_json::to_string(&context.decommit.as_ref().unwrap()).unwrap(),
        context.uuid.clone()
    )
    .await
    .is_ok());
    let round4_ans_vec = poll_for_broadcasts(
        &client,
        &context.addr,
        context.party_num_int,
        context.threshould + 1,
        "round4",
        context.uuid.clone(),
    )
    .await;

    let mut decommit_vec: Vec<SignDecommitPhase1> = Vec::new();
    format_vec_from_reads(
        &round4_ans_vec,
        context.party_num_int as usize,
        context.decommit.clone().unwrap(),
        &mut decommit_vec,
    );

    let decomm_i = decommit_vec.remove(usize::from(context.party_num_int - 1));
    &context
        .bc1_vec
        .as_mut()
        .unwrap()
        .remove(usize::from(context.party_num_int - 1));
    let b_proof_vec = (0..context.m_b_gamma_rec_vec.as_ref().unwrap().len())
        .map(|i| &context.m_b_gamma_rec_vec.as_ref().unwrap()[i].b_proof)
        .collect::<Vec<&DLogProof>>();

    let R = SignKeys::phase4(
        &context.delta_inv.as_ref().unwrap(),
        &b_proof_vec,
        decommit_vec,
        &context.bc1_vec.as_ref().unwrap(),
    )
    .expect("bad gamma_i decommit");

    // adding local g_gamma_i
    let R = R + decomm_i.g_gamma_i * context.delta_inv.as_ref().unwrap();

    // we assume the message is already hashed (by the signer).
    let message = &context.message[..];
    let message_bn = BigInt::from_bytes_be(message);
    let local_sig = LocalSignature::phase5_local_sig(
        &context.sign_keys.as_ref().unwrap().k_i,
        &message_bn,
        &R,
        &context.sigma.as_ref().unwrap(),
        &context.y_sum,
    );

    let (phase5_com, phase_5a_decom, helgamal_proof, dlog_proof_rho) =
        local_sig.phase5a_broadcast_5b_zkproof();

    context.phase5_com = Some(phase5_com);
    context.phase_5a_decom = Some(phase_5a_decom);
    context.helgamal_proof = Some(helgamal_proof);
    context.dlog_proof_rho = Some(dlog_proof_rho);
    context.local_sig = Some(local_sig);
    context.r = Some(R);

    serde_json::to_string(&context).unwrap()
}

#[wasm_bindgen]
pub async fn gg18_sign_client_round5(context: String) -> String {
    let mut context = serde_json::from_str::<GG18SignClientContext>(&context).unwrap();
    let client = new_client_with_headers();
    //phase (5A)  broadcast commit
    assert!(broadcast(
        &client,
        &context.addr,
        context.party_num_int,
        "round5",
        serde_json::to_string(&context.phase5_com.as_ref().unwrap()).unwrap(),
        context.uuid.clone()
    )
    .await
    .is_ok());
    let round5_ans_vec = poll_for_broadcasts(
        &client,
        &context.addr,
        context.party_num_int,
        context.threshould + 1,
        "round5",
        context.uuid.clone(),
    )
    .await;

    let mut commit5a_vec: Vec<Phase5Com1> = Vec::new();
    format_vec_from_reads(
        &round5_ans_vec,
        context.party_num_int as usize,
        context.phase5_com.clone().unwrap(),
        &mut commit5a_vec,
    );

    context.commit5a_vec = Some(commit5a_vec);

    serde_json::to_string(&context).unwrap()
}

#[wasm_bindgen]
pub async fn gg18_sign_client_round6(context: String) -> String {
    let mut context = serde_json::from_str::<GG18SignClientContext>(&context).unwrap();
    let client = new_client_with_headers();
    //phase (5B)  broadcast decommit and (5B) ZK proof
    assert!(broadcast(
        &client,
        &context.addr,
        context.party_num_int,
        "round6",
        serde_json::to_string(&(
            context.phase_5a_decom.clone().unwrap(),
            context.helgamal_proof.clone().unwrap(),
            context.dlog_proof_rho.clone().unwrap()
        ))
        .unwrap(),
        context.uuid.clone()
    )
    .await
    .is_ok());
    let round6_ans_vec = poll_for_broadcasts(
        &client,
        &context.addr,
        context.party_num_int,
        context.threshould + 1,
        "round6",
        context.uuid.clone(),
    )
    .await;

    let mut decommit5a_and_elgamal_and_dlog_vec: Vec<(Phase5ADecom1, HomoELGamalProof, DLogProof)> =
        Vec::new();
    format_vec_from_reads(
        &round6_ans_vec,
        context.party_num_int as usize,
        (
            context.phase_5a_decom.clone().unwrap(),
            context.helgamal_proof.clone().unwrap(),
            context.dlog_proof_rho.clone().unwrap(),
        ),
        &mut decommit5a_and_elgamal_and_dlog_vec,
    );
    let decommit5a_and_elgamal_and_dlog_vec_includes_i =
        decommit5a_and_elgamal_and_dlog_vec.clone();
    decommit5a_and_elgamal_and_dlog_vec.remove(usize::from(context.party_num_int - 1));
    context
        .commit5a_vec
        .as_mut()
        .unwrap()
        .remove(usize::from(context.party_num_int - 1));
    let phase_5a_decomm_vec = (0..context.threshould)
        .map(|i| decommit5a_and_elgamal_and_dlog_vec[i as usize].0.clone())
        .collect::<Vec<Phase5ADecom1>>();
    let phase_5a_elgamal_vec = (0..context.threshould)
        .map(|i| decommit5a_and_elgamal_and_dlog_vec[i as usize].1.clone())
        .collect::<Vec<HomoELGamalProof>>();
    let phase_5a_dlog_vec = (0..context.threshould)
        .map(|i| decommit5a_and_elgamal_and_dlog_vec[i as usize].2.clone())
        .collect::<Vec<DLogProof>>();
    let (phase5_com2, phase_5d_decom2) = context
        .local_sig
        .clone()
        .unwrap()
        .phase5c(
            &phase_5a_decomm_vec,
            &context.commit5a_vec.as_ref().unwrap(),
            &phase_5a_elgamal_vec,
            &phase_5a_dlog_vec,
            &context.phase_5a_decom.as_ref().unwrap().V_i,
            &context.r.as_ref().unwrap(),
        )
        .expect("error phase5");

    context.phase5_com2 = Some(phase5_com2);
    context.phase_5d_decom2 = Some(phase_5d_decom2);
    context.decommit5a_and_elgamal_and_dlog_vec_includes_i =
        Some(decommit5a_and_elgamal_and_dlog_vec_includes_i);

    serde_json::to_string(&context).unwrap()
}

#[wasm_bindgen]
pub async fn gg18_sign_client_round7(context: String) -> String {
    let mut context = serde_json::from_str::<GG18SignClientContext>(&context).unwrap();
    let client = new_client_with_headers();
    //////////////////////////////////////////////////////////////////////////////
    assert!(broadcast(
        &client,
        &context.addr,
        context.party_num_int,
        "round7",
        serde_json::to_string(&context.phase5_com2.as_ref().unwrap()).unwrap(),
        context.uuid.clone()
    )
    .await
    .is_ok());
    let round7_ans_vec = poll_for_broadcasts(
        &client,
        &context.addr,
        context.party_num_int,
        context.threshould + 1,
        "round7",
        context.uuid.clone(),
    )
    .await;

    let mut commit5c_vec: Vec<Phase5Com2> = Vec::new();
    format_vec_from_reads(
        &round7_ans_vec,
        context.party_num_int as usize,
        context.phase5_com2.clone().unwrap(),
        &mut commit5c_vec,
    );

    context.commit5c_vec = Some(commit5c_vec);

    serde_json::to_string(&context).unwrap()
}

#[wasm_bindgen]
pub async fn gg18_sign_client_round8(context: String) -> String {
    let mut context = serde_json::from_str::<GG18SignClientContext>(&context).unwrap();
    let client = new_client_with_headers();
    //phase (5B)  broadcast decommit and (5B) ZK proof
    assert!(broadcast(
        &client,
        &context.addr,
        context.party_num_int,
        "round8",
        serde_json::to_string(&context.phase_5d_decom2.as_ref().unwrap()).unwrap(),
        context.uuid.clone()
    )
    .await
    .is_ok());
    let round8_ans_vec = poll_for_broadcasts(
        &client,
        &context.addr,
        context.party_num_int,
        context.threshould + 1,
        "round8",
        context.uuid.clone(),
    )
    .await;

    let mut decommit5d_vec: Vec<Phase5DDecom2> = Vec::new();
    format_vec_from_reads(
        &round8_ans_vec,
        context.party_num_int as usize,
        context.phase_5d_decom2.clone().unwrap(),
        &mut decommit5d_vec,
    );

    let phase_5a_decomm_vec_includes_i = (0..=context.threshould)
        .map(|i| {
            context
                .decommit5a_and_elgamal_and_dlog_vec_includes_i
                .clone()
                .unwrap()[i as usize]
                .0
                .clone()
        })
        .collect::<Vec<Phase5ADecom1>>();
    let s_i = context
        .local_sig
        .clone()
        .unwrap()
        .phase5d(
            &decommit5d_vec,
            &context.commit5c_vec.as_ref().unwrap(),
            &phase_5a_decomm_vec_includes_i,
        )
        .expect("bad com 5d");

    context.s_i = Some(s_i);

    serde_json::to_string(&context).unwrap()
}

#[wasm_bindgen]
pub async fn gg18_sign_client_round9(context: String) -> String {
    let mut context = serde_json::from_str::<GG18SignClientContext>(&context).unwrap();
    let client = new_client_with_headers();
    //////////////////////////////////////////////////////////////////////////////
    assert!(broadcast(
        &client,
        &context.addr,
        context.party_num_int,
        "round9",
        serde_json::to_string(&context.s_i.as_ref().unwrap()).unwrap(),
        context.uuid.clone()
    )
    .await
    .is_ok());
    let round9_ans_vec = poll_for_broadcasts(
        &client,
        &context.addr,
        context.party_num_int,
        context.threshould + 1,
        "round9",
        context.uuid.clone(),
    )
    .await;

    let mut s_i_vec: Vec<Scalar> = Vec::new();
    format_vec_from_reads(
        &round9_ans_vec,
        context.party_num_int as usize,
        context.s_i.unwrap(),
        &mut s_i_vec,
    );

    s_i_vec.remove(usize::from(context.party_num_int - 1));
    let sig = context
        .local_sig
        .unwrap()
        .output_signature(&s_i_vec)
        .expect("verification failed");

    let sign_json = serde_json::to_string(&(
        "r",
        BigInt::from_bytes_be(sig.r.to_big_int().to_bytes_be().as_ref()).to_str_radix(16),
        "s",
        BigInt::from_bytes_be(sig.s.to_big_int().to_bytes_be().as_ref()).to_str_radix(16),
    ))
    .unwrap();

    sign_json
}

#[wasm_bindgen]
pub async fn gg18_sign(t: usize, n: usize, key_store: String, message_str: String) -> String {
    let message = match hex::decode(message_str.clone()) {
        Ok(x) => x,
        Err(_e) => message_str.as_bytes().to_vec(),
    };
    let message = &message[..];
    let client = new_client_with_headers();
    let addr = "http://127.0.0.1:8000";
    let (party_keys, shared_keys, party_id, vss_scheme_vec, paillier_key_vector, y_sum): (
        Keys,
        SharedKeys,
        u16,
        Vec<VerifiableSS>,
        Vec<EncryptionKey>,
        Point,
    ) = serde_json::from_str(&key_store).unwrap();

    let THRESHOLD = t as u16;

    //signup:
    let (party_num_int, uuid) = match signup(&client, addr).await.unwrap() {
        PartySignup { number, uuid } => (number, uuid),
    };

    // round 0: collect signers IDs
    assert!(broadcast(
        &client,
        addr,
        party_num_int,
        "round0",
        serde_json::to_string(&party_id).unwrap(),
        uuid.clone()
    )
    .await
    .is_ok());
    let round0_ans_vec = poll_for_broadcasts(
        &client,
        addr,
        party_num_int,
        THRESHOLD + 1,
        "round0",
        uuid.clone(),
    )
    .await;

    let mut j = 0;
    let mut signers_vec: Vec<usize> = Vec::new();
    for i in 1..=THRESHOLD + 1 {
        if i == party_num_int {
            signers_vec.push((party_id - 1).into());
        } else {
            let signer_j: u16 = serde_json::from_str(&round0_ans_vec[j]).unwrap();
            signers_vec.push((signer_j - 1).into());
            j += 1;
        }
    }

    let private = PartyPrivate::set_private(party_keys.clone(), shared_keys);

    let sign_keys = SignKeys::create(
        &private,
        &vss_scheme_vec[usize::from(signers_vec[usize::from(party_num_int - 1)])],
        signers_vec[usize::from(party_num_int - 1)].into(),
        &signers_vec,
    );

    let xi_com_vec = Keys::get_commitments_to_xi(&vss_scheme_vec);
    //////////////////////////////////////////////////////////////////////////////
    let (com, decommit) = sign_keys.phase1_broadcast();
    let (m_a_k, _) = MessageA::a(&sign_keys.k_i, &party_keys.ek, &[]);
    assert!(broadcast(
        &client,
        addr,
        party_num_int,
        "round1",
        serde_json::to_string(&(com.clone(), m_a_k)).unwrap(),
        uuid.clone()
    )
    .await
    .is_ok());
    let round1_ans_vec = poll_for_broadcasts(
        &client,
        addr,
        party_num_int,
        THRESHOLD + 1,
        "round1",
        uuid.clone(),
    )
    .await;

    let mut j = 0;
    let mut bc1_vec: Vec<SignBroadcastPhase1> = Vec::new();
    let mut m_a_vec: Vec<MessageA> = Vec::new();

    for i in 1..THRESHOLD + 2 {
        if i == party_num_int {
            bc1_vec.push(com.clone());
        //   m_a_vec.push(m_a_k.clone());
        } else {
            //     if signers_vec.contains(&(i as usize)) {
            let (bc1_j, m_a_party_j): (SignBroadcastPhase1, MessageA) =
                serde_json::from_str(&round1_ans_vec[j]).unwrap();
            bc1_vec.push(bc1_j);
            m_a_vec.push(m_a_party_j);

            j += 1;
            //       }
        }
    }
    assert_eq!(signers_vec.len(), bc1_vec.len());

    //////////////////////////////////////////////////////////////////////////////
    let mut m_b_gamma_send_vec: Vec<MessageB> = Vec::new();
    let mut beta_vec: Vec<Scalar> = Vec::new();
    let mut m_b_w_send_vec: Vec<MessageB> = Vec::new();
    let mut ni_vec: Vec<Scalar> = Vec::new();
    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i != party_num_int {
            let (m_b_gamma, beta_gamma, _, _) = MessageB::b(
                &sign_keys.gamma_i,
                &paillier_key_vector[usize::from(signers_vec[usize::from(i - 1)])],
                m_a_vec[j].clone(),
                &[],
            )
            .unwrap();
            let (m_b_w, beta_wi, _, _) = MessageB::b(
                &sign_keys.w_i,
                &paillier_key_vector[usize::from(signers_vec[usize::from(i - 1)])],
                m_a_vec[j].clone(),
                &[],
            )
            .unwrap();
            m_b_gamma_send_vec.push(m_b_gamma);
            m_b_w_send_vec.push(m_b_w);
            beta_vec.push(beta_gamma);
            ni_vec.push(beta_wi);
            j += 1;
        }
    }

    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i != party_num_int {
            assert!(sendp2p(
                &client,
                addr,
                party_num_int,
                i,
                "round2",
                serde_json::to_string(&(m_b_gamma_send_vec[j].clone(), m_b_w_send_vec[j].clone()))
                    .unwrap(),
                uuid.clone()
            )
            .await
            .is_ok());
            j += 1;
        }
    }

    let round2_ans_vec = poll_for_p2p(
        &client,
        addr,
        party_num_int,
        THRESHOLD + 1,
        "round2",
        uuid.clone(),
    )
    .await;

    let mut m_b_gamma_rec_vec: Vec<MessageB> = Vec::new();
    let mut m_b_w_rec_vec: Vec<MessageB> = Vec::new();

    for i in 0..THRESHOLD {
        //  if signers_vec.contains(&(i as usize)) {
        let (m_b_gamma_i, m_b_w_i): (MessageB, MessageB) =
            serde_json::from_str(&round2_ans_vec[i as usize]).unwrap();
        m_b_gamma_rec_vec.push(m_b_gamma_i);
        m_b_w_rec_vec.push(m_b_w_i);
        //     }
    }

    let mut alpha_vec: Vec<Scalar> = Vec::new();
    let mut miu_vec: Vec<Scalar> = Vec::new();

    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i != party_num_int {
            let m_b = m_b_gamma_rec_vec[j].clone();

            let alpha_ij_gamma = m_b
                .verify_proofs_get_alpha(&party_keys.dk, &sign_keys.k_i)
                .expect("wrong dlog or m_b");
            let m_b = m_b_w_rec_vec[j].clone();
            let alpha_ij_wi = m_b
                .verify_proofs_get_alpha(&party_keys.dk, &sign_keys.k_i)
                .expect("wrong dlog or m_b");
            alpha_vec.push(alpha_ij_gamma.0);
            miu_vec.push(alpha_ij_wi.0);
            let g_w_i = Keys::update_commitments_to_xi(
                &xi_com_vec[usize::from(signers_vec[usize::from(i - 1)])],
                &vss_scheme_vec[usize::from(signers_vec[usize::from(i - 1)])],
                signers_vec[usize::from(i - 1)],
                &signers_vec,
            );
            assert_eq!(m_b.b_proof.pk, g_w_i);
            j += 1;
        }
    }
    //////////////////////////////////////////////////////////////////////////////
    let delta_i = sign_keys.phase2_delta_i(&alpha_vec, &beta_vec);
    let sigma = sign_keys.phase2_sigma_i(&miu_vec, &ni_vec);

    assert!(broadcast(
        &client,
        addr,
        party_num_int,
        "round3",
        serde_json::to_string(&delta_i).unwrap(),
        uuid.clone()
    )
    .await
    .is_ok());
    let round3_ans_vec = poll_for_broadcasts(
        &client,
        addr,
        party_num_int,
        THRESHOLD + 1,
        "round3",
        uuid.clone(),
    )
    .await;
    let mut delta_vec: Vec<Scalar> = Vec::new();
    format_vec_from_reads(
        &round3_ans_vec,
        party_num_int as usize,
        delta_i,
        &mut delta_vec,
    );
    let delta_inv = SignKeys::phase3_reconstruct_delta(&delta_vec);

    //////////////////////////////////////////////////////////////////////////////
    // decommit to gamma_i
    assert!(broadcast(
        &client,
        addr,
        party_num_int,
        "round4",
        serde_json::to_string(&decommit).unwrap(),
        uuid.clone()
    )
    .await
    .is_ok());
    let round4_ans_vec = poll_for_broadcasts(
        &client,
        addr,
        party_num_int,
        THRESHOLD + 1,
        "round4",
        uuid.clone(),
    )
    .await;

    let mut decommit_vec: Vec<SignDecommitPhase1> = Vec::new();
    format_vec_from_reads(
        &round4_ans_vec,
        party_num_int as usize,
        decommit,
        &mut decommit_vec,
    );

    let decomm_i = decommit_vec.remove(usize::from(party_num_int - 1));
    bc1_vec.remove(usize::from(party_num_int - 1));
    let b_proof_vec = (0..m_b_gamma_rec_vec.len())
        .map(|i| &m_b_gamma_rec_vec[i].b_proof)
        .collect::<Vec<&DLogProof>>();

    let R = SignKeys::phase4(&delta_inv, &b_proof_vec, decommit_vec, &bc1_vec)
        .expect("bad gamma_i decommit");

    // adding local g_gamma_i
    let R = R + decomm_i.g_gamma_i * delta_inv;

    // we assume the message is already hashed (by the signer).
    let message_bn = BigInt::from_bytes_be(message);
    let local_sig =
        LocalSignature::phase5_local_sig(&sign_keys.k_i, &message_bn, &R, &sigma, &y_sum);

    let (phase5_com, phase_5a_decom, helgamal_proof, dlog_proof_rho) =
        local_sig.phase5a_broadcast_5b_zkproof();

    //phase (5A)  broadcast commit
    assert!(broadcast(
        &client,
        addr,
        party_num_int,
        "round5",
        serde_json::to_string(&phase5_com).unwrap(),
        uuid.clone()
    )
    .await
    .is_ok());
    let round5_ans_vec = poll_for_broadcasts(
        &client,
        addr,
        party_num_int,
        THRESHOLD + 1,
        "round5",
        uuid.clone(),
    )
    .await;

    let mut commit5a_vec: Vec<Phase5Com1> = Vec::new();
    format_vec_from_reads(
        &round5_ans_vec,
        party_num_int as usize,
        phase5_com,
        &mut commit5a_vec,
    );

    //phase (5B)  broadcast decommit and (5B) ZK proof
    assert!(broadcast(
        &client,
        addr,
        party_num_int,
        "round6",
        serde_json::to_string(&(
            phase_5a_decom.clone(),
            helgamal_proof.clone(),
            dlog_proof_rho.clone()
        ))
        .unwrap(),
        uuid.clone()
    )
    .await
    .is_ok());
    let round6_ans_vec = poll_for_broadcasts(
        &client,
        addr,
        party_num_int,
        THRESHOLD + 1,
        "round6",
        uuid.clone(),
    )
    .await;

    let mut decommit5a_and_elgamal_and_dlog_vec: Vec<(Phase5ADecom1, HomoELGamalProof, DLogProof)> =
        Vec::new();
    format_vec_from_reads(
        &round6_ans_vec,
        party_num_int as usize,
        (phase_5a_decom.clone(), helgamal_proof, dlog_proof_rho),
        &mut decommit5a_and_elgamal_and_dlog_vec,
    );
    let decommit5a_and_elgamal_and_dlog_vec_includes_i =
        decommit5a_and_elgamal_and_dlog_vec.clone();
    decommit5a_and_elgamal_and_dlog_vec.remove(usize::from(party_num_int - 1));
    commit5a_vec.remove(usize::from(party_num_int - 1));
    let phase_5a_decomm_vec = (0..THRESHOLD)
        .map(|i| decommit5a_and_elgamal_and_dlog_vec[i as usize].0.clone())
        .collect::<Vec<Phase5ADecom1>>();
    let phase_5a_elgamal_vec = (0..THRESHOLD)
        .map(|i| decommit5a_and_elgamal_and_dlog_vec[i as usize].1.clone())
        .collect::<Vec<HomoELGamalProof>>();
    let phase_5a_dlog_vec = (0..THRESHOLD)
        .map(|i| decommit5a_and_elgamal_and_dlog_vec[i as usize].2.clone())
        .collect::<Vec<DLogProof>>();
    let (phase5_com2, phase_5d_decom2) = local_sig
        .phase5c(
            &phase_5a_decomm_vec,
            &commit5a_vec,
            &phase_5a_elgamal_vec,
            &phase_5a_dlog_vec,
            &phase_5a_decom.V_i,
            &R,
        )
        .expect("error phase5");

    //////////////////////////////////////////////////////////////////////////////
    assert!(broadcast(
        &client,
        addr,
        party_num_int,
        "round7",
        serde_json::to_string(&phase5_com2).unwrap(),
        uuid.clone()
    )
    .await
    .is_ok());
    let round7_ans_vec = poll_for_broadcasts(
        &client,
        addr,
        party_num_int,
        THRESHOLD + 1,
        "round7",
        uuid.clone(),
    )
    .await;

    let mut commit5c_vec: Vec<Phase5Com2> = Vec::new();
    format_vec_from_reads(
        &round7_ans_vec,
        party_num_int as usize,
        phase5_com2,
        &mut commit5c_vec,
    );

    //phase (5B)  broadcast decommit and (5B) ZK proof
    assert!(broadcast(
        &client,
        addr,
        party_num_int,
        "round8",
        serde_json::to_string(&phase_5d_decom2).unwrap(),
        uuid.clone()
    )
    .await
    .is_ok());
    let round8_ans_vec = poll_for_broadcasts(
        &client,
        addr,
        party_num_int,
        THRESHOLD + 1,
        "round8",
        uuid.clone(),
    )
    .await;

    let mut decommit5d_vec: Vec<Phase5DDecom2> = Vec::new();
    format_vec_from_reads(
        &round8_ans_vec,
        party_num_int as usize,
        phase_5d_decom2,
        &mut decommit5d_vec,
    );

    let phase_5a_decomm_vec_includes_i = (0..=THRESHOLD)
        .map(|i| {
            decommit5a_and_elgamal_and_dlog_vec_includes_i[i as usize]
                .0
                .clone()
        })
        .collect::<Vec<Phase5ADecom1>>();
    let s_i = local_sig
        .phase5d(
            &decommit5d_vec,
            &commit5c_vec,
            &phase_5a_decomm_vec_includes_i,
        )
        .expect("bad com 5d");

    //////////////////////////////////////////////////////////////////////////////
    assert!(broadcast(
        &client,
        addr,
        party_num_int,
        "round9",
        serde_json::to_string(&s_i).unwrap(),
        uuid.clone()
    )
    .await
    .is_ok());
    let round9_ans_vec = poll_for_broadcasts(
        &client,
        addr,
        party_num_int,
        THRESHOLD + 1,
        "round9",
        uuid,
    )
    .await;

    let mut s_i_vec: Vec<Scalar> = Vec::new();
    format_vec_from_reads(&round9_ans_vec, party_num_int as usize, s_i, &mut s_i_vec);

    s_i_vec.remove(usize::from(party_num_int - 1));
    let sig = local_sig
        .output_signature(&s_i_vec)
        .expect("verification failed");
    /*
    println!("party {:?} Output Signature: \n", party_num_int);
    println!("R: {:?}", sig.r);
    println!("s: {:?} \n", sig.s);
    println!("recid: {:?} \n", sig.recid.clone());
    */

    let sign_json = serde_json::to_string(&(
        "r",
        BigInt::from_bytes_be(sig.r.to_big_int().to_bytes_be().as_ref()).to_str_radix(16),
        "s",
        BigInt::from_bytes_be(sig.s.to_big_int().to_bytes_be().as_ref()).to_str_radix(16),
    ))
    .unwrap();

    //fs::write("signature".to_string(), sign_json).expect("Unable to save !");
    sign_json
}

fn format_vec_from_reads<'a, T: serde::Deserialize<'a> + Clone>(
    ans_vec: &'a [String],
    party_num: usize,
    value_i: T,
    new_vec: &'a mut Vec<T>,
) {
    let mut j = 0;
    for i in 1..ans_vec.len() + 2 {
        if i == party_num {
            new_vec.push(value_i.clone());
        } else {
            let value_j: T = serde_json::from_str(&ans_vec[j]).unwrap();
            new_vec.push(value_j);
            j += 1;
        }
    }
}
