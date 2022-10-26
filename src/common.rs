#![allow(dead_code)]

use crate::curv::elliptic::curves::traits::{ECPoint, ECScalar};
// use crate::gg_2018::party_i::Signature;

use crate::errors::TssError;
#[cfg(target_arch = "wasm32")]
use crate::log;

use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::{rngs::OsRng, RngCore};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_futures::JsFuture;

use crate::curv::{
    arithmetic::num_bigint::BigInt,
    arithmetic::traits::Converter,
    elliptic::curves::secp256_k1::{Secp256k1Point as Point, Secp256k1Scalar as Scalar},
};

use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

pub type Key = String;

#[allow(dead_code)]
pub const AES_KEY_BYTES_LEN: usize = 32;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct AEAD {
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct PartySignup {
    pub number: u16,
    pub uuid: String,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Index {
    pub key: Key,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub key: Key,
    pub value: String,
}

#[derive(Serialize, Deserialize)]
pub struct Params {
    pub parties: String,
    pub threshold: String,
}

#[allow(dead_code)]
pub fn aes_encrypt(key: &[u8], plaintext: &[u8]) -> Result<AEAD, TssError> {
    let aes_key = aes_gcm::Key::from_slice(key);
    let cipher = Aes256Gcm::new(aes_key);

    let mut nonce = [0u8; 12];
    let mut rng = OsRng::new().map_err(|_e| TssError::UnknownError {
        msg: ("aes_encrypt").to_string(),
        file: ("common.rs").to_string(),
        line: (line!()),
    })?;
    rng.fill_bytes(&mut nonce);
    let nonce = Nonce::from_slice(&nonce);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_e| TssError::UnknownError {
            msg: ("encryption failure!").to_string(),
            file: ("common.rs").to_string(),
            line: (line!()),
        })?;
    // .expect("encryption failure!");

    Ok(AEAD {
        ciphertext: ciphertext,
        tag: nonce.to_vec(),
    })
}

#[allow(dead_code)]
pub fn aes_decrypt(key: &[u8], aead_pack: AEAD) -> Result<Vec<u8>, TssError> {
    let aes_key = aes_gcm::Key::from_slice(key);
    let nonce = Nonce::from_slice(&aead_pack.tag);
    let gcm = Aes256Gcm::new(aes_key);

    let out = gcm
        .decrypt(nonce, aead_pack.ciphertext.as_slice())
        .map_err(|_e| TssError::UnknownError {
            msg: ("aes_decrypt").to_string(),
            file: ("common.rs").to_string(),
            line: (line!()),
        });
    out
}

// use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};

#[cfg(target_arch = "wasm32")]
pub async fn sleep(ms: u32) {
    let promise = js_sys::Promise::new(&mut |resolve, _| {
        web_sys::window()
            .unwrap()
            .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, ms as i32)
            .unwrap();
    });
    wasm_bindgen_futures::JsFuture::from(promise).await;
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn sleep(ms: u32) {
    std::thread::sleep(core::time::Duration::from_millis(ms as u64));
}

pub async fn postb<T>(client: &Client, addr: &str, path: &str, body: T) -> Result<String, TssError>
where
    T: serde::ser::Serialize,
{
    let url = format!("{}/{}", addr, path);
    let retries = 3;
    for _i in 1..retries {
        let res = client
            .post(url.clone())
            .header("Content-Type", "application/json; charset=utf-8")
            .json(&body)
            .send()
            .await;
        if let Ok(res) = res {
            return Ok(res.text().await.map_err(|_e| TssError::UnknownError {
                msg: ("postb").to_string(),
                file: ("common.rs").to_string(),
                line: (line!()),
            })?);
        }
    }
    Err(TssError::UnknownError {
        msg: ("postb").to_string(),
        file: ("common.rs").to_string(),
        line: (line!()),
    })
}

pub async fn broadcast(
    client: &Client,
    addr: &str,
    party_num: u16,
    round: &str,
    data: String,
    sender_uuid: String,
) -> Result<(), TssError> {
    let key = format!("{}-{}-{}", party_num, round, sender_uuid);
    let entry = Entry { key, value: data };
    let res_body = postb(client, addr, "set", entry).await?;
    let _u = serde_json::from_str::<()>(&res_body).map_err(|_e| TssError::UnknownError {
        msg: ("broadcast").to_string(),
        file: ("common.rs").to_string(),
        line: (line!()),
    });
    Ok(())
}

pub async fn sendp2p(
    client: &Client,
    addr: &str,
    party_from: u16,
    party_to: u16,
    round: &str,
    data: String,
    sender_uuid: String,
) -> Result<(), TssError> {
    let key = format!("{}-{}-{}-{}", party_from, party_to, round, sender_uuid);

    let entry = Entry { key, value: data };

    let res_body = postb(client, addr, "set", entry).await?;
    let _u = serde_json::from_str::<()>(&res_body).map_err(|_e| TssError::UnknownError {
        msg: ("sendp2p").to_string(),
        file: ("common.rs").to_string(),
        line: (line!()),
    });
    Ok(())
}

// pub async fn poll_for_broadcasts(
//     client: &Client,
//     addr: &str,
//     party_num: u16,
//     n: u16,
//     round: &str,
//     sender_uuid: String,
//     delay: u32,
// ) -> Result<Vec<String>,TssError> {
//     let mut ans_vec = Vec::new();
//     for i in 1..=n {
//         if i != party_num {
//             let key = format!("{}-{}-{}", i, round, sender_uuid);
//             let index = Index { key };
//             loop {
//                 sleep(delay).await;
//                 // add delay to allow the server to process request:
//                 let res_body = postb(client, addr, "get", index.clone()).await.unwrap();
//                 let answer: Result<Entry, TssError> = serde_json::from_str(&res_body).map_err(|_e|TssError::UnknownError { msg: ("poll_for_broadcasts").to_string(), file: ("common.rs").to_string(), line: (line!()) });
//                 if let Ok(answer) = answer {
//                     ans_vec.push(answer.value);
//                     println!("[{:?}] party {:?} => party {:?}", round, i, party_num);
//                     break;
//                 }
//             }
//         }
//     }
//     return Ok(ans_vec)
// }

pub async fn poll_for_broadcasts(
    client: &Client,
    addr: &str,
    party_num: u16,
    n: u16,
    round: &str,
    sender_uuid: String,
    delay: u32,
) -> Vec<String> {
    let mut ans_vec = Vec::new();
    for i in 1..=n {
        if i != party_num {
            let key = format!("{}-{}-{}", i, round, sender_uuid);
            let index = Index { key };
            loop {
                sleep(delay).await;
                // add delay to allow the server to process request:
                let res_body = postb(client, addr, "get", index.clone()).await.unwrap();
                let answer: Result<Entry, ()> = serde_json::from_str(&res_body).unwrap();
                if let Ok(answer) = answer {
                    ans_vec.push(answer.value);
                    println!("[{:?}] party {:?} => party {:?}", round, i, party_num);
                    break;
                }
            }
        }
    }
    ans_vec
}

pub async fn poll_for_p2p(
    client: &Client,
    addr: &str,
    party_num: u16,
    n: u16,
    delay: u32,
    round: &str,
    sender_uuid: String,
) -> Vec<String> {
    let mut ans_vec = Vec::new();
    for i in 1..=n {
        if i != party_num {
            let key = format!("{}-{}-{}-{}", i, party_num, round, sender_uuid);
            let index = Index { key };
            loop {
                // add delay to allow the server to process request:
                sleep(delay).await;
                let res_body = postb(client, addr, "get", index.clone()).await.unwrap();
                let answer: Result<Entry, ()> = serde_json::from_str(&res_body).unwrap();
                if let Ok(answer) = answer {
                    ans_vec.push(answer.value);
                    println!("[{:?}] party {:?} => party {:?}", round, i, party_num);
                    break;
                }
            }
        }
    }
    ans_vec
}

pub fn check_sig(r: &Scalar, s: &Scalar, msg: &BigInt, pk: &Point) -> Result<bool, TssError> {
    let r_vec = BigInt::to_vec(&r.to_big_int());
    let s_vec = BigInt::to_vec(&s.to_big_int());

    let mut signature_a = [0u8; 64];
    for i in 0..32 {
        signature_a[i] = r_vec[i];
    }
    for i in 0..32 {
        signature_a[i + 32] = s_vec[i];
    }

    let signature = secp256k1::Signature::parse(&signature_a);

    let msg_vec = BigInt::to_vec(msg);

    let message =
        secp256k1::Message::parse(&msg_vec.try_into().map_err(|_e| TssError::UnknownError {
            msg: ("check_sig").to_string(),
            file: ("common.rs").to_string(),
            line: (line!()),
        })?);

    let pubkey_a = pk.get_element().serialize();

    let pubkey = secp256k1::PublicKey::parse(&pubkey_a).map_err(|_e| TssError::UnknownError {
        msg: ("check_sig").to_string(),
        file: ("common.rs").to_string(),
        line: (line!()),
    })?;

    #[cfg(target_arch = "wasm32")]
    crate::console_log!("pubkey: {:?}", pubkey);
    #[cfg(target_arch = "wasm32")]
    crate::console_log!(
        "address: {:?}",
        checksum(&hex::encode(public_key_address(&pubkey)?))
    );
    Ok(secp256k1::verify(&message, &signature, &pubkey))
}

pub fn public_key_address(public_key: &secp256k1::PublicKey) -> Result<[u8; 20], TssError> {
    let public_key = public_key.serialize();
    debug_assert_eq!(public_key[0], 0x04);
    let hash = keccak256(&public_key[1..]);
    hash[12..32]
        .try_into()
        .map_err(|_e| TssError::UnknownError {
            msg: ("public_key_address").to_string(),
            file: ("common.rs").to_string(),
            line: (line!()),
        })
}

pub fn keccak256(bytes: &[u8]) -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak};
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    hasher.finalize(&mut output);
    output
}

const PREFIX: &str = "0x";

pub fn checksum(address: &str) -> Result<String, TssError> {
    let stripped = String::from(address.to_ascii_lowercase().trim_start_matches(PREFIX));

    let mut hasher = Keccak256::new();
    hasher.update(stripped.clone());
    let hash_vec = hasher.finalize().to_vec();
    let hash = hex::encode(hash_vec);

    let mut checksum = String::new();

    if address.len() != stripped.len() {
        checksum.push_str(PREFIX);
    }

    for (pos, char) in hash.chars().enumerate() {
        if pos > 39 {
            break;
        }
        if u32::from_str_radix(&char.to_string()[..], 16).map_err(|_e| TssError::UnknownError {
            msg: ("checkSum").to_string(),
            file: ("common.rs").to_string(),
            line: (line!()),
        })? > 7
        {
            checksum.push_str(&stripped[pos..pos + 1].to_ascii_uppercase());
        } else {
            checksum.push_str(&stripped[pos..pos + 1].to_ascii_lowercase());
        }
    }

    Ok(checksum)
}
