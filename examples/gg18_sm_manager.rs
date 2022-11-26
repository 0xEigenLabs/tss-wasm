// #[cfg(not(target_arch = "wasm32"))]
// use rocket::fairing::{Fairing, Info, Kind};
#[cfg(not(target_arch = "wasm32"))]
use rocket::serde::json::Json;
#[cfg(not(target_arch = "wasm32"))]
use rocket::{post, routes, State};
// #[cfg(not(target_arch = "wasm32"))]
// use rocket::{Request, Response};
#[cfg(not(target_arch = "wasm32"))]
use rand::Rng;
#[cfg(not(target_arch = "wasm32"))]
use rocket_cors::{AllowedOrigins, CorsOptions};
#[cfg(not(target_arch = "wasm32"))]
use std::collections::HashMap;
#[cfg(not(target_arch = "wasm32"))]
use std::fs;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::RwLock;
#[cfg(not(target_arch = "wasm32"))]
use tss_wasm::common::{Entry, Index, Key, Params, PartySignup, PartySignup1};
#[cfg(not(target_arch = "wasm32"))]
use uuid::Uuid;

#[cfg(not(target_arch = "wasm32"))]
#[post("/get", format = "json", data = "<request>")]
fn get(
    db_mtx: &State<RwLock<HashMap<Key, String>>>,
    request: Json<Index>,
) -> Json<Result<Entry, ()>> {
    let index: Index = request.0;
    let hm = db_mtx.read().unwrap();
    match hm.get(&index.key) {
        Some(v) => {
            let entry = Entry {
                key: index.key,
                value: v.clone(),
            };
            Json(Ok(entry))
        }
        None => Json(Err(())),
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[post("/set", format = "json", data = "<request>")]
fn set(db_mtx: &State<RwLock<HashMap<Key, String>>>, request: Json<Entry>) -> Json<Result<(), ()>> {
    let entry: Entry = request.0;
    let mut hm = db_mtx.write().unwrap();
    hm.insert(entry.key.clone(), entry.value);
    Json(Ok(()))
}

#[cfg(not(target_arch = "wasm32"))]
#[post("/signupkeygen", format = "json")]
fn signup_keygen(db_mtx: &State<RwLock<HashMap<Key, String>>>) -> Json<Result<PartySignup, ()>> {
    let data = fs::read_to_string("params.json")
        .expect("Unable to read params, make sure config file is present in the same folder ");
    let params: Params = serde_json::from_str(&data).unwrap();
    let parties = params.parties.parse::<u16>().unwrap();

    let key = "signup-keygen".to_string();
    let key_partyid = "sum-partyid".to_string();

    let mut hm = db_mtx.write().unwrap();
    let party_signup: PartySignup = {
        let value = hm.get(&key).unwrap();
        let value_partyid = hm.get(&key_partyid).unwrap();
        let vector_partyid: Vec<u32> = value_partyid
            .chars()
            .flat_map(|ch| ch.to_digit(10))
            .collect();
        let tmp: u32 = vector_partyid.iter().sum();
        let sum_partyid = tmp as u16;
        let client_signup: PartySignup = serde_json::from_str(value).unwrap();
        let sum_parties = (0..parties + 1).fold(0, |a, b| a + b);
        if value_partyid.parse::<u16>().unwrap() == 0 {
            let num = rand::thread_rng().gen_range(0, parties);
            hm.insert(key_partyid, num.to_string());
            PartySignup {
                number: num,
                uuid: client_signup.uuid,
                is_client: 1,
            }
        } else if sum_partyid < sum_parties {
            let mut vector_parties: Vec<u32> = vec![];
            for i in 1..sum_parties {
                vector_parties.push(i.into());
            }
            let difference: Vec<u32> = vector_parties
                .into_iter()
                .filter(|item| !vector_partyid.contains(item))
                .collect();
            let tmp1 = format!("{}{}", value_partyid, difference[0].to_string());
            hm.insert(key_partyid, tmp1);
            PartySignup {
                number: difference[0] as u16,
                uuid: client_signup.uuid,
                is_client: 0,
            }
        } else {
            let num = rand::thread_rng().gen_range(0, parties);
            hm.insert(key_partyid, num.to_string());
            PartySignup {
                number: num,
                uuid: Uuid::new_v4().to_string(),
                is_client: 1,
            }
        }
    };

    hm.insert(key, serde_json::to_string(&party_signup).unwrap());
    Json(Ok(party_signup))
}

#[cfg(not(target_arch = "wasm32"))]
#[post("/signupsign", format = "json")]
fn signup_sign(db_mtx: &State<RwLock<HashMap<Key, String>>>) -> Json<Result<PartySignup1, ()>> {
    //read parameters:
    let data = fs::read_to_string("params.json")
        .expect("Unable to read params, make sure config file is present in the same folder ");
    let params: Params = serde_json::from_str(&data).unwrap();
    let threshold = params.threshold.parse::<u16>().unwrap();
    let key = "signup-sign".to_string();

    let mut hm = db_mtx.write().unwrap();
    let party_signup = {
        let value = hm.get(&key).unwrap();
        let client_signup: PartySignup1 = serde_json::from_str(value).unwrap();
        if client_signup.number < threshold + 1 {
            PartySignup1 {
                number: client_signup.number + 1,
                uuid: client_signup.uuid,
            }
        } else {
            PartySignup1 {
                number: 1,
                uuid: Uuid::new_v4().to_string(),
            }
        }
    };

    hm.insert(key, serde_json::to_string(&party_signup).unwrap());
    Json(Ok(party_signup))
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::main]
async fn main() {
    let db: HashMap<Key, String> = HashMap::new();
    let db_mtx = RwLock::new(db);

    /////////////////////////////////////////////////////////////////
    //////////////////////////init signups://////////////////////////
    /////////////////////////////////////////////////////////////////

    let keygen_key = "signup-keygen".to_string();
    let sign_key = "signup-sign".to_string();
    let party_id = "sum-partyid".to_string();

    let uuid_keygen = Uuid::new_v4().to_string();
    let uuid_sign = Uuid::new_v4().to_string();

    let party1 = 0;
    let is_client1 = 0;
    let sum_partyid = "0".to_string();
    let party_signup_keygen = PartySignup {
        number: party1,
        uuid: uuid_keygen,
        is_client: is_client1,
    };
    let party_signup_sign = PartySignup1 {
        number: party1,
        uuid: uuid_sign,
    };
    {
        let mut hm = db_mtx.write().unwrap();
        hm.insert(party_id, sum_partyid);
        hm.insert(
            keygen_key,
            serde_json::to_string(&party_signup_keygen).unwrap(),
        );
        hm.insert(sign_key, serde_json::to_string(&party_signup_sign).unwrap());
    }

    let cors = CorsOptions::default()
        .allowed_origins(AllowedOrigins::all())
        .allowed_methods(
            ["Get", "Post", "Patch"]
                .iter()
                .map(|s| std::str::FromStr::from_str(s).unwrap())
                .collect(),
        )
        .allow_credentials(true);

    /////////////////////////////////////////////////////////////////
    rocket::build()
        .mount("/", routes![get, set, signup_keygen, signup_sign])
        .attach(cors.to_cors().unwrap())
        .manage(db_mtx)
        .launch()
        .await
        .unwrap();
}

#[cfg(target_arch = "wasm32")]
fn main() {
    panic!("Unimplemented")
}
