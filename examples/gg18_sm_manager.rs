#[cfg(not(target_arch = "wasm32"))]
use rocket::fairing::{Fairing, Info, Kind};
#[cfg(not(target_arch = "wasm32"))]
use rocket::serde::json::Json;
#[cfg(not(target_arch = "wasm32"))]
use rocket::{post, routes, State};
#[cfg(not(target_arch = "wasm32"))]
use rocket::{Request, Response};
#[cfg(not(target_arch = "wasm32"))]
use rocket_cors::{AllowedHeaders, AllowedOrigins, CorsOptions};
#[cfg(not(target_arch = "wasm32"))]
use std::collections::HashMap;
#[cfg(not(target_arch = "wasm32"))]
use std::fs;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::RwLock;
#[cfg(not(target_arch = "wasm32"))]
use tss_wasm::common::{Entry, Index, Key, Params, PartySignup};
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

    let party_signup = {
        let hm = db_mtx.read().unwrap();
        let value = hm.get(&key).unwrap();
        let client_signup: PartySignup = serde_json::from_str(value).unwrap();
        if client_signup.number < parties {
            PartySignup {
                number: client_signup.number + 1,
                uuid: client_signup.uuid,
            }
        } else {
            PartySignup {
                number: 1,
                uuid: Uuid::new_v4().to_string(),
            }
        }
    };

    let mut hm = db_mtx.write().unwrap();
    hm.insert(key, serde_json::to_string(&party_signup).unwrap());
    Json(Ok(party_signup))
}

#[cfg(not(target_arch = "wasm32"))]
#[post("/signupsign", format = "json")]
fn signup_sign(db_mtx: &State<RwLock<HashMap<Key, String>>>) -> Json<Result<PartySignup, ()>> {
    //read parameters:
    let data = fs::read_to_string("params.json")
        .expect("Unable to read params, make sure config file is present in the same folder ");
    let params: Params = serde_json::from_str(&data).unwrap();
    let threshold = params.threshold.parse::<u16>().unwrap();
    let key = "signup-sign".to_string();

    let party_signup = {
        let hm = db_mtx.read().unwrap();
        let value = hm.get(&key).unwrap();
        let client_signup: PartySignup = serde_json::from_str(value).unwrap();
        if client_signup.number < threshold + 1 {
            PartySignup {
                number: client_signup.number + 1,
                uuid: client_signup.uuid,
            }
        } else {
            PartySignup {
                number: 1,
                uuid: Uuid::new_v4().to_string(),
            }
        }
    };

    let mut hm = db_mtx.write().unwrap();
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

    let uuid_keygen = Uuid::new_v4().to_string();
    let uuid_sign = Uuid::new_v4().to_string();

    let party1 = 0;
    let party_signup_keygen = PartySignup {
        number: party1,
        uuid: uuid_keygen,
    };
    let party_signup_sign = PartySignup {
        number: party1,
        uuid: uuid_sign,
    };
    {
        let mut hm = db_mtx.write().unwrap();
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
        //.attach(CORS)
        .attach(cors.to_cors().unwrap())
        .manage(db_mtx)
        .launch()
        .await
        .unwrap();
}

#[cfg(target_arch = "wasm32")]
fn main() {}
