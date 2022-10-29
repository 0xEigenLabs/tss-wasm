#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, TssError>;

#[derive(Error, Debug)]
pub enum TssError {
    #[error("Context create error")]
    ContextError,
    #[error("Unknown error: {msg}, {line}")]
    UnknownError { msg: String, line: u32 },
    #[error("json serialization error")]
    SerdeError(#[from] serde_json::Error),
    #[error("reqwest builder error")]
    RequestError(#[from] reqwest::Error),
    #[error("secp256k1 builder error")]
    Secp256k1Error(#[from] secp256k1::Error),
}

#[cfg(target_arch = "wasm32")]
impl Into<JsValue> for TssError {
    fn into(self) -> JsValue {
        JsValue::from_str(&format!("{:?}", self))
    }
}
