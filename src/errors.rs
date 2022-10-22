#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, TssError>;

#[derive(Error, Debug)]
pub enum TssError {
    #[error("Context create error")]
    ContextError,
    #[error("Unknown error: {msg}, {file}, {line}")]
    UnknownError {
        msg: String,
        file: String,
        line: u32,
    },
}

#[cfg(target_arch = "wasm32")]
impl Into<JsValue> for TssError {
    fn into(self) -> JsValue {
        JsValue::from_str(&format!("{:?}", self))
    }
}
