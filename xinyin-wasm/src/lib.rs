use xinyin::sks::SksStore;

use wasm_bindgen::{JsValue, prelude::wasm_bindgen};
use xinyin::{EncryptedSk, generate_words32, import_words32};

#[wasm_bindgen(raw_module = "./xinyinOPFS.js")]
extern "C" {
    #[wasm_bindgen(js_name = saveEncryptedSkBase64)]
    fn js_save_encrypted_sk_base64(sk: &str);
    #[wasm_bindgen(js_name = loadEncryptedSks)]
    fn js_load_encrypted_sks() -> Vec<String>;
}

#[wasm_bindgen]
pub fn sign_message(address: &str, message: &[u8], psw: &str) -> Result<Vec<u8>, JsValue> {
    let encrypted_sk = EncryptedSk::get_by_address(address, psw, &WebSksStore).map_err(|err| {
        JsValue::from_str(&format!(
            "get encrypted sk by address({}) failed: {:?}",
            address, err
        ))
    })?;

    match encrypted_sk.sign_message(message, psw) {
        Ok(signature) => Ok(signature),
        Err(err) => Err(JsValue::from_str(&format!(
            "sign message failed: {:?}",
            err
        ))),
    }
}

#[wasm_bindgen]
pub fn import_xinyin_words32(
    words32: &str,
    txt_in_heart: &str,
    start: usize,
    count: usize,
    psw: &str,
) -> Result<String, JsValue> {
    let sk = match import_words32(words32, txt_in_heart, start, count) {
        Ok(sk) => sk,
        Err(err) => {
            return Err(JsValue::from_str(&format!(
                "import words32 failed: {:?}",
                err
            )));
        }
    };

    let encrypted_sk = EncryptedSk::encrypt_sk(&sk, psw, &WebSksStore)
        .map_err(|err| JsValue::from_str(&format!("encrypt sk failed: {:?}", err)))?;

    Ok(encrypted_sk.address.clone())
}

#[wasm_bindgen]
pub fn generate_xinyin_words32(
    txt_in_heart: &str,
    start: usize,
    count: usize,
) -> Result<String, JsValue> {
    match generate_words32(txt_in_heart, start, count, None) {
        Ok(words32) => Ok(words32),
        Err(err) => Err(JsValue::from_str(&format!(
            "generate words32 failed: {:?}",
            err
        ))),
    }
}

struct WebSksStore;

impl SksStore for WebSksStore {
    fn save_encrypted_sk(&self, encrypted_sk_bs64: &str) -> anyhow::Result<()> {
        js_save_encrypted_sk_base64(encrypted_sk_bs64);
        Ok(())
    }

    fn load_encrypted_sks(&self) -> Vec<String> {
        js_load_encrypted_sks()
    }
}
