/// sk - Secret key
mod utils;

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD as base64_engine};
use bs58::encode;
use ed25519_dalek::{SigningKey, ed25519::signature::SignerMut};
use std::{
    collections::HashMap,
    sync::{Arc, LazyLock, RwLock},
};
use utils::{aes_gcm_decrypt, aes_gcm_encrypt};
// use web_sys::console;

const SALT_SIZE: usize = 16;
const NONCE_SIZE: usize = 12;
/// secret key size for ed25519
const SK_SIZE: usize = 32;

type SecretKey = [u8; SK_SIZE];
type Nonce = [u8; NONCE_SIZE];
type Salt = [u8; SALT_SIZE];

static ENCRYPTED_SKS: LazyLock<RwLock<HashMap<String, Arc<EncryptedSk>>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

struct EncryptedSks;

impl EncryptedSks {
    fn get(address: &str) -> Result<Option<Arc<EncryptedSk>>> {
        match ENCRYPTED_SKS.read() {
            Ok(encrypted_sks) => Ok(encrypted_sks.get(address).cloned()),
            Err(_) => bail!("failed to read ENCRYPTED_SKS"),
        }
    }

    fn insert(address: &str, encrypted_sk: &Arc<EncryptedSk>) -> Result<()> {
        match ENCRYPTED_SKS.write() {
            Ok(mut encrypted_sks) => {
                encrypted_sks.insert(address.to_string(), encrypted_sk.clone());
                Ok(())
            }
            Err(_) => bail!("failed to write ENCRYPTED_SKS"),
        }
    }
}

pub trait SksStore {
    fn load_encrypted_sks(&self) -> Vec<String>;
    fn save_encrypted_sk(&self, encrypted_sk_bs64: &str) -> Result<()>;
}

#[derive(Debug, Eq, PartialEq)]
pub struct EncryptedSk {
    pub address: String,
    pub encrypted_sk: Vec<u8>,
    pub salt: Salt,
    pub nonce: Nonce,
}

impl EncryptedSk {
    /// Get an encrypted secret key by address
    pub fn get_by_address(address: &str, pwd: &str, store: &impl SksStore) -> Result<Arc<Self>> {
        if let Some(encrypted_sk) = EncryptedSks::get(address)? {
            if let Ok(_) = encrypted_sk.decrypt(pwd) {
                return Ok(encrypted_sk.clone());
            }
        }

        let address = address.to_string();
        // console::log_1(&format!("get encrypted sk by address: {}", address).into());
        // console::log_1(&format!("pwd: {}", pwd).into());

        for encrypted_sk_base64 in store.load_encrypted_sks() {
            let encrypted_sk = Self::from_base64(&encrypted_sk_base64, &address)
                .context("loop stored encrypted sks failed")?;

            if let Ok(_) = encrypted_sk.decrypt(pwd) {
                EncryptedSks::insert(&address, &encrypted_sk)
                    .context("failed to insert encrypted sk into cache")?;

                return Ok(encrypted_sk);
            }
        }

        bail!("secret key not found by address: {}", address);
    }

    pub fn encrypt_sk(sk: &SecretKey, pwd: &str, store: &impl SksStore) -> Result<Arc<Self>> {
        let signing_key = SigningKey::from_bytes(sk);
        let address = encode(signing_key.verifying_key().as_bytes()).into_string();

        if let Ok(encrypted_sk) = EncryptedSk::get_by_address(&address, pwd, store) {
            return Ok(encrypted_sk);
        }

        let (encrypted_sk, salt, nonce) = aes_gcm_encrypt(pwd, &address, sk)?;

        let encrypted_sk = Arc::new(EncryptedSk {
            address: address.clone(),
            encrypted_sk,
            salt,
            nonce,
        });

        store
            .save_encrypted_sk(&encrypted_sk.to_base64())
            .context("failed to save encrypted sk base64 to store")?;

        EncryptedSks::insert(&address, &encrypted_sk)
            .context("failed to insert encrypted sk into cache")?;

        Ok(encrypted_sk)
    }
}

impl EncryptedSk {
    pub fn sign_message(&self, message: &[u8], pwd: &str) -> Result<Vec<u8>> {
        let sk = self.decrypt(pwd).context("failed to sign message")?;

        let mut signing_key = SigningKey::from_bytes(&sk);

        let signature = signing_key
            .try_sign(message)
            .context("failed to sign message")?;

        Ok(signature.to_bytes().to_vec())
    }

    #[inline(always)]
    fn decrypt(&self, pwd: &str) -> Result<SecretKey> {
        aes_gcm_decrypt(
            pwd,
            &self.salt,
            &self.address,
            &self.nonce,
            &self.encrypted_sk,
        )
        .context("failed to decrypt encrypted sk")
    }

    fn to_base64(&self) -> String {
        let mut encrypted_sk_bin = Vec::new();
        encrypted_sk_bin.extend_from_slice(&self.salt);
        encrypted_sk_bin.extend_from_slice(&self.nonce);
        encrypted_sk_bin.extend_from_slice(&self.encrypted_sk);

        base64_engine.encode(&encrypted_sk_bin)
    }

    fn from_base64(encrypted_sk_base64: &str, address: &str) -> Result<Arc<Self>> {
        let encrypted_sk_bin = base64_engine.decode(encrypted_sk_base64).context(format!(
            "from_base64: failed to decode encrypted sk base64: {}",
            encrypted_sk_base64
        ))?;

        if encrypted_sk_bin.len() < (SALT_SIZE + NONCE_SIZE + SK_SIZE) {
            bail!(
                "from_base64: invalid encrypted sk bin length: {}",
                encrypted_sk_bin.len()
            );
        }

        let salt: Salt = encrypted_sk_bin[0..SALT_SIZE]
            .try_into()
            .context("from_base64: failed to parse salt")?;
        let nonce: Nonce = encrypted_sk_bin[SALT_SIZE..(SALT_SIZE + NONCE_SIZE)]
            .try_into()
            .context("from_base64: failed to parse nonce")?;
        let encrypted_sk: Vec<u8> = encrypted_sk_bin[SALT_SIZE + NONCE_SIZE..].to_vec();

        Ok(Arc::new(Self {
            salt,
            nonce,
            encrypted_sk,
            address: address.into(),
        }))
    }
}
