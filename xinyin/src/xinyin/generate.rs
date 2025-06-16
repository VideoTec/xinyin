use super::charset_256::generate_256_words;

/// 生成心印密钥
/// * `txt_in_heart`: 心印文本
/// * `start`: 1-based index, must be between 1 and 7600
/// * `count`: must be greater than 500
/// * `sk`: optional secret key, if not provided, a random one will be generated
pub fn generate_words32(
    txt_in_heart: &str,
    start: usize,
    count: usize,
    sk: Option<&[u8]>,
) -> Result<String> {
    let words = generate_256_words(txt_in_heart, start, count)
        .context("failed to generate charset256 words")?;

    let mut secret_key = match sk {
        Some(sk) => sk
            .try_into()
            .map_err(|_| anyhow::anyhow!("secret key must be 32 bytes"))?,
        None => {
            let mut secret_key = [0u8; 32];
            OsRng
                .try_fill_bytes(&mut secret_key)
                .context("osrng failed when generating xinyin secret key")?;
            secret_key
        }
    };

    encrypt_xinyin_key(txt_in_heart, &mut secret_key)?;

    let mut key_words: Vec<char> = Vec::new();
    for (_, &byte) in secret_key.iter().enumerate() {
        let index = byte as usize % words.len();
        key_words.push(words[index]);
    }

    Ok(key_words.into_iter().collect())
}

use super::utils::generate_cbc_key_iv;
use aes::{
    Aes256,
    cipher::{BlockModeEncrypt, KeyIvInit, block_padding::NoPadding},
};
use anyhow::{Context, Result};
use cbc::Encryptor;
use rand::{TryRngCore, rngs::OsRng};

type Aes256CbcEnc = Encryptor<Aes256>;

fn encrypt_xinyin_key(txt_in_heart: &str, sk: &mut [u8; 32]) -> Result<()> {
    let (aes_key, aes_iv) =
        generate_cbc_key_iv(txt_in_heart).context("failed to encrypt xinyin secret key")?;

    Aes256CbcEnc::new(&aes_key.into(), &aes_iv.into())
        .encrypt_padded::<NoPadding>(sk, 32)
        .context("failed to encrypt xinyin secret key")?;

    Ok(())
}
