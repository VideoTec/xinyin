use super::charset_256::generate_256_words;
use anyhow::{Context, Result};

/// 导入心印密钥
pub fn import_words32(
    words32: &str,
    txt_in_heart: &str,
    start: usize,
    count: usize,
) -> Result<[u8; 32]> {
    let words = generate_256_words(txt_in_heart, start, count)
        .context("failed to generate Charset256 words")?;

    let mut key = [0u8; 32];
    for (i, word) in words32.chars().enumerate() {
        let index = words.iter().position(|&w| w == word).context(format!(
            "failed to import xinyin words32: word `{}` not found in 256-words",
            word
        ))?;
        key[i] = index as u8;
    }

    decrypt_xinyin_key(&mut key, txt_in_heart).context("failed to import xinyin words32")?;

    Ok(key)
}

use super::utils::generate_cbc_key_iv;
use aes::{
    Aes256,
    cipher::{BlockModeDecrypt, KeyIvInit, block_padding::NoPadding},
};
use cbc::Decryptor;
type Aes256CbcDec = Decryptor<Aes256>;

fn decrypt_xinyin_key(encrypted_key: &mut [u8; 32], txt_in_heart: &str) -> Result<()> {
    let (aes_key, aes_iv) =
        generate_cbc_key_iv(txt_in_heart).context("failed to decrypt xinyin secret key")?;

    Aes256CbcDec::new(&aes_key.into(), &aes_iv.into())
        .decrypt_padded::<NoPadding>(encrypted_key)
        .context("failed to decrypt xinyin secret key")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_import_words32() {
        let secret_key = import_words32(
            "问抖廷亿丙驯弗付屹节尔力麦叮计寻右右问丑幻坏丙忆天闪父旬力扑抖延",
            "不立文字",
            6,
            666,
        )
        .unwrap();
        assert_eq!(secret_key.len(), 32);
        assert_eq!(
            secret_key,
            [
                194, 124, 163, 194, 143, 43, 107, 102, 250, 172, 57, 40, 79, 56, 100, 215, 145,
                185, 195, 196, 3, 98, 199, 30, 111, 112, 46, 51, 223, 108, 157, 199
            ]
        );
    }
}
