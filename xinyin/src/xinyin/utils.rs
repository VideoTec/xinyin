use anyhow::{Context, Result};
use argon2::Argon2;
use sha2::Digest;

pub(super) fn generate_cbc_key_iv(txt_in_heart: &str) -> Result<([u8; 32], [u8; 16])> {
    let argon2_salt = sha2::Sha256::digest(format!("{}-as-argon2-salt", txt_in_heart).as_bytes());
    let aes_iv = sha2::Sha256::digest(format!("{}-as-aes-iv", txt_in_heart).as_bytes());

    let mut aes_key = [0u8; 32];
    Argon2::default()
        .hash_password_into(txt_in_heart.as_bytes(), &argon2_salt, &mut aes_key)
        .context("failed to generate cbc key")?;

    Ok((
        aes_key,
        aes_iv[0..16]
            .try_into()
            .context("cbc iv must be 16 bytes")?,
    ))
}
