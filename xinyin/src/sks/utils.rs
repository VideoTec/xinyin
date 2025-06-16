use aes_gcm::{
    AeadCore, Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use anyhow::{Context, Result};
use argon2::Argon2;
use rand::{TryRngCore, rngs::OsRng};

pub(super) fn aes_gcm_decrypt(
    pwd: &str,
    salt: &[u8],
    vk_bs58: &str,
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> Result<[u8; 32]> {
    let aes_key = generate_aes_key(pwd, salt).context("failed to decrypt(aes-gcm) data")?;

    let cipher = Aes256Gcm::new(&aes_key.into());

    let plaintext = cipher
        .decrypt(
            &(*nonce).into(),
            Payload {
                aad: vk_bs58.as_bytes(),
                msg: ciphertext,
            },
        )
        .context("failed to decrypt(aes-gcm) data")?;

    let sk: [u8; 32] = plaintext
        .try_into()
        .map_err(|_| anyhow::anyhow!("decrypted(aes-gcm) data is not 32 bytes"))?;

    Ok(sk)
}

pub(super) fn aes_gcm_encrypt(
    pwd: &str,
    vk_bs58: &str,
    sk: &[u8; 32],
) -> Result<(Vec<u8>, [u8; 16], [u8; 12])> {
    let salt = generate_salt_from_rng()?;
    let aes_key = generate_aes_key(pwd, salt.as_ref())?;

    let cipher = Aes256Gcm::new(&aes_key.into());
    let nonce = Aes256Gcm::generate_nonce().context("failed to encrypt(aes-gcm) data")?;

    let ciphertext = cipher
        .encrypt(
            &nonce.into(),
            Payload {
                aad: vk_bs58.as_bytes(),
                msg: sk,
            },
        )
        .context("failed to encrypt(aes-gcm) data")?;

    Ok((ciphertext, salt, nonce.into()))
}

#[inline(always)]
fn generate_salt_from_rng() -> Result<[u8; 16]> {
    let mut salt = [0u8; 16];
    OsRng
        .try_fill_bytes(&mut salt)
        .context("failed to generate salt when osrng fill buffer")?;
    Ok(salt)
}

#[inline(always)]
fn generate_aes_key(pwd: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let mut aes_key = [0u8; 32];
    Argon2::default()
        .hash_password_into(pwd.as_bytes(), salt, &mut aes_key)
        .context("failed to generate aes key by argon2")?;
    Ok(aes_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_gcm_encrypt() {
        let vk_bs58 = "7tWEmKfxBwm517CQtbEVNNMGRQeZSN2gwuZWzmxkumTc";
        let pwd = "test-password";
        let sk = [
            194, 124, 163, 194, 143, 43, 107, 102, 250, 172, 57, 40, 79, 56, 100, 215, 145, 185,
            195, 196, 3, 98, 199, 30, 111, 112, 46, 51, 223, 108, 157, 199,
        ];

        let (encrypt_key, salt, nonce) =
            aes_gcm_encrypt(pwd, vk_bs58, &sk).expect("Failed to encrypt with AES-GCM");
        println!("AES-GCM encrypt result: {:?}", encrypt_key);

        let decrypted = aes_gcm_decrypt(pwd, &salt, vk_bs58, &nonce, &encrypt_key)
            .expect("Failed to decrypt with AES-GCM");

        assert_eq!(decrypted, sk);
    }
}
