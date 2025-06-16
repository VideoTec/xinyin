use std::usize;

use anyhow::{Result, bail};
use rand::{SeedableRng, seq::IndexedRandom};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

const WORDS: &str = include_str!("../../8105.bin");

/// * start: 1-based index
fn read_8105_slice(start: usize, len: usize) -> Result<Vec<char>> {
    if start < 1 || start > 7605 {
        bail!("start must be between 1 and 7605");
    }

    if len < 500 {
        bail!("count must be greater than 500");
    }

    let words = WORDS
        .chars()
        .skip(start - 1)
        .take(len)
        .collect::<Vec<char>>();
    if words.len() != len {
        bail!("expected {} characters, but got {}", len, words.len());
    }
    Ok(words)
}

pub(super) fn generate_256_words(
    text_in_heart: &str,
    start: usize,
    count: usize,
) -> Result<Vec<char>> {
    if start < 1 || start > 7600 {
        bail!("start must be between 1 and 7600");
    }

    if count <= 500 || count + start > 8105 {
        bail!(
            "count({}) must be greater than 500 and last index({}) must not exceed 8105",
            count,
            count + start
        );
    }

    let words = read_8105_slice(start, count)?;

    let sha_seed = Sha256::digest(text_in_heart.as_bytes());
    let mut chacha_rng = ChaCha20Rng::from_seed(sha_seed.into());

    let words_256 = words
        .choose_multiple(&mut chacha_rng, 256)
        .cloned()
        .collect::<Vec<char>>();
    if words_256.len() != 256 {
        bail!("expected 256 characters, but got {}", words_256.len());
    }
    Ok(words_256)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_8105_slice() {
        let res = read_8105_slice(6, 666);
        assert!(res.is_ok());
        let chars = res.unwrap();
        assert_eq!(chars[0], '厂');
        assert_eq!(chars[100], '互');
        assert_eq!(chars[665], '严');
        assert_eq!(chars.len(), 666);
    }

    #[test]
    fn test_generate() {
        let res = generate_256_words("hello", 6, 666);
        assert!(res.is_ok());
        let chars = res.unwrap();
        assert_eq!(chars[0], '勾');
        assert_eq!(chars[100], '危');
        assert_eq!(chars[200], '进');
        assert_eq!(chars[255], '它');
        assert_eq!(chars.len(), 256);
    }
}
