use anyhow::{Context, Result, ensure};
use argon2::{Algorithm, Argon2, Params, Version};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const WORDLIST: &str = include_str!("../data/slip39.txt");
pub const WORDLIST_SHA256: &str =
    "bcc4555340332d169718aed8bf31dd9d5248cb7da6e5d355140ef4f1e601eec3";
pub const WORD_COUNT: usize = 40;
const CHECKSUM_DOMAIN: &[u8] = b"gpg-keys/backup/v1\0";
const ENTROPY_DOMAIN: &[u8] = b"gpg-keys/entropy/v1";
pub type Secret = Zeroizing<[u8; 32]>;

pub fn random() -> Result<Secret> {
    let mut secret = Zeroizing::new([0; 32]);
    getrandom::fill(secret.as_mut()).map_err(|e| anyhow::anyhow!("OS randomness failed: {e}"))?;
    Ok(secret)
}

fn compact(input: &str) -> Zeroizing<String> {
    Zeroizing::new(input.chars().filter(|c| !c.is_ascii_whitespace()).collect())
}

fn binary_bytes(input: &str) -> Result<Zeroizing<Vec<u8>>> {
    let bits = compact(input);
    ensure!(
        bits.len().is_multiple_of(8),
        "binary input must contain whole bytes"
    );
    ensure!(
        bits.bytes().all(|b| b == b'0' || b == b'1'),
        "binary input must contain only 0, 1, and ASCII whitespace"
    );
    Ok(Zeroizing::new(
        bits.as_bytes()
            .as_chunks::<8>()
            .0
            .iter()
            .map(|chunk| chunk.iter().fold(0, |byte, bit| (byte << 1) | (bit - b'0')))
            .collect(),
    ))
}

pub fn parse_exact(input: &str, binary: bool) -> Result<Secret> {
    let mut secret = Zeroizing::new([0; 32]);
    if binary {
        let bytes = binary_bytes(input)?;
        ensure!(
            bytes.len() == 32,
            "exact secret must contain 256 binary digits"
        );
        secret.copy_from_slice(&bytes);
    } else {
        let input = compact(input);
        ensure!(
            input.len() == 64,
            "exact secret must contain 64 hexadecimal digits"
        );
        hex::decode_to_slice(input.as_bytes(), secret.as_mut())
            .context("invalid hexadecimal secret")?;
    }
    Ok(secret)
}

pub fn derive(input: &str) -> Result<Secret> {
    let entropy = binary_bytes(input)?;
    ensure!(
        entropy.len() >= 32,
        "provide at least 256 high-entropy binary digits"
    );
    let salt = Sha256::digest(ENTROPY_DOMAIN);
    let params = Params::new(65536, 3, 1, Some(32))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut secret = Zeroizing::new([0; 32]);
    argon.hash_password_into(&entropy, &salt[..16], secret.as_mut())?;
    Ok(secret)
}

fn checksum(body: &[u8]) -> [u8; 5] {
    let mut hash = Sha256::new();
    hash.update(CHECKSUM_DOMAIN);
    hash.update(body);
    hash.finalize()[..5]
        .try_into()
        .expect("fixed checksum length")
}

fn serialize(secret: &Secret) -> Zeroizing<[u8; 50]> {
    let mut bytes = Zeroizing::new([0; 50]);
    bytes[..4].copy_from_slice(b"GPKB");
    bytes[4] = 1;
    bytes[5..13].copy_from_slice(&Sha256::digest(WORDLIST.as_bytes())[..8]);
    bytes[13..45].copy_from_slice(secret.as_ref());
    let check = checksum(&bytes[..45]);
    bytes[45..].copy_from_slice(&check);
    bytes
}

pub fn encode(secret: &Secret) -> Zeroizing<String> {
    let bytes = serialize(secret);
    let words: Vec<_> = WORDLIST.lines().collect();
    let mut result = Zeroizing::new(String::new());
    for word in 0..WORD_COUNT {
        let mut index = 0;
        for bit in word * 10..word * 10 + 10 {
            index = (index << 1) | ((bytes[bit / 8] >> (7 - bit % 8)) & 1) as usize;
        }
        if word > 0 {
            result.push(' ');
        }
        result.push_str(words[index]);
    }
    result.push('\n');
    result
}

pub fn decode(input: &str) -> Result<Secret> {
    let tokens: Vec<_> = input.split_whitespace().collect();
    ensure!(
        tokens.len() == WORD_COUNT,
        "expected exactly {WORD_COUNT} words, found {}",
        tokens.len()
    );
    let words: Vec<_> = WORDLIST.lines().collect();
    let mut bytes = Zeroizing::new([0u8; 50]);
    for (position, token) in tokens.iter().enumerate() {
        // Do not include secret input in errors.
        let index = words
            .iter()
            .position(|word| word.eq_ignore_ascii_case(token))
            .with_context(|| format!("unknown word at position {}", position + 1))?;
        for offset in 0..10 {
            let bit = position * 10 + offset;
            bytes[bit / 8] |= (((index >> (9 - offset)) & 1) as u8) << (7 - bit % 8);
        }
    }
    ensure!(
        &bytes[..4] == b"GPKB",
        "invalid backup marker; this is not a SLIP-39 share"
    );
    ensure!(bytes[4] == 1, "unsupported scheme version {}", bytes[4]);
    ensure!(
        bytes[5..13] == Sha256::digest(WORDLIST.as_bytes())[..8],
        "wordlist hash mismatch"
    );
    ensure!(
        bytes[45..] == checksum(&bytes[..45]),
        "checksum mismatch; check the written words"
    );
    let mut secret = Zeroizing::new([0; 32]);
    secret.copy_from_slice(&bytes[13..45]);
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_python_vector() {
        let lines: Vec<_> = include_str!("../tests/vectors.txt").lines().collect();
        let secret = parse_exact(lines[0], false).unwrap();
        assert_eq!(hex::encode(serialize(&secret).as_ref()), lines[1]);
        assert_eq!(encode(&secret).trim(), lines[2]);
        assert_eq!(*decode(lines[2]).unwrap(), *secret);
    }

    #[test]
    fn kdf_is_reproducible_and_whitespace_independent() {
        let input = (0u8..32).map(|b| format!("{b:08b}")).collect::<String>();
        let seed = derive(&input).unwrap();
        let vector: Vec<_> = include_str!("../tests/vectors.txt").lines().collect();
        assert_eq!(hex::encode(seed.as_ref()), vector[3]);
        assert_eq!(
            *derive(
                &input
                    .as_bytes()
                    .chunks(8)
                    .map(|c| std::str::from_utf8(c).unwrap())
                    .collect::<Vec<_>>()
                    .join("\n")
            )
            .unwrap(),
            *seed
        );
        let mut changed = input;
        changed.replace_range(..1, "1");
        assert_ne!(*derive(&changed).unwrap(), *seed);
    }

    #[test]
    fn pinned_wordlist() {
        let words: Vec<_> = WORDLIST.lines().collect();
        assert_eq!(words.len(), 1024);
        assert_eq!(words[0], "academic");
        assert_eq!(words[1023], "zero");
        assert!(words.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(
            hex::encode(Sha256::digest(WORDLIST.as_bytes())),
            WORDLIST_SHA256
        );
    }

    #[test]
    fn roundtrip_and_transcription_errors() {
        for value in 0..=255 {
            let secret = Zeroizing::new([value; 32]);
            let mnemonic = encode(&secret);
            assert_eq!(*decode(&mnemonic.to_uppercase()).unwrap(), *secret);
        }
        let mnemonic = encode(&Zeroizing::new([42; 32]));
        let original: Vec<_> = mnemonic.split_whitespace().collect();
        for position in 0..WORD_COUNT {
            let mut words = original.clone();
            words[position] = if words[position] == "academic" {
                "zero"
            } else {
                "academic"
            };
            assert!(decode(&words.join(" ")).is_err());
        }
        assert!(decode(&original[..39].join(" ")).is_err());
        assert!(decode(&(mnemonic.to_string() + "zero")).is_err());
        let err = decode(&mnemonic.replacen(original[20], "SECRET_INPUT", 1)).unwrap_err();
        assert!(!err.to_string().contains("SECRET_INPUT"));
    }

    #[test]
    fn exact_input_validation() {
        assert_eq!(*parse_exact(&"ff".repeat(32), false).unwrap(), [255; 32]);
        assert_eq!(
            *parse_exact(&"10101010\n".repeat(32), true).unwrap(),
            [170; 32]
        );
        for input in ["", "00", &"f".repeat(63), &"g".repeat(64)] {
            assert!(parse_exact(input, false).is_err());
        }
        assert!(parse_exact(&"1".repeat(255), true).is_err());
        assert!(derive(&"1".repeat(248)).is_err());
        assert!(derive(&"2".repeat(256)).is_err());
    }

    #[test]
    fn rejects_valid_checksums_with_wrong_metadata() {
        for offset in [0, 4, 5] {
            let mut bytes = serialize(&Zeroizing::new([0; 32]));
            bytes[offset] ^= 1;
            let check = checksum(&bytes[..45]);
            bytes[45..].copy_from_slice(&check);
            let words: Vec<_> = WORDLIST.lines().collect();
            let mut mnemonic = String::new();
            for position in 0..40 {
                let index = (position * 10..position * 10 + 10).fold(0usize, |acc, bit| {
                    (acc << 1) | ((bytes[bit / 8] >> (7 - bit % 8)) & 1) as usize
                });
                mnemonic.push_str(words[index]);
                mnemonic.push(' ');
            }
            assert!(decode(&mnemonic).is_err());
        }
    }
}
