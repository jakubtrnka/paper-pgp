use anyhow::{Context, Result, bail, ensure};
use argon2::{Algorithm, Argon2, Params, Version};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

pub const WORDLIST: &str = include_str!("../data/slip39.txt");
pub const WORDLIST_SHA256: &str =
    "bcc4555340332d169718aed8bf31dd9d5248cb7da6e5d355140ef4f1e601eec3";
pub const SCHEME_VERSION: u8 = 1;
pub const COMPACT_WORD_COUNT: usize = 35;
pub const RAW_WORD_COUNT: usize = 44;
const MAGIC: &[u8; 4] = b"GPKB";
const WORDLIST_ID: [u8; 8] = [0xbc, 0xc4, 0x55, 0x53, 0x40, 0x33, 0x2d, 0x16];
const HEADER_LEN: usize = 18;
const CHECKSUM_LEN: usize = 5;
const CHECKSUM_DOMAIN: &[u8] = b"gpg-keys/backup/v1\0";
const ENTROPY_DOMAIN: &[u8] = b"gpg-keys/entropy/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretKind {
    Raw,
    CompactEntropy,
}

impl SecretKind {
    pub fn tag(self) -> u8 {
        match self {
            Self::Raw => 0,
            Self::CompactEntropy => 1,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::CompactEntropy => "compact",
        }
    }

    pub fn payload_len(self) -> usize {
        match self {
            Self::Raw => 32,
            Self::CompactEntropy => 20,
        }
    }

    pub fn word_count(self) -> usize {
        match self {
            Self::Raw => RAW_WORD_COUNT,
            Self::CompactEntropy => COMPACT_WORD_COUNT,
        }
    }

    fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            0 => Ok(Self::Raw),
            1 => Ok(Self::CompactEntropy),
            _ => bail!("unsupported secret variant tag {tag}"),
        }
    }
}

#[derive(PartialEq, Eq)]
pub enum BackupSecret {
    /// Native Ed25519 private seed: used directly, without HKDF.
    Raw(Zeroizing<[u8; 32]>),
    /// Backup entropy: expanded to the native private seed with HKDF.
    CompactEntropy(Zeroizing<[u8; 20]>),
}

impl BackupSecret {
    pub fn kind(&self) -> SecretKind {
        match self {
            Self::Raw(_) => SecretKind::Raw,
            Self::CompactEntropy(_) => SecretKind::CompactEntropy,
        }
    }

    pub fn payload(&self) -> &[u8] {
        match self {
            Self::Raw(seed) => seed.as_ref(),
            Self::CompactEntropy(seed) => seed.as_ref(),
        }
    }

    fn from_payload(kind: SecretKind, payload: &[u8]) -> Result<Self> {
        ensure!(
            payload.len() == kind.payload_len(),
            "incorrect secret payload length"
        );
        Ok(match kind {
            SecretKind::Raw => {
                let mut seed = Zeroizing::new([0; 32]);
                seed.copy_from_slice(payload);
                Self::Raw(seed)
            }
            SecretKind::CompactEntropy => {
                let mut seed = Zeroizing::new([0; 20]);
                seed.copy_from_slice(payload);
                Self::CompactEntropy(seed)
            }
        })
    }
}

impl fmt::Debug for BackupSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple(match self.kind() {
            SecretKind::Raw => "Raw",
            SecretKind::CompactEntropy => "CompactEntropy",
        })
        .field(&"<redacted>")
        .finish()
    }
}

/// Validated recovery record. Magic, checksum, and word-padding belong to its
/// binary envelope, rather than mutable fields of this logical structure.
#[derive(Debug, PartialEq, Eq)]
pub struct Backup {
    version: u8,
    wordlist_id: [u8; 8],
    created_at: u32,
    secret: BackupSecret,
}

impl Backup {
    pub fn new(secret: BackupSecret, created_at: u32) -> Self {
        Self {
            version: SCHEME_VERSION,
            wordlist_id: WORDLIST_ID,
            created_at,
            secret,
        }
    }

    pub fn new_now(secret: BackupSecret) -> Result<Self> {
        Ok(Self::new(secret, timestamp(SystemTime::now())?))
    }

    pub fn version(&self) -> u8 {
        self.version
    }
    pub fn wordlist_id(&self) -> &[u8; 8] {
        &self.wordlist_id
    }
    pub fn created_at(&self) -> u32 {
        self.created_at
    }
    pub fn secret(&self) -> &BackupSecret {
        &self.secret
    }
    pub fn kind(&self) -> SecretKind {
        self.secret.kind()
    }
    pub fn word_count(&self) -> usize {
        self.kind().word_count()
    }

    /// GPKB | version | wordlist ID | BE32(created_at) | tag | payload | checksum.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(
            HEADER_LEN + self.kind().payload_len() + CHECKSUM_LEN,
        ));
        bytes.extend_from_slice(MAGIC);
        bytes.push(self.version);
        bytes.extend_from_slice(&self.wordlist_id);
        bytes.extend_from_slice(&self.created_at.to_be_bytes());
        bytes.push(self.kind().tag());
        bytes.extend_from_slice(self.secret.payload());
        let check = checksum(&bytes);
        bytes.extend_from_slice(&check);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() >= HEADER_LEN + CHECKSUM_LEN, "truncated backup");
        ensure!(
            &bytes[..4] == MAGIC,
            "invalid backup marker; this is not a SLIP-39 share"
        );
        ensure!(
            bytes[4] == SCHEME_VERSION,
            "unsupported scheme version {}",
            bytes[4]
        );
        ensure!(bytes[5..13] == WORDLIST_ID, "wordlist hash mismatch");
        let kind = SecretKind::from_tag(bytes[17])?;
        let body_len = HEADER_LEN + kind.payload_len();
        ensure!(
            bytes.len() == body_len + CHECKSUM_LEN,
            "backup length does not match its secret variant"
        );
        ensure!(
            bytes[body_len..] == checksum(&bytes[..body_len]),
            "checksum mismatch; check the written words"
        );
        let created_at =
            u32::from_be_bytes(bytes[13..17].try_into().expect("fixed timestamp width"));
        Ok(Self::new(
            BackupSecret::from_payload(kind, &bytes[HEADER_LEN..body_len])?,
            created_at,
        ))
    }

    pub fn encode(&self) -> Zeroizing<String> {
        encode_bytes(&self.to_bytes())
    }

    pub fn decode(input: &str) -> Result<Self> {
        let tokens: Vec<_> = input.split_whitespace().collect();
        let byte_len = match tokens.len() {
            COMPACT_WORD_COUNT => HEADER_LEN + 20 + CHECKSUM_LEN,
            RAW_WORD_COUNT => HEADER_LEN + 32 + CHECKSUM_LEN,
            count => bail!(
                "expected {COMPACT_WORD_COUNT} compact or {RAW_WORD_COUNT} raw words, found {count}"
            ),
        };
        let words: Vec<_> = WORDLIST.lines().collect();
        let mut bytes = Zeroizing::new(vec![0u8; byte_len]);
        for (position, token) in tokens.iter().enumerate() {
            let index = words
                .iter()
                .position(|word| word.eq_ignore_ascii_case(token))
                .with_context(|| format!("unknown word at position {}", position + 1))?;
            for offset in 0..10 {
                let bit = position * 10 + offset;
                let value = ((index >> (9 - offset)) & 1) as u8;
                if bit < byte_len * 8 {
                    bytes[bit / 8] |= value << (7 - bit % 8);
                } else {
                    ensure!(value == 0, "nonzero word-padding bits");
                }
            }
        }
        Self::from_bytes(&bytes)
    }
}

pub fn timestamp(time: SystemTime) -> Result<u32> {
    time.duration_since(UNIX_EPOCH)
        .context("creation time precedes Unix epoch")?
        .as_secs()
        .try_into()
        .context("creation time exceeds OpenPGP's 32-bit timestamp range")
}

pub fn random() -> Result<BackupSecret> {
    let mut entropy = Zeroizing::new([0; 20]);
    getrandom::fill(entropy.as_mut()).map_err(|e| anyhow::anyhow!("OS randomness failed: {e}"))?;
    Ok(BackupSecret::CompactEntropy(entropy))
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

pub fn parse_exact(input: &str, binary: bool, kind: SecretKind) -> Result<BackupSecret> {
    let payload = if binary {
        let bytes = binary_bytes(input)?;
        ensure!(
            bytes.len() == kind.payload_len(),
            "exact {} secret must contain {} binary digits",
            kind.name(),
            kind.payload_len() * 8
        );
        bytes
    } else {
        let input = compact(input);
        ensure!(
            input.len() == kind.payload_len() * 2,
            "exact {} secret must contain {} hexadecimal digits",
            kind.name(),
            kind.payload_len() * 2
        );
        let mut bytes = Zeroizing::new(vec![0; kind.payload_len()]);
        hex::decode_to_slice(input.as_bytes(), &mut bytes).context("invalid hexadecimal secret")?;
        bytes
    };
    BackupSecret::from_payload(kind, &payload)
}

pub fn derive(input: &str) -> Result<BackupSecret> {
    let entropy = binary_bytes(input)?;
    ensure!(
        entropy.len() >= 20,
        "provide at least 160 high-entropy binary digits"
    );
    let salt = Sha256::digest(ENTROPY_DOMAIN);
    let params = Params::new(65536, 3, 1, Some(20))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut secret = Zeroizing::new([0; 20]);
    argon.hash_password_into(&entropy, &salt[..16], secret.as_mut())?;
    Ok(BackupSecret::CompactEntropy(secret))
}

fn checksum(body: &[u8]) -> [u8; CHECKSUM_LEN] {
    let mut hash = Sha256::new();
    hash.update(CHECKSUM_DOMAIN);
    hash.update(body);
    hash.finalize()[..CHECKSUM_LEN]
        .try_into()
        .expect("fixed checksum length")
}

fn encode_bytes(bytes: &[u8]) -> Zeroizing<String> {
    let words: Vec<_> = WORDLIST.lines().collect();
    let count = (bytes.len() * 8).div_ceil(10);
    let mut result = Zeroizing::new(String::new());
    for word in 0..count {
        let mut index = 0;
        for bit in word * 10..word * 10 + 10 {
            let value = if bit < bytes.len() * 8 {
                (bytes[bit / 8] >> (7 - bit % 8)) & 1
            } else {
                0
            };
            index = (index << 1) | value as usize;
        }
        if word > 0 {
            result.push(' ');
        }
        result.push_str(words[index]);
    }
    result.push('\n');
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn examples(value: u8) -> [Backup; 2] {
        [
            Backup::new(
                BackupSecret::CompactEntropy(Zeroizing::new([value; 20])),
                1767225600,
            ),
            Backup::new(BackupSecret::Raw(Zeroizing::new([value; 32])), 1700000000),
        ]
    }

    #[test]
    fn independent_vectors() {
        for line in include_str!("../tests/vectors.txt").lines().take(2) {
            let v: Vec<_> = line.split('\t').collect();
            let kind = if v[0] == "raw" {
                SecretKind::Raw
            } else {
                SecretKind::CompactEntropy
            };
            let backup = Backup::new(
                parse_exact(v[2], false, kind).unwrap(),
                v[1].parse().unwrap(),
            );
            assert_eq!(hex::encode(backup.to_bytes().as_slice()), v[3]);
            assert_eq!(backup.encode().trim(), v[4]);
            assert_eq!(Backup::decode(v[4]).unwrap(), backup);
            assert_eq!(Backup::from_bytes(&backup.to_bytes()).unwrap(), backup);
        }
    }

    #[test]
    fn kdf_is_reproducible_and_matches_reference() {
        let v: Vec<_> = include_str!("../tests/vectors.txt")
            .lines()
            .nth(2)
            .unwrap()
            .split('\t')
            .collect();
        let input = hex::decode(v[1])
            .unwrap()
            .iter()
            .map(|b| format!("{b:08b}"))
            .collect::<String>();
        let secret = derive(&input).unwrap();
        assert_eq!(hex::encode(secret.payload()), v[2]);
        let spaced = input
            .as_bytes()
            .chunks(8)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(derive(&spaced).unwrap(), secret);
        let mut changed = input;
        changed.replace_range(..1, "1");
        assert_ne!(derive(&changed).unwrap(), secret);
    }

    #[test]
    fn pinned_wordlist() {
        let words: Vec<_> = WORDLIST.lines().collect();
        assert_eq!(words.len(), 1024);
        assert_eq!(words[0], "academic");
        assert_eq!(words[1023], "zero");
        assert!(words.windows(2).all(|pair| pair[0] < pair[1]));
        let digest = Sha256::digest(WORDLIST.as_bytes());
        assert_eq!(hex::encode(digest), WORDLIST_SHA256);
        assert_eq!(digest[..8], WORDLIST_ID);
    }

    #[test]
    fn roundtrip_and_transcription_errors() {
        for value in 0..=255 {
            for backup in examples(value) {
                assert_eq!(
                    Backup::decode(&backup.encode().to_uppercase()).unwrap(),
                    backup
                );
                assert_eq!(
                    backup.encode().split_whitespace().count(),
                    backup.word_count()
                );
            }
        }
        for backup in examples(42) {
            let mnemonic = backup.encode();
            let original: Vec<_> = mnemonic.split_whitespace().collect();
            for position in 0..original.len() {
                let mut words = original.clone();
                words[position] = if words[position] == "academic" {
                    "zero"
                } else {
                    "academic"
                };
                assert!(Backup::decode(&words.join(" ")).is_err());
            }
            assert!(Backup::decode(&original[..original.len() - 1].join(" ")).is_err());
            assert!(Backup::decode(&(mnemonic.to_string() + "zero")).is_err());
            let err =
                Backup::decode(&mnemonic.replacen(original[20], "SECRET_INPUT", 1)).unwrap_err();
            assert!(!err.to_string().contains("SECRET_INPUT"));
        }
    }

    #[test]
    fn rejects_nonzero_padding() {
        let backup = examples(42).into_iter().next().unwrap();
        let encoded = backup.encode();
        let original: Vec<_> = encoded.split_whitespace().collect();
        let wordlist: Vec<_> = WORDLIST.lines().collect();
        let index = wordlist
            .iter()
            .position(|word| *word == original[34])
            .unwrap();
        assert_eq!(index & 63, 0);
        for bit in 0..6 {
            let mut words = original.clone();
            words[34] = wordlist[index | (1 << bit)];
            assert!(
                Backup::decode(&words.join(" "))
                    .unwrap_err()
                    .to_string()
                    .contains("padding")
            );
        }
    }

    #[test]
    fn rejects_bad_metadata_lengths_and_checksums() {
        for backup in examples(0) {
            let bytes = backup.to_bytes();
            for length in 0..bytes.len() {
                assert!(Backup::from_bytes(&bytes[..length]).is_err());
            }
            let mut extended = bytes.clone();
            extended.push(0);
            assert!(Backup::from_bytes(&extended).is_err());
            for offset in [0, 4, 5, 17] {
                let mut changed = bytes.clone();
                changed[offset] = if offset == 17 { 2 } else { changed[offset] ^ 1 };
                let body_len = changed.len() - CHECKSUM_LEN;
                let check = checksum(&changed[..body_len]);
                changed[body_len..].copy_from_slice(&check);
                assert!(Backup::from_bytes(&changed).is_err());
            }
            let mut changed = bytes.clone();
            changed[17] ^= 1;
            assert!(Backup::from_bytes(&changed).is_err());
            // The magic, timestamp, variant and payload are all checksum-covered.
            for offset in 0..bytes.len() {
                let mut changed = bytes.clone();
                changed[offset] ^= 1;
                assert!(Backup::from_bytes(&changed).is_err());
            }
        }
    }

    #[test]
    fn exact_input_validation_and_redacted_debug() {
        for kind in [SecretKind::Raw, SecretKind::CompactEntropy] {
            let input = "ff".repeat(kind.payload_len());
            let secret = parse_exact(&input, false, kind).unwrap();
            assert_eq!(secret.payload(), vec![255; kind.payload_len()]);
            assert_eq!(
                parse_exact(&"11111111\n".repeat(kind.payload_len()), true, kind).unwrap(),
                secret
            );
            for bad in [
                "",
                "00",
                &"f".repeat(input.len() - 1),
                &"g".repeat(input.len()),
            ] {
                assert!(parse_exact(bad, false, kind).is_err());
            }
            assert!(parse_exact(&"1".repeat(kind.payload_len() * 8 - 1), true, kind).is_err());
            let debug = format!("{:?}", Backup::new(secret, 1700000000));
            assert!(debug.contains("<redacted>"));
            assert!(!debug.contains(&input));
        }
        assert!(derive(&"1".repeat(152)).is_err());
        assert!(derive(&"2".repeat(160)).is_err());
        assert!(timestamp(UNIX_EPOCH - std::time::Duration::from_secs(1)).is_err());
        assert!(
            timestamp(UNIX_EPOCH + std::time::Duration::from_secs(u32::MAX as u64 + 1)).is_err()
        );
    }
}
