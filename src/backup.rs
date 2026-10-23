use anyhow::{Context, Result, bail, ensure};
use argon2::{Algorithm, Argon2, Block, Params, Version};
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
/// Nineteen data words followed by three checksum words.
pub const WORD_COUNT: usize = DATA_WORDS + CHECKSUM_WORDS;
pub const ENTROPY_LEN: usize = 20;
/// Low bits of the creation time that are not stored: the stored time is a
/// multiple of 1024 seconds.
pub const TIME_SHIFT: u32 = 10;
const DATA_WORDS: usize = 19;
const CHECKSUM_WORDS: usize = 3;
const VERSION_BITS: u32 = 8;
const TIME_BITS: u32 = 32 - TIME_SHIFT;
/// rs1024 customization string; a SLIP-39 share uses "shamir".
const CUSTOMIZATION: &[u8] = b"gpkb";
const ENTROPY_DOMAIN: &[u8] = b"GPG Key Backup v1 entropy";
/// SLIP-0039 rs1024 generator constants.
const GEN: [u32; 10] = [
    0xe0e040, 0x1c1c080, 0x3838100, 0x7070200, 0xe0e0009, 0x1c0c2412, 0x38086c24, 0x3090fc48,
    0x21b1f890, 0x3f3f120,
];
const _: () = assert!(
    VERSION_BITS as usize + TIME_BITS as usize + ENTROPY_LEN * 8 == DATA_WORDS * 10,
    "the data fields must fill the data words exactly"
);

pub type Entropy = Zeroizing<[u8; ENTROPY_LEN]>;
pub type Symbols = Zeroizing<[u16; WORD_COUNT]>;

/// Validated recovery record: the scheme version, the primary key's creation
/// time rounded down to 1024 seconds, and the 20-byte entropy that HKDF
/// expands to the Ed25519 seed. The checksum belongs to the word envelope.
#[derive(PartialEq, Eq)]
pub struct Backup {
    version: u8,
    created_at: u32,
    secret: Entropy,
}

impl fmt::Debug for Backup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Backup")
            .field("version", &self.version)
            .field("created_at", &self.created_at)
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl Backup {
    /// `created_at` is rounded down to a multiple of 1024 seconds.
    pub fn new(secret: Entropy, created_at: u32) -> Self {
        Self {
            version: SCHEME_VERSION,
            created_at: created_at & !((1 << TIME_SHIFT) - 1),
            secret,
        }
    }

    pub fn new_now(secret: Entropy) -> Result<Self> {
        Ok(Self::new(secret, timestamp(SystemTime::now())?))
    }

    pub fn version(&self) -> u8 {
        self.version
    }
    pub fn created_at(&self) -> u32 {
        self.created_at
    }
    pub fn creation_time(&self) -> SystemTime {
        UNIX_EPOCH + std::time::Duration::from_secs(u64::from(self.created_at))
    }
    pub fn secret(&self) -> &[u8; ENTROPY_LEN] {
        &self.secret
    }

    /// All word indices: version | created_at >> 10 | entropy, packed most
    /// significant bit first into 19 ten-bit words, then 3 checksum words.
    pub fn symbols(&self) -> Symbols {
        let mut symbols = Zeroizing::new([0u16; WORD_COUNT]);
        let mut writer = BitWriter::new(&mut symbols[..DATA_WORDS]);
        writer.push(u64::from(self.version), VERSION_BITS);
        writer.push(u64::from(self.created_at >> TIME_SHIFT), TIME_BITS);
        for byte in self.secret.iter() {
            writer.push(u64::from(*byte), 8);
        }
        debug_assert_eq!(writer.position, DATA_WORDS * 10);
        let check = checksum(&symbols[..DATA_WORDS]);
        symbols[DATA_WORDS..].copy_from_slice(&check);
        symbols
    }

    pub fn from_symbols(symbols: &[u16]) -> Result<Self> {
        ensure!(
            symbols.len() == WORD_COUNT,
            "expected {WORD_COUNT} words, found {}",
            symbols.len()
        );
        ensure!(symbols.iter().all(|&s| s < 1024), "word index out of range");
        if !verify_checksum(symbols) {
            bail!("{}", diagnose(symbols));
        }
        let mut reader = BitReader::new(&symbols[..DATA_WORDS]);
        let version = reader.take(VERSION_BITS) as u8;
        ensure!(
            version == SCHEME_VERSION,
            "unsupported scheme version {version}"
        );
        let created_at = (reader.take(TIME_BITS) as u32) << TIME_SHIFT;
        let mut secret = Zeroizing::new([0u8; ENTROPY_LEN]);
        for byte in secret.iter_mut() {
            *byte = reader.take(8) as u8;
        }
        Ok(Self {
            version,
            created_at,
            secret,
        })
    }

    pub fn encode(&self) -> Zeroizing<String> {
        let words: Vec<_> = WORDLIST.lines().collect();
        let max_word_len = words.iter().map(|word| word.len()).max().unwrap();
        let symbols = self.symbols();
        // One separator per word includes the final newline.
        let mut result = Zeroizing::new(String::with_capacity(WORD_COUNT * (max_word_len + 1)));
        for (position, &symbol) in symbols.iter().enumerate() {
            if position > 0 {
                result.push(' ');
            }
            result.push_str(words[usize::from(symbol)]);
        }
        result.push('\n');
        result
    }

    pub fn decode(input: &str) -> Result<Self> {
        let tokens: Vec<_> = input.split_whitespace().collect();
        ensure!(
            tokens.len() == WORD_COUNT,
            "expected {WORD_COUNT} words, found {}",
            tokens.len()
        );
        let words: Vec<_> = WORDLIST.lines().collect();
        let mut symbols = Zeroizing::new([0u16; WORD_COUNT]);
        for (position, token) in tokens.iter().enumerate() {
            let index = words
                .iter()
                .position(|word| word.eq_ignore_ascii_case(token))
                .with_context(|| format!("unknown word at position {}", position + 1))?;
            symbols[position] = index as u16;
        }
        Self::from_symbols(&symbols[..])
    }
}

struct BitWriter<'a> {
    symbols: &'a mut [u16],
    position: usize,
}

impl<'a> BitWriter<'a> {
    fn new(symbols: &'a mut [u16]) -> Self {
        Self {
            symbols,
            position: 0,
        }
    }

    fn push(&mut self, value: u64, width: u32) {
        for bit in (0..width).rev() {
            if (value >> bit) & 1 == 1 {
                self.symbols[self.position / 10] |= 1 << (9 - self.position % 10);
            }
            self.position += 1;
        }
    }
}

struct BitReader<'a> {
    symbols: &'a [u16],
    position: usize,
}

impl<'a> BitReader<'a> {
    fn new(symbols: &'a [u16]) -> Self {
        Self {
            symbols,
            position: 0,
        }
    }

    fn take(&mut self, width: u32) -> u64 {
        let mut value = 0;
        for _ in 0..width {
            let bit = (self.symbols[self.position / 10] >> (9 - self.position % 10)) & 1;
            value = (value << 1) | u64::from(bit);
            self.position += 1;
        }
        value
    }
}

fn polymod(values: impl IntoIterator<Item = u16>) -> u32 {
    let mut chk: u32 = 1;
    for value in values {
        let b = chk >> 20;
        chk = ((chk & 0xfffff) << 10) ^ u32::from(value);
        for (i, generator) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= generator;
            }
        }
    }
    chk
}

fn customization() -> impl Iterator<Item = u16> {
    CUSTOMIZATION.iter().map(|&c| u16::from(c))
}

fn checksum(data: &[u16]) -> [u16; CHECKSUM_WORDS] {
    let polymod = polymod(
        customization()
            .chain(data.iter().copied())
            .chain([0; CHECKSUM_WORDS]),
    ) ^ 1;
    std::array::from_fn(|i| ((polymod >> (10 * (CHECKSUM_WORDS - 1 - i))) & 1023) as u16)
}

fn verify_checksum(symbols: &[u16]) -> bool {
    polymod(customization().chain(symbols.iter().copied())) == 1
}

/// Locate a single wrong word. rs1024 has minimum distance 4, so at most one
/// single-word substitution can make the sequence valid. Only the position is
/// reported, never the word; a sequence with three wrong words can be one
/// substitution away from a different valid backup.
fn diagnose(symbols: &[u16]) -> String {
    let mut trial = Zeroizing::new([0u16; WORD_COUNT]);
    trial.copy_from_slice(symbols);
    let mut found = None;
    for position in 0..WORD_COUNT {
        let original = trial[position];
        for alternative in 0..1024u16 {
            if alternative != original {
                trial[position] = alternative;
                if verify_checksum(&trial[..]) {
                    found = Some(position + 1);
                }
            }
        }
        trial[position] = original;
    }
    match found {
        Some(position) => format!("checksum mismatch; word {position} is probably wrong"),
        None => "checksum mismatch; at least two words are wrong".to_string(),
    }
}

pub fn timestamp(time: SystemTime) -> Result<u32> {
    time.duration_since(UNIX_EPOCH)
        .context("creation time precedes Unix epoch")?
        .as_secs()
        .try_into()
        .context("creation time exceeds OpenPGP's 32-bit timestamp range")
}

pub fn random() -> Result<Entropy> {
    let mut entropy = Zeroizing::new([0; ENTROPY_LEN]);
    getrandom::fill(entropy.as_mut()).map_err(|e| anyhow::anyhow!("OS randomness failed: {e}"))?;
    Ok(entropy)
}

fn compact(input: &str) -> Zeroizing<String> {
    // Reserve before copying secrets: reallocations would leave unwiped copies.
    let mut result = Zeroizing::new(String::with_capacity(input.len()));
    for c in input.chars().filter(|c| !c.is_ascii_whitespace()) {
        result.push(c);
    }
    result
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
    let mut bytes = Zeroizing::new(vec![0; bits.len() / 8]);
    for (byte, chunk) in bytes.iter_mut().zip(bits.as_bytes().as_chunks::<8>().0) {
        *byte = chunk.iter().fold(0, |byte, bit| (byte << 1) | (bit - b'0'));
    }
    Ok(bytes)
}

pub fn parse_exact(input: &str, binary: bool) -> Result<Entropy> {
    let mut entropy = Zeroizing::new([0; ENTROPY_LEN]);
    if binary {
        let bytes = binary_bytes(input)?;
        ensure!(
            bytes.len() == ENTROPY_LEN,
            "exact secret must contain {} binary digits",
            ENTROPY_LEN * 8
        );
        entropy.copy_from_slice(&bytes);
    } else {
        let input = compact(input);
        ensure!(
            input.len() == ENTROPY_LEN * 2,
            "exact secret must contain {} hexadecimal digits",
            ENTROPY_LEN * 2
        );
        // The library's error names the offending character; keep input out of messages.
        hex::decode_to_slice(input.as_bytes(), entropy.as_mut()).map_err(|_| {
            anyhow::anyhow!(
                "exact secret must contain only hexadecimal digits and ASCII whitespace"
            )
        })?;
    }
    Ok(entropy)
}

pub fn derive(input: &str) -> Result<Entropy> {
    let entropy = binary_bytes(input)?;
    ensure!(
        entropy.len() >= ENTROPY_LEN,
        "provide at least {} high-entropy binary digits",
        ENTROPY_LEN * 8
    );
    let salt = Sha256::digest(ENTROPY_DOMAIN);
    let params = Params::new(65536, 3, 1, Some(ENTROPY_LEN))?;
    // Argon2's allocating API does not wipe its workspace on drop.
    let mut memory = Zeroizing::new(vec![Block::default(); params.block_count()]);
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut secret = Zeroizing::new([0; ENTROPY_LEN]);
    argon.hash_password_into_with_memory(&entropy, &salt[..16], secret.as_mut(), &mut *memory)?;
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vector(line: usize) -> Vec<&'static str> {
        include_str!("../tests/vectors.txt")
            .lines()
            .nth(line)
            .unwrap()
            .split('\t')
            .collect()
    }

    fn example(value: u8) -> Backup {
        Backup::new(Zeroizing::new([value; ENTROPY_LEN]), 1767225600)
    }

    fn indices(mnemonic: &str) -> Vec<u16> {
        let words: Vec<_> = WORDLIST.lines().collect();
        mnemonic
            .split_whitespace()
            .map(|token| words.iter().position(|w| *w == token).unwrap() as u16)
            .collect()
    }

    #[test]
    fn independent_vector() {
        let v = vector(0);
        assert_eq!(v[0], "compact");
        let backup = Backup::new(parse_exact(v[3], false).unwrap(), v[1].parse().unwrap());
        assert_eq!(backup.created_at().to_string(), v[2]);
        assert_eq!(backup.encode().trim(), v[4]);
        assert_eq!(Backup::decode(v[4]).unwrap(), backup);
        let symbols = backup.symbols();
        assert_eq!(symbols.len(), WORD_COUNT);
        assert!(verify_checksum(&symbols[..]));
        assert_eq!(Backup::from_symbols(&symbols[..]).unwrap(), backup);
    }

    #[test]
    fn checksum_matches_slip39_reference() {
        let v = vector(2);
        assert_eq!(v[0], "slip39");
        let shamir = b"shamir".iter().map(|&c| u16::from(c));
        assert_eq!(polymod(shamir.clone().chain(indices(v[1]))), 1);
        assert_ne!(polymod(shamir.chain(indices(v[2]))), 1);
        // The customization string separates GPKB from SLIP-39 shares.
        assert!(!verify_checksum(&indices(v[1])));
    }

    #[test]
    fn kdf_is_reproducible_and_matches_reference() {
        let v = vector(1);
        assert_eq!(v[0], "argon2id");
        let input = hex::decode(v[1])
            .unwrap()
            .iter()
            .map(|b| format!("{b:08b}"))
            .collect::<String>();
        let secret = derive(&input).unwrap();
        assert_eq!(hex::encode(secret.as_ref()), v[2]);
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
    }

    #[test]
    fn roundtrip_and_transcription_errors() {
        for value in 0..=255 {
            let backup = example(value);
            assert_eq!(
                Backup::decode(&backup.encode().to_uppercase()).unwrap(),
                backup
            );
            assert_eq!(backup.encode().split_whitespace().count(), WORD_COUNT);
        }
        let backup = example(42);
        let mnemonic = backup.encode();
        let original: Vec<_> = mnemonic.split_whitespace().collect();
        let other = |word: &str| {
            if word == "academic" {
                "zero"
            } else {
                "academic"
            }
        };
        for position in 0..WORD_COUNT {
            let mut words = original.clone();
            words[position] = other(words[position]);
            let err = Backup::decode(&words.join(" ")).unwrap_err().to_string();
            assert_eq!(
                err,
                format!("checksum mismatch; word {} is probably wrong", position + 1)
            );
        }
        for (first, second) in [(0, 1), (3, 21), (10, 18)] {
            let mut words = original.clone();
            words[first] = other(words[first]);
            words[second] = other(words[second]);
            let err = Backup::decode(&words.join(" ")).unwrap_err().to_string();
            assert_eq!(err, "checksum mismatch; at least two words are wrong");
        }
        assert!(Backup::decode(&original[..WORD_COUNT - 1].join(" ")).is_err());
        assert!(Backup::decode(&(mnemonic.to_string() + "zero")).is_err());
        let mut words = original.clone();
        words[9] = "SECRET_INPUT";
        let err = Backup::decode(&words.join(" ")).unwrap_err();
        assert_eq!(err.to_string(), "unknown word at position 10");
    }

    #[test]
    fn rejects_other_versions_and_malformed_symbols() {
        let mut symbols = example(0).symbols();
        assert_eq!(symbols[0] >> 2, u16::from(SCHEME_VERSION));
        symbols[0] = (2 << 2) | (symbols[0] & 3);
        let check = checksum(&symbols[..DATA_WORDS]);
        symbols[DATA_WORDS..].copy_from_slice(&check);
        assert!(
            Backup::from_symbols(&symbols[..])
                .unwrap_err()
                .to_string()
                .contains("version 2")
        );
        let symbols = example(0).symbols();
        assert!(Backup::from_symbols(&symbols[..WORD_COUNT - 1]).is_err());
        let mut extended = symbols.to_vec();
        extended.push(0);
        assert!(Backup::from_symbols(&extended).is_err());
        let mut out_of_range = symbols.to_vec();
        out_of_range[5] = 1024;
        assert!(Backup::from_symbols(&out_of_range).is_err());
    }

    #[test]
    fn creation_time_is_rounded_down() {
        let secret = || Zeroizing::new([1; ENTROPY_LEN]);
        assert_eq!(Backup::new(secret(), 1767225600).created_at(), 1767225344);
        assert_eq!(Backup::new(secret(), 1023).created_at(), 0);
        assert_eq!(Backup::new(secret(), 1024).created_at(), 1024);
        assert_eq!(
            Backup::new(secret(), u32::MAX).created_at(),
            u32::MAX - 1023
        );
        let backup = Backup::new(secret(), u32::MAX);
        assert_eq!(Backup::decode(&backup.encode()).unwrap(), backup);
        assert!(timestamp(UNIX_EPOCH - std::time::Duration::from_secs(1)).is_err());
        assert!(
            timestamp(UNIX_EPOCH + std::time::Duration::from_secs(u32::MAX as u64 + 1)).is_err()
        );
    }

    #[test]
    fn exact_input_validation_and_redacted_debug() {
        let input = "ff".repeat(ENTROPY_LEN);
        let secret = parse_exact(&input, false).unwrap();
        assert_eq!(secret.as_ref(), &[255; ENTROPY_LEN]);
        assert_eq!(
            parse_exact(&"11111111\n".repeat(ENTROPY_LEN), true).unwrap(),
            secret
        );
        for bad in [
            "",
            "00",
            &"f".repeat(input.len() - 1),
            &"g".repeat(input.len()),
        ] {
            assert!(parse_exact(bad, false).is_err());
        }
        let err = parse_exact(&("zz".to_string() + &"f".repeat(input.len() - 2)), false)
            .unwrap_err()
            .to_string();
        assert!(!err.contains('z') && !err.contains("position"), "{err}");
        assert!(parse_exact(&"1".repeat(ENTROPY_LEN * 8 - 1), true).is_err());
        let debug = format!("{:?}", Backup::new(secret, 1700000000));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(&input));
        assert!(derive(&"1".repeat(152)).is_err());
        assert!(derive(&"2".repeat(160)).is_err());
    }
}
