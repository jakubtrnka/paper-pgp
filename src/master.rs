use crate::backup::{self, Backup, BackupSecret};
use anyhow::{Context, Result, bail, ensure};
use pgp::{
    Cert, Packet,
    cert::CertParser,
    crypto::mpi,
    packet::{
        Key, UserID,
        key::{Encrypted, PrimaryRole, SecretKeyMaterial, SecretParts, Unencrypted},
        signature::SignatureBuilder,
    },
    parse::Parse,
    types::{
        Curve, HashAlgorithm, KeyFlags, PublicKeyAlgorithm, SignatureType, SymmetricAlgorithm,
    },
};
use sequoia_openpgp as pgp;
use std::{
    cmp::Ordering,
    io::Read,
    time::{Duration, SystemTime},
};
use zeroize::Zeroizing;

pub const MASTER_SALT: &[u8] = b"gpg-keys/master/v1";
pub const MASTER_INFO: &[u8] = b"ed25519-certification";

pub fn ed25519_seed(secret: &BackupSecret) -> Zeroizing<[u8; 32]> {
    let mut seed = Zeroizing::new([0; 32]);
    match secret {
        BackupSecret::Raw(raw) => seed.copy_from_slice(raw.as_ref()),
        BackupSecret::CompactEntropy(entropy) => {
            let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(Some(MASTER_SALT), entropy.as_ref());
            hkdf.expand(MASTER_INFO, seed.as_mut())
                .expect("32-byte HKDF output is valid");
        }
    }
    seed
}

/// Reconstruct the primary key without creating new certificate metadata.
pub fn primary_key(backup: &Backup) -> Result<Key<SecretParts, PrimaryRole>> {
    let seed = ed25519_seed(backup.secret());
    Ok(
        pgp::packet::key::Key4::import_secret_ed25519(seed.as_ref(), backup.creation_time())?
            .into(),
    )
}

/// Create a fresh certification-only certificate, certifying `identity` anew.
/// The primary key retains its original timestamp; the self-signature uses
/// `signed_at`. Merging preserves packets but can change effective metadata;
/// equal or future timestamps prevent a guarantee that this signature wins.
/// `expires_at` is stored relative to the primary key's creation time.
pub fn certificate(
    backup: &Backup,
    identity: &str,
    signed_at: SystemTime,
    expires_at: Option<SystemTime>,
) -> Result<Cert> {
    ensure!(
        !identity.trim().is_empty() && !identity.chars().any(char::is_control),
        "identity must be nonempty and contain no control characters"
    );
    let time = backup.creation_time();
    ensure!(
        signed_at >= time,
        "signing time precedes the key creation time; check the system clock or --created-at"
    );
    let validity_period = expires_at
        .map(|expires| {
            ensure!(
                expires > signed_at,
                "expiry must be later than the signing time"
            );
            let period = expires.duration_since(time)?;
            ensure!(
                u32::try_from(period.as_secs()).is_ok(),
                "expiry exceeds the OpenPGP 32-bit validity period"
            );
            Ok(period)
        })
        .transpose()?;
    let key = primary_key(backup)?;
    let mut signer = key.clone().into_keypair()?;
    let uid = UserID::from(identity);
    let signature = SignatureBuilder::new(SignatureType::PositiveCertification)
        .set_hash_algo(HashAlgorithm::SHA256)
        .set_signature_creation_time(signed_at)?
        .set_key_flags(KeyFlags::empty().set_certification())?
        .set_primary_userid(true)?
        .set_key_validity_period(validity_period)?
        .set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512, HashAlgorithm::SHA256])?
        .set_preferred_symmetric_algorithms(vec![
            SymmetricAlgorithm::AES256,
            SymmetricAlgorithm::AES128,
        ])?
        .sign_userid_binding(&mut signer, key.parts_as_public(), &uid)?;
    Cert::from_packets(
        vec![
            Packet::SecretKey(key),
            Packet::UserID(uid),
            Packet::Signature(signature),
        ]
        .into_iter(),
    )
}

/// Parse a GnuPG-style validity duration: `<n>d`, `<n>w`, `<n>m` (30 days), `<n>y` (365 days).
pub fn validity(text: &str) -> Result<Duration> {
    let (unit, digits) = text
        .as_bytes()
        .split_last()
        .context("validity must end with d, w, m, or y, e.g. 2y")?;
    let days: u64 = match unit {
        b'd' => 1,
        b'w' => 7,
        b'm' => 30,
        b'y' => 365,
        _ => bail!("validity must end with d, w, m, or y, e.g. 2y"),
    };
    ensure!(
        !digits.is_empty() && digits.iter().all(u8::is_ascii_digit),
        "validity must be a positive whole number followed by d, w, m, or y"
    );
    let count: u64 = std::str::from_utf8(digits)
        .expect("validated ASCII digits")
        .parse()
        .context("validity count is too large")?;
    ensure!(count > 0, "validity must be positive");
    let secs = count
        .checked_mul(days * 86400)
        .context("validity is too large")?;
    ensure!(
        u32::try_from(secs).is_ok(),
        "validity exceeds the OpenPGP 32-bit validity period"
    );
    Ok(Duration::from_secs(secs))
}

/// Import exactly one certificate's exportable v4/algorithm-22 Ed25519 primary
/// secret. Subkeys and certificate updates remain separate backup artifacts.
pub fn import(input: &[u8], passphrase: Option<&[u8]>) -> Result<Backup> {
    let mut parser = CertParser::from_bytes(input).context("cannot parse OpenPGP certificate")?;
    let cert = parser.next().context("no OpenPGP certificate found")??;
    ensure!(
        parser.next().is_none(),
        "provide exactly one OpenPGP certificate, not a keyring"
    );
    let primary = cert.primary_key().key();
    ensure!(
        matches!(primary, Key::V4(_)),
        "only OpenPGP version 4 primary keys are supported"
    );
    ensure!(
        primary.pk_algo() == PublicKeyAlgorithm::EdDSA
            && matches!(
                primary.mpis(),
                mpi::PublicKey::EdDSA {
                    curve: Curve::Ed25519,
                    ..
                }
            ),
        "only algorithm-22 Ed25519 primary keys are supported"
    );
    let created_at = backup::timestamp(primary.creation_time())?;
    let key = primary
        .clone()
        .parts_into_secret()
        .context("primary key has no exportable secret material")?;
    let secret = match key.secret() {
        SecretKeyMaterial::Unencrypted(material) => native_secret(material)?,
        SecretKeyMaterial::Encrypted(encrypted) => {
            let password =
                passphrase.context("encrypted primary key requires --passphrase-file")?;
            ensure!(!password.is_empty(), "passphrase must not be empty");
            let password = pgp::crypto::Password::from(password);
            match encrypted.decrypt(&key, &password) {
                Ok(material) => native_secret(&material)?,
                Err(error) => {
                    // GnuPG 2.4 can export a fixed-width opaque seed (SOS) where
                    // Sequoia expects a canonical MPI. Keep this exception narrow.
                    if matches!(
                        error.downcast_ref::<pgp::Error>(),
                        Some(pgp::Error::MalformedMPI(_))
                    ) {
                        gpg_opaque_secret(encrypted, &password)
                            .context("cannot decrypt primary key; check its passphrase and whether the secret is exportable")?
                    } else {
                        return Err(error).context("cannot decrypt primary key; check its passphrase and whether the secret is exportable");
                    }
                }
            }
        }
    };
    let backup = Backup::new(secret, created_at);
    // Reject mismatched private/public material before producing a backup.
    // Only the fingerprint matters here, so stay independent of the clock.
    let recovered = primary_key(&backup)?;
    ensure!(
        recovered.fingerprint() == cert.fingerprint(),
        "private material does not reproduce the imported primary fingerprint"
    );
    Ok(backup)
}

fn native_secret(material: &Unencrypted) -> Result<BackupSecret> {
    material.map(|material| match material {
        mpi::SecretKeyMaterial::EdDSA { scalar } => {
            ensure!(
                scalar.value().len() <= 32,
                "invalid Ed25519 private seed length"
            );
            let mut seed = Zeroizing::new([0; 32]);
            seed.copy_from_slice(&scalar.value_padded(32));
            Ok(BackupSecret::Raw(seed))
        }
        _ => bail!("unexpected primary secret key representation"),
    })
}

/// Handle only GnuPG's v4 CFB/SHA1-protected, byte-aligned Ed25519 SOS.
/// Validate the original plaintext checksum before extracting any seed; import
/// also verifies that this seed reproduces the original public fingerprint.
fn gpg_opaque_secret(
    encrypted: &Encrypted,
    password: &pgp::crypto::Password,
) -> Result<BackupSecret> {
    use pgp::crypto::symmetric::{BlockCipherMode, Decryptor, UnpaddingMode};
    ensure!(
        encrypted.aead_algo().is_none()
            && encrypted.checksum() == Some(mpi::SecretKeyChecksum::SHA1),
        "unsupported GnuPG opaque secret protection"
    );
    let algo = encrypted.algo();
    let block_size = algo.block_size()?;
    let ciphertext = encrypted.ciphertext()?;
    ensure!(
        (block_size + 2 + 20..=block_size + 2 + 32 + 20).contains(&ciphertext.len()),
        "invalid GnuPG opaque secret length"
    );
    let key = encrypted.s2k().derive_key(password, algo.key_size()?)?;
    let reader = pgp::parse::buffered_reader::Memory::with_cookie(ciphertext, Default::default());
    let mut decryptor = Decryptor::new(
        algo,
        BlockCipherMode::CFB,
        UnpaddingMode::None,
        &key,
        None,
        reader,
    )?;
    // Sequoia stores the clear CFB IV with the ciphertext. Decrypting that first
    // block with a zero IV sets up CFB for the actual secret, as its importer does.
    let mut plaintext = Zeroizing::new(vec![0; ciphertext.len()]);
    decryptor.read_exact(&mut plaintext)?;
    let secret = &plaintext[block_size..];
    let body_len = secret.len() - 20;
    let seed_len = body_len - 2;
    let mut digest = Zeroizing::new([0; 20]);
    let mut hash = HashAlgorithm::SHA1.context()?.for_digest();
    hash.update(&secret[..body_len]);
    hash.digest(digest.as_mut())?;
    ensure!(
        pgp::crypto::mem::secure_cmp(digest.as_ref(), &secret[body_len..]) == Ordering::Equal,
        "invalid protected secret checksum"
    );
    ensure!(
        u16::from_be_bytes([secret[0], secret[1]]) as usize == seed_len * 8,
        "invalid GnuPG opaque secret header"
    );
    let mut seed = Zeroizing::new([0; 32]);
    seed[32 - seed_len..].copy_from_slice(&secret[2..body_len]);
    Ok(BackupSecret::Raw(seed))
}

pub fn protect(cert: Cert, passphrase: &[u8]) -> Result<Cert> {
    ensure!(!passphrase.is_empty(), "passphrase must not be empty");
    let password = pgp::crypto::Password::from(passphrase);
    let key = cert
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()?
        .encrypt_secret(&password)?;
    Ok(cert.insert_packets(Packet::SecretKey(key))?.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgp::{
        cert::{CertBuilder, CipherSuite},
        policy::StandardPolicy,
        serialize::Serialize,
    };
    use std::time::UNIX_EPOCH;

    fn creation(backup: &Backup) -> SystemTime {
        backup.creation_time()
    }

    fn example() -> Backup {
        Backup::new(
            BackupSecret::CompactEntropy(Zeroizing::new([42; 20])),
            1700000000,
        )
    }

    #[test]
    fn independent_master_vectors() {
        for line in include_str!("../tests/vectors.txt").lines().take(2) {
            let v: Vec<_> = line.split('\t').collect();
            let backup = Backup::decode(v[4]).unwrap();
            assert_eq!(hex::encode(ed25519_seed(backup.secret()).as_ref()), v[5]);
            let cert =
                certificate(&backup, "Independent test vector", creation(&backup), None).unwrap();
            assert_eq!(cert.fingerprint().to_string(), v[6]);
            assert_eq!(
                primary_key(&backup).unwrap().fingerprint().to_string(),
                v[6]
            );
        }
    }

    #[test]
    fn recovery_timestamp_and_passphrase_protection() {
        let backup = example();
        let cert = certificate(
            &backup,
            "Alice <alice@example.org>",
            creation(&backup),
            None,
        )
        .unwrap();
        let recovered = certificate(
            &Backup::decode(&backup.encode()).unwrap(),
            "Alice <alice@example.org>",
            creation(&backup),
            None,
        )
        .unwrap();
        assert_eq!(cert.fingerprint(), recovered.fingerprint());
        assert_eq!(
            cert.fingerprint(),
            certificate(&backup, "Different identity", creation(&backup), None)
                .unwrap()
                .fingerprint()
        );
        let changed_time = Backup::new(
            BackupSecret::CompactEntropy(Zeroizing::new([42; 20])),
            backup.created_at() + 1,
        );
        assert_eq!(
            *ed25519_seed(backup.secret()),
            *ed25519_seed(changed_time.secret())
        );
        assert_ne!(
            cert.fingerprint(),
            certificate(&changed_time, "Alice", creation(&changed_time), None)
                .unwrap()
                .fingerprint()
        );
        let native = Backup::new(
            BackupSecret::Raw(ed25519_seed(backup.secret())),
            backup.created_at(),
        );
        assert_eq!(
            cert.fingerprint(),
            certificate(&native, "Alice", creation(&native), None)
                .unwrap()
                .fingerprint()
        );
        let policy = StandardPolicy::new();
        let valid = cert.with_policy(&policy, None).unwrap();
        assert_eq!(valid.keys().for_certification().count(), 1);
        assert_eq!(valid.keys().for_signing().count(), 0);
        let protected = protect(cert, b"test password").unwrap();
        let mut bytes = Vec::new();
        protected.as_tsk().armored().serialize(&mut bytes).unwrap();
        let parsed = Cert::from_bytes(&bytes).unwrap();
        let key = parsed
            .primary_key()
            .key()
            .clone()
            .parts_into_secret()
            .unwrap();
        assert!(!key.has_unencrypted_secret());
        assert!(
            key.clone()
                .decrypt_secret(&pgp::crypto::Password::from(&b"wrong"[..]))
                .is_err()
        );
        assert!(
            key.decrypt_secret(&pgp::crypto::Password::from(&b"test password"[..]))
                .unwrap()
                .into_keypair()
                .is_ok()
        );
        assert!(certificate(&backup, "\n", creation(&backup), None).is_err());
    }

    #[test]
    fn self_signature_is_dated_at_signing_time() {
        let backup = example();
        let created = backup.creation_time();
        assert_eq!(created, UNIX_EPOCH + Duration::from_secs(1700000000));
        let signed_at = created + Duration::from_secs(365 * 24 * 3600);
        let cert = certificate(&backup, "Alice", signed_at, None).unwrap();
        let policy = StandardPolicy::new();
        let valid = cert.with_policy(&policy, signed_at).unwrap();
        let binding = valid.primary_userid().unwrap().binding_signature();
        assert_eq!(binding.signature_creation_time(), Some(signed_at));
        assert_eq!(
            cert.fingerprint(),
            certificate(&backup, "Alice", created, None)
                .unwrap()
                .fingerprint()
        );
        assert!(certificate(&backup, "Alice", created - Duration::from_secs(1), None).is_err());
    }

    #[test]
    fn self_signature_carries_optional_expiry() {
        let backup = example();
        let signed_at = backup.creation_time() + Duration::from_secs(86400);
        let expires_at = signed_at + Duration::from_secs(2 * 365 * 86400);
        let cert = certificate(&backup, "Alice", signed_at, Some(expires_at)).unwrap();
        let policy = StandardPolicy::new();
        let valid = cert.with_policy(&policy, signed_at).unwrap();
        assert!(valid.primary_key().alive().is_ok());
        assert_eq!(valid.primary_key().key_expiration_time(), Some(expires_at));
        let later = cert
            .with_policy(&policy, expires_at + Duration::from_secs(1))
            .unwrap();
        assert!(later.primary_key().alive().is_err());
        let unlimited = certificate(&backup, "Alice", signed_at, None).unwrap();
        assert_eq!(cert.fingerprint(), unlimited.fingerprint());
        let unlimited = unlimited.with_policy(&policy, signed_at).unwrap();
        assert_eq!(unlimited.primary_key().key_expiration_time(), None);
        assert!(certificate(&backup, "Alice", signed_at, Some(signed_at)).is_err());
    }

    #[test]
    fn validity_durations_follow_gnupg_units() {
        assert_eq!(
            validity("2y").unwrap(),
            Duration::from_secs(2 * 365 * 86400)
        );
        assert_eq!(
            validity("18m").unwrap(),
            Duration::from_secs(18 * 30 * 86400)
        );
        assert_eq!(validity("4w").unwrap(), Duration::from_secs(4 * 7 * 86400));
        assert_eq!(validity("90d").unwrap(), Duration::from_secs(90 * 86400));
        assert_eq!(
            validity("49710d").unwrap(),
            Duration::from_secs(49710 * 86400)
        );
        for bad in [
            "",
            "2",
            "0d",
            "2x",
            "y",
            "-1d",
            " 2y",
            "1y1d",
            "é",
            "1年",
            "éy",
            "١d",
            "49711d",
            "213503982334600d",
            "18446744073709551615y",
        ] {
            assert!(validity(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn fresh_export_recertifies_identity_and_replaces_active_metadata() {
        use pgp::{
            cert::UserIDRevocationBuilder,
            types::{ReasonForRevocation, RevocationStatus},
        };

        let backup = example();
        let created = backup.creation_time();
        let signed_at = created + Duration::from_secs(300);
        let expiry = created + Duration::from_secs(365 * 86400);
        let identity = "Former identity <old@example.org>";
        let original = certificate(&backup, identity, created, Some(expiry)).unwrap();
        let uid = original.userids().next().unwrap().userid().clone();
        let mut signer = primary_key(&backup).unwrap().into_keypair().unwrap();
        let binding = original
            .userids()
            .next()
            .unwrap()
            .self_signatures()
            .next()
            .unwrap()
            .clone();
        let updated = SignatureBuilder::from(binding)
            .set_signature_creation_time(created + Duration::from_secs(1))
            .unwrap()
            .set_key_flags(KeyFlags::empty().set_certification().set_signing())
            .unwrap()
            .sign_userid_binding(&mut signer, original.primary_key().key(), &uid)
            .unwrap();
        let original = original.insert_packets(updated).unwrap().0;
        let policy = StandardPolicy::new();
        let valid = original.with_policy(&policy, signed_at).unwrap();
        assert!(valid.primary_key().for_signing());
        assert_eq!(valid.primary_key().key_expiration_time(), Some(expiry));

        let revocation = UserIDRevocationBuilder::new()
            .set_reason_for_revocation(ReasonForRevocation::UIDRetired, b"Old address")
            .unwrap()
            .set_signature_creation_time(created + Duration::from_secs(100))
            .unwrap()
            .build(&mut signer, &original, &uid, None)
            .unwrap();
        let revoked = original.insert_packets(revocation).unwrap().0;
        assert!(matches!(
            revoked
                .userids()
                .next()
                .unwrap()
                .revocation_status(&policy, signed_at),
            RevocationStatus::Revoked(_)
        ));

        let recovered = certificate(&backup, identity, signed_at, None).unwrap();
        let merged = recovered.merge_public(revoked.clone()).unwrap();
        assert_eq!(merged.fingerprint(), revoked.fingerprint());
        let uid = merged.userids().next().unwrap();
        assert_eq!(uid.self_revocations().count(), 1);
        assert!(matches!(
            uid.revocation_status(&policy, signed_at),
            RevocationStatus::NotAsFarAsWeKnow
        ));
        let valid = merged.with_policy(&policy, signed_at).unwrap();
        assert!(valid.primary_key().for_certification());
        assert!(!valid.primary_key().for_signing());
        assert_eq!(valid.primary_key().key_expiration_time(), None);
        assert_eq!(
            valid
                .primary_userid()
                .unwrap()
                .binding_signature()
                .signature_creation_time(),
            Some(signed_at)
        );
    }

    #[test]
    fn import_preserves_native_seed_and_timestamp() {
        let mut seed = Zeroizing::new([42; 32]);
        seed[0] = 0;
        seed[1] = 0;
        let original = Backup::new(BackupSecret::Raw(seed), 1234567890);
        let cert = certificate(&original, "Original", creation(&original), None).unwrap();
        for password in [None, Some(&b"test password"[..])] {
            let exported = if let Some(p) = password {
                protect(cert.clone(), p).unwrap()
            } else {
                cert.clone()
            };
            let mut bytes = Vec::new();
            exported.as_tsk().armored().serialize(&mut bytes).unwrap();
            if password.is_some() {
                assert!(import(&bytes, None).is_err());
                assert!(import(&bytes, Some(b"wrong")).is_err());
            }
            let backup = import(&bytes, password).unwrap();
            assert_eq!(backup, original);
            assert_eq!(backup.word_count(), 44);
            assert_eq!(
                cert.fingerprint(),
                certificate(
                    &Backup::decode(&backup.encode()).unwrap(),
                    "Restored",
                    creation(&backup),
                    None,
                )
                .unwrap()
                .fingerprint()
            );
        }
        let mut public = Vec::new();
        cert.armored().serialize(&mut public).unwrap();
        assert!(import(&public, None).is_err());
        let mut multiple = Vec::new();
        cert.as_tsk().serialize(&mut multiple).unwrap();
        cert.as_tsk().serialize(&mut multiple).unwrap();
        assert!(import(&multiple, None).is_err());
        let (rsa, _) = CertBuilder::new()
            .set_cipher_suite(CipherSuite::RSA2k)
            .add_userid("Unsupported")
            .generate()
            .unwrap();
        let mut bytes = Vec::new();
        rsa.as_tsk().serialize(&mut bytes).unwrap();
        assert!(import(&bytes, None).is_err());
    }

    #[test]
    fn gpg_opaque_import_validates_checksum_header_and_public_key() {
        use pgp::crypto::{
            S2K,
            symmetric::{BlockCipherMode, Encryptor, PaddingMode},
        };
        use std::io::Write;

        // Construct GnuPG-style encrypted exports independently of the importer.
        // Include full-width, stripped-leading-zero, and all-zero representations.
        fn exported(cert: &Cert, payload: &[u8], bits: u16, corrupt_checksum: bool) -> Vec<u8> {
            let mut plaintext = Zeroizing::new(bits.to_be_bytes().to_vec());
            plaintext.extend_from_slice(payload);
            let mut hash = HashAlgorithm::SHA1.context().unwrap().for_digest();
            hash.update(&plaintext);
            let mut digest = Zeroizing::new([0; 20]);
            hash.digest(digest.as_mut()).unwrap();
            if corrupt_checksum {
                digest[0] ^= 1;
            }
            plaintext.extend_from_slice(digest.as_ref());
            let algo = SymmetricAlgorithm::AES256;
            let s2k = S2K::Iterated {
                hash: HashAlgorithm::SHA256,
                salt: [42; 8],
                hash_bytes: 1024,
            };
            let password = pgp::crypto::Password::from(&b"test password"[..]);
            let key = s2k.derive_key(&password, algo.key_size().unwrap()).unwrap();
            let iv = vec![42; algo.block_size().unwrap()];
            let mut ciphertext = iv.clone();
            let mut encryptor = Encryptor::new(
                algo,
                BlockCipherMode::CFB,
                PaddingMode::None,
                &key,
                Some(&iv),
                &mut ciphertext,
            )
            .unwrap();
            encryptor.write_all(&plaintext).unwrap();
            encryptor.finalize().unwrap();
            let encrypted = Encrypted::new(
                s2k,
                algo,
                Some(mpi::SecretKeyChecksum::SHA1),
                ciphertext.into_boxed_slice(),
            );
            let primary = cert
                .primary_key()
                .key()
                .clone()
                .parts_into_secret()
                .unwrap();
            let key = primary
                .add_secret(SecretKeyMaterial::Encrypted(encrypted))
                .0;
            let cert = cert
                .clone()
                .insert_packets(Packet::SecretKey(key))
                .unwrap()
                .0;
            let mut bytes = Vec::new();
            cert.as_tsk().serialize(&mut bytes).unwrap();
            bytes
        }

        for zeros in [1, 2, 32] {
            let mut seed = Zeroizing::new([42; 32]);
            seed[..zeros].fill(0);
            let original = Backup::new(BackupSecret::Raw(seed), 1234567890);
            let cert = certificate(&original, "Original", creation(&original), None).unwrap();
            for payload in [
                original.secret().payload(),
                &original.secret().payload()[zeros..],
            ] {
                let bits = (payload.len() * 8) as u16;
                let bytes = exported(&cert, payload, bits, false);
                assert_eq!(import(&bytes, Some(b"test password")).unwrap(), original);
                assert!(import(&bytes, Some(b"wrong password")).is_err());
                assert!(
                    import(
                        &exported(&cert, payload, bits, true),
                        Some(b"test password")
                    )
                    .is_err()
                );
                assert!(
                    import(
                        &exported(&cert, payload, bits + 1, false),
                        Some(b"test password")
                    )
                    .is_err()
                );
            }
            let mismatch = exported(&cert, &[43; 32], 256, false);
            assert!(
                import(&mismatch, Some(b"test password"))
                    .unwrap_err()
                    .to_string()
                    .contains("fingerprint")
            );
            assert!(
                import(
                    &exported(&cert, &[42; 33], 264, false),
                    Some(b"test password")
                )
                .is_err()
            );
        }
    }
}
