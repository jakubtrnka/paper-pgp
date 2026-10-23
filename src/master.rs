use crate::backup::{Backup, ENTROPY_LEN};
use anyhow::{Context, Result, bail, ensure};
use pgp::{
    Cert, Packet,
    cert::CertParser,
    packet::{
        Key, UserID,
        key::{PrimaryRole, SecretParts},
        signature::SignatureBuilder,
    },
    parse::Parse,
    types::{HashAlgorithm, KeyFlags, SignatureType, SymmetricAlgorithm},
};
use sequoia_openpgp as pgp;
use std::time::{Duration, SystemTime};
use zeroize::Zeroizing;

pub const MASTER_SALT: &[u8] = b"GPG Key Backup v1";
pub const MASTER_INFO: &[u8] = b"ed25519-certification";

/// Expand the stored entropy to the native Ed25519 private seed.
pub fn ed25519_seed(entropy: &[u8; ENTROPY_LEN]) -> Zeroizing<[u8; 32]> {
    let mut seed = Zeroizing::new([0; 32]);
    let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(Some(MASTER_SALT), entropy);
    hkdf.expand(MASTER_INFO, seed.as_mut())
        .expect("32-byte HKDF output is valid");
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
    let identity = identity.trim();
    ensure!(
        !identity.is_empty() && !identity.chars().any(char::is_control),
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

/// Restore the recovered primary secret into a saved certificate without
/// creating any signature. Public keys, User IDs, subkey bindings, expirations,
/// and revocations are kept as saved. Any existing secret material is discarded:
/// the result contains only the recovered primary secret.
pub fn restore(backup: &Backup, certificate: &[u8]) -> Result<Cert> {
    let mut parser =
        CertParser::from_bytes(certificate).context("cannot parse the saved certificate")?;
    let cert = parser
        .next()
        .context("no OpenPGP certificate found in the saved certificate")??;
    ensure!(
        parser.next().is_none(),
        "the saved certificate must contain exactly one certificate, not a keyring"
    );
    let key = primary_key(backup)?;
    ensure!(
        cert.fingerprint() == key.fingerprint(),
        "the saved certificate does not belong to the recovered primary key"
    );
    // A saved secret-key export may include unencrypted subkeys. Do not carry
    // them into an export whose passphrase protects only the recovered primary.
    Ok(cert
        .strip_secret_key_material()
        .insert_packets(Packet::SecretKey(key))?
        .0)
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
    use pgp::{parse::Parse, policy::StandardPolicy, serialize::Serialize};
    use std::time::UNIX_EPOCH;

    fn creation(backup: &Backup) -> SystemTime {
        backup.creation_time()
    }

    fn example() -> Backup {
        Backup::new(Zeroizing::new([42; ENTROPY_LEN]), 1767225344)
    }

    #[test]
    fn independent_master_vector() {
        let v: Vec<_> = include_str!("../tests/vectors.txt")
            .lines()
            .next()
            .unwrap()
            .split('\t')
            .collect();
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

    #[test]
    fn recovery_timestamp_identity_and_passphrase_protection() {
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
            Zeroizing::new([42; ENTROPY_LEN]),
            backup.created_at() + 1024,
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
        let policy = StandardPolicy::new();
        let valid = cert.with_policy(&policy, None).unwrap();
        assert_eq!(valid.keys().for_certification().count(), 1);
        assert_eq!(valid.keys().for_signing().count(), 0);
        let trimmed = certificate(
            &backup,
            "  Alice <alice@example.org>  ",
            creation(&backup),
            None,
        )
        .unwrap();
        assert_eq!(
            trimmed.userids().next().unwrap().userid().value(),
            b"Alice <alice@example.org>"
        );
        assert!(certificate(&backup, "   ", creation(&backup), None).is_err());
        assert!(certificate(&backup, "\n", creation(&backup), None).is_err());
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
    }

    #[test]
    fn self_signature_is_dated_at_signing_time() {
        let backup = example();
        let created = backup.creation_time();
        assert_eq!(created, UNIX_EPOCH + Duration::from_secs(1767225344));
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
    fn restore_inserts_secret_without_signing() {
        use pgp::serialize::SerializeInto;

        let backup = example();
        let created = backup.creation_time();
        let signed_at = created + Duration::from_secs(3600);
        let expiry = created + Duration::from_secs(365 * 86400);
        let original = certificate(
            &backup,
            "Alice <alice@example.org>",
            signed_at,
            Some(expiry),
        )
        .unwrap();
        let policy = StandardPolicy::new();
        let signatures = |cert: &Cert| {
            cert.clone()
                .into_packets()
                .filter(|p| matches!(p, Packet::Signature(_)))
                .count()
        };
        for saved in [
            original.armored().to_vec().unwrap(),
            original.as_tsk().to_vec().unwrap(),
        ] {
            let restored = restore(&backup, &saved).unwrap();
            assert!(restored.is_tsk());
            assert_eq!(restored.fingerprint(), original.fingerprint());
            assert_eq!(signatures(&restored), signatures(&original));
            assert!(restored.primary_key().key().has_unencrypted_secret());
            let valid = restored.with_policy(&policy, signed_at).unwrap();
            assert_eq!(valid.primary_key().key_expiration_time(), Some(expiry));
            assert_eq!(
                valid
                    .primary_userid()
                    .unwrap()
                    .binding_signature()
                    .signature_creation_time(),
                Some(signed_at)
            );
            let protected = protect(restored, b"test password").unwrap();
            assert!(!protected.primary_key().key().has_unencrypted_secret());
        }
        let other = Backup::new(Zeroizing::new([43; ENTROPY_LEN]), backup.created_at());
        let err = restore(&other, &original.armored().to_vec().unwrap()).unwrap_err();
        assert!(err.to_string().contains("does not belong"), "{err}");
        let mut keyring = original.to_vec().unwrap();
        keyring.extend(original.to_vec().unwrap());
        assert!(restore(&backup, &keyring).is_err());
        assert!(restore(&backup, b"not a certificate").is_err());
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
}
