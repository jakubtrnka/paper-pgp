use crate::backup::Secret;
use anyhow::{Result, ensure};
use pgp::{
    Cert, Packet,
    packet::{
        Key, UserID,
        key::{PrimaryRole, SecretParts},
        signature::SignatureBuilder,
    },
    types::{HashAlgorithm, KeyFlags, SignatureType, SymmetricAlgorithm},
};
use sequoia_openpgp as pgp;
use std::time::{Duration, UNIX_EPOCH};

pub const CREATION_TIME: u64 = 1_767_225_600;

pub fn ed25519_seed(secret: &Secret) -> Secret {
    let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(Some(b"gpg-keys/master/v1"), secret.as_ref());
    let mut seed = zeroize::Zeroizing::new([0; 32]);
    hkdf.expand(b"ed25519-certification", seed.as_mut())
        .expect("32-byte HKDF output is valid");
    seed
}

/// The seed and fixed packet timestamp determine the primary fingerprint.
pub fn certificate(secret: &Secret, identity: &str) -> Result<Cert> {
    ensure!(
        !identity.trim().is_empty() && !identity.chars().any(char::is_control),
        "identity must be nonempty and contain no control characters"
    );
    let time = UNIX_EPOCH + Duration::from_secs(CREATION_TIME);
    let key_seed = ed25519_seed(secret);
    let key: Key<SecretParts, PrimaryRole> =
        pgp::packet::key::Key4::import_secret_ed25519(key_seed.as_ref(), time)?.into();
    let mut signer = key.clone().into_keypair()?;
    let uid = UserID::from(identity);
    let signature = SignatureBuilder::new(SignatureType::PositiveCertification)
        .set_hash_algo(HashAlgorithm::SHA256)
        .set_signature_creation_time(time)?
        .set_key_flags(KeyFlags::empty().set_certification())?
        .set_primary_userid(true)?
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
    use zeroize::Zeroizing;

    #[test]
    fn independent_master_vector() {
        let vector: Vec<_> = include_str!("../tests/vectors.txt").lines().collect();
        let seed = crate::backup::parse_exact(vector[0], false).unwrap();
        assert_eq!(hex::encode(ed25519_seed(&seed).as_ref()), vector[4]);
        let cert = certificate(&seed, "Independent test vector").unwrap();
        assert_eq!(cert.fingerprint().to_string(), vector[5]);
    }

    #[test]
    fn recovery_and_passphrase_protection() {
        let seed = Zeroizing::new([42; 32]);
        let cert = certificate(&seed, "Alice <alice@example.org>").unwrap();
        let recovered = certificate(
            &crate::backup::decode(&crate::backup::encode(&seed)).unwrap(),
            "Alice <alice@example.org>",
        )
        .unwrap();
        assert_eq!(cert.fingerprint(), recovered.fingerprint());
        assert_eq!(
            cert.fingerprint(),
            certificate(&seed, "Different identity")
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
        assert!(certificate(&seed, "\n").is_err());
    }
}
