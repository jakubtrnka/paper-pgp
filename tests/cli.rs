use gpg_keys::{
    backup::{Backup, BackupSecret, SecretKind},
    master,
};
use sequoia_openpgp::{Cert, parse::Parse, serialize::Serialize};
use std::{
    fs,
    path::Path,
    process::{Command, Output},
    time::SystemTime,
};
use zeroize::Zeroizing;

fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_gpg-keys"))
        .args(args)
        .output()
        .unwrap()
}
fn succeeds(output: Output) -> Output {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

#[test]
fn file_workflow_and_protection_for_both_variants() {
    for kind in [SecretKind::CompactEntropy, SecretKind::Raw] {
        let dir = tempfile::tempdir().unwrap();
        let words_path = dir.path().join("words.txt");
        let words = words_path.to_str().unwrap();
        if kind == SecretKind::CompactEntropy {
            let before = gpg_keys::backup::timestamp(SystemTime::now()).unwrap();
            succeeds(cli(&["random", "-o", words]));
            let after = gpg_keys::backup::timestamp(SystemTime::now()).unwrap();
            let generated = Backup::decode(&fs::read_to_string(words).unwrap()).unwrap();
            assert!((before..=after).contains(&generated.created_at()));
        } else {
            let raw_input = dir.path().join("raw.hex");
            fs::write(&raw_input, "2a".repeat(32)).unwrap();
            succeeds(cli(&[
                "encode",
                "--kind",
                "raw",
                "--created-at",
                "1234567890",
                "-i",
                raw_input.to_str().unwrap(),
                "-o",
                words,
            ]));
        }
        let original = fs::read(words).unwrap();
        let backup = Backup::decode(std::str::from_utf8(&original).unwrap()).unwrap();
        assert_eq!(backup.kind(), kind);
        assert_eq!(backup.word_count(), kind.word_count());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(words).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(!cli(&["random", "-o", words]).status.success());
        assert_eq!(fs::read(words).unwrap(), original);
        let decoded = succeeds(cli(&["decode", "-i", words]));
        assert!(
            String::from_utf8_lossy(&decoded.stderr)
                .contains(&format!("created-at: {}", backup.created_at()))
        );
        assert_eq!(decoded.stdout.len(), kind.payload_len() * 2 + 1);
        let seed_file = dir.path().join("seed.hex");
        fs::write(&seed_file, &decoded.stdout).unwrap();
        assert_eq!(
            succeeds(cli(&[
                "encode",
                "--kind",
                kind.name(),
                "--created-at",
                &backup.created_at().to_string(),
                "-i",
                seed_file.to_str().unwrap()
            ]))
            .stdout,
            original
        );
        let base_args = [
            "export",
            "-i",
            words,
            "--identity",
            "Test <test@example.org>",
        ];
        assert!(!cli(&base_args).status.success());
        let mut args = base_args.to_vec();
        args.push("--public");
        let public_bytes = succeeds(cli(&args)).stdout;
        let public = Cert::from_bytes(&public_bytes).unwrap();
        assert!(!public.is_tsk());
        assert_eq!(
            gpg_keys::backup::timestamp(public.primary_key().key().creation_time()).unwrap(),
            backup.created_at()
        );
        let mut args = base_args.to_vec();
        args.extend(["--public", "--expires", "2y"]);
        let whole_seconds = |t: SystemTime| {
            std::time::UNIX_EPOCH
                + std::time::Duration::from_secs(u64::from(gpg_keys::backup::timestamp(t).unwrap()))
        };
        let before = whole_seconds(SystemTime::now());
        let expiring = succeeds(cli(&args));
        let after = SystemTime::now();
        let expiring_cert = Cert::from_bytes(&expiring.stdout).unwrap();
        assert_eq!(expiring_cert.fingerprint(), public.fingerprint());
        let policy = sequoia_openpgp::policy::StandardPolicy::new();
        let expiry = expiring_cert
            .with_policy(&policy, None)
            .unwrap()
            .primary_key()
            .key_expiration_time()
            .unwrap();
        let two_years = std::time::Duration::from_secs(2 * 365 * 86400);
        assert!(expiry >= before + two_years && expiry <= after + two_years);
        assert!(String::from_utf8_lossy(&expiring.stderr).contains("expires"));
        let mut args = base_args.to_vec();
        args.extend(["--public", "--expires", "2x"]);
        assert!(!cli(&args).status.success());
        let password = dir.path().join("password");
        fs::write(&password, "test password\r\n").unwrap();
        let mut args = base_args.to_vec();
        args.extend(["--passphrase-file", password.to_str().unwrap()]);
        let secret_bytes = succeeds(cli(&args)).stdout;
        let private = Cert::from_bytes(&secret_bytes).unwrap();
        assert!(private.is_tsk());
        assert_eq!(private.fingerprint(), public.fingerprint());
        let key = private
            .primary_key()
            .key()
            .clone()
            .parts_into_secret()
            .unwrap();
        assert!(!key.has_unencrypted_secret());
        assert!(
            key.decrypt_secret(&sequoia_openpgp::crypto::Password::from(
                &b"test password"[..]
            ))
            .is_ok()
        );
        let exported = dir.path().join("master.asc");
        fs::write(&exported, &secret_bytes).unwrap();
        assert!(
            !cli(&["import", "-i", exported.to_str().unwrap()])
                .status
                .success()
        );
        let imported = succeeds(cli(&[
            "import",
            "-i",
            exported.to_str().unwrap(),
            "--passphrase-file",
            password.to_str().unwrap(),
        ]));
        let raw_backup = Backup::decode(std::str::from_utf8(&imported.stdout).unwrap()).unwrap();
        assert_eq!(raw_backup.kind(), SecretKind::Raw);
        assert_eq!(raw_backup.created_at(), backup.created_at());
        assert_eq!(
            raw_backup.secret().payload(),
            master::ed25519_seed(backup.secret()).as_ref()
        );
        assert_eq!(
            master::certificate(&raw_backup, "Recovered", SystemTime::now(), None)
                .unwrap()
                .fingerprint(),
            public.fingerprint()
        );
        fs::write(&password, "wrong").unwrap();
        assert!(
            !cli(&[
                "import",
                "-i",
                exported.to_str().unwrap(),
                "--passphrase-file",
                password.to_str().unwrap()
            ])
            .status
            .success()
        );
        fs::write(&password, "\n").unwrap();
        assert!(!cli(&args).status.success());
        fs::write(&exported, public_bytes).unwrap();
        assert!(
            !cli(&["import", "-i", exported.to_str().unwrap()])
                .status
                .success()
        );
        let typst =
            String::from_utf8(succeeds(cli(&["template", "--kind", kind.name()])).stdout).unwrap();
        assert!(typst.contains("paper: \"a5\""));
        assert!(typst.contains("#backup-document(("));
        assert!(typst.contains(&format!("kind: \"{}\"", kind.name())));
        assert!(!typst.contains("read("));
        for word in gpg_keys::backup::WORDLIST.lines() {
            assert!(typst.contains(&format!("  \"{word}\",\n")));
        }
        assert!(!typst.contains(std::str::from_utf8(&original).unwrap().trim()));
        assert!(typst.contains(gpg_keys::backup::WORDLIST_SHA256));
    }
}

#[test]
fn explicit_compact_input_and_entropy_derivation() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("bits.txt");
    fs::write(&input, "10101010\n".repeat(20)).unwrap();
    let encoded = succeeds(cli(&[
        "encode",
        "--format",
        "binary",
        "--created-at",
        "1700000000",
        "-i",
        input.to_str().unwrap(),
    ]));
    let backup = Backup::decode(std::str::from_utf8(&encoded.stdout).unwrap()).unwrap();
    assert_eq!(backup.secret().payload(), [170; 20]);
    let derived = succeeds(cli(&[
        "derive",
        "--created-at",
        "1700000000",
        "-i",
        input.to_str().unwrap(),
    ]));
    let derived = Backup::decode(std::str::from_utf8(&derived.stdout).unwrap()).unwrap();
    assert_eq!(derived.kind(), SecretKind::CompactEntropy);
    assert_ne!(derived.secret().payload(), backup.secret().payload());
    assert!(
        !cli(&[
            "encode",
            "--kind",
            "raw",
            "--format",
            "binary",
            "-i",
            input.to_str().unwrap()
        ])
        .status
        .success()
    );
    assert!(
        !cli(&[
            "encode",
            "--created-at",
            "4294967296",
            "-i",
            input.to_str().unwrap()
        ])
        .status
        .success()
    );
    fs::write(&input, "1".repeat(152)).unwrap();
    assert!(
        !cli(&["derive", "-i", input.to_str().unwrap()])
            .status
            .success()
    );
}

#[test]
fn expiration_errors_do_not_panic_or_create_output() {
    let dir = tempfile::tempdir().unwrap();
    let words = dir.path().join("words.txt");
    let output = dir.path().join("master.asc");
    let backup = Backup::new(BackupSecret::CompactEntropy(Zeroizing::new([42; 20])), 0);
    fs::write(&words, backup.encode().as_bytes()).unwrap();
    for expires in [
        "é",
        "1年",
        "éy",
        "١d",
        "213503982334600d",
        "18446744073709551615y",
        "49711d",
        "136y",
    ] {
        let result = cli(&[
            "export",
            "--input",
            words.to_str().unwrap(),
            "--identity",
            "Test",
            "--public",
            "--expires",
            expires,
            "--output",
            output.to_str().unwrap(),
        ]);
        assert!(
            matches!(result.status.code(), Some(1 | 2)),
            "{expires}: {result:?}"
        );
        assert!(result.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&result.stderr).contains("panicked"));
        assert!(
            !output.exists(),
            "invalid expiry created an output file: {expires}"
        );
    }
}

#[test]
fn expiration_after_unix_u32_range_is_exported_and_reported() {
    use sequoia_openpgp::policy::StandardPolicy;
    use std::time::{Duration, UNIX_EPOCH};

    let dir = tempfile::tempdir().unwrap();
    let words = dir.path().join("words.txt");
    let backup = Backup::new_now(BackupSecret::CompactEntropy(Zeroizing::new([42; 20]))).unwrap();
    fs::write(&words, backup.encode().as_bytes()).unwrap();
    for protection in ["--public", "--unprotected"] {
        let output = dir.path().join(protection);
        let result = succeeds(cli(&[
            "export",
            "--input",
            words.to_str().unwrap(),
            "--identity",
            "Test",
            protection,
            "--expires",
            "100y",
            "--output",
            output.to_str().unwrap(),
        ]));
        let cert = Cert::from_bytes(&fs::read(&output).unwrap()).unwrap();
        assert_eq!(cert.is_tsk(), protection == "--unprotected");
        let policy = StandardPolicy::new();
        let valid = cert.with_policy(&policy, None).unwrap();
        let signed_at = valid
            .primary_userid()
            .unwrap()
            .binding_signature()
            .signature_creation_time()
            .unwrap();
        let expiry = valid.primary_key().key_expiration_time().unwrap();
        assert_eq!(expiry, signed_at + Duration::from_secs(100 * 365 * 86400));
        let seconds = expiry.duration_since(UNIX_EPOCH).unwrap().as_secs();
        assert!(seconds > u64::from(u32::MAX));
        assert!(
            String::from_utf8_lossy(&result.stderr)
                .contains(&format!("Key expires: {seconds} (Unix seconds)"))
        );
    }
}

#[test]
fn bounded_input_accepts_limit_and_rejects_extra_byte() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("entropy.hex");
    let mut data = " ".repeat(1024 * 1024 - 40);
    data.push_str(&"2a".repeat(20));
    fs::write(&input, &data).unwrap();
    let result = succeeds(cli(&["encode", "--input", input.to_str().unwrap()]));
    let backup = Backup::decode(std::str::from_utf8(&result.stdout).unwrap()).unwrap();
    assert_eq!(backup.secret().payload(), &[42; 20]);
    data.push(' ');
    fs::write(&input, &data).unwrap();
    let result = cli(&["encode", "--input", input.to_str().unwrap()]);
    assert_eq!(result.status.code(), Some(1));
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8_lossy(&result.stderr).contains("input exceeds 1 MiB"));
}

fn gpg(home: &Path, args: &[&str]) -> Output {
    eprintln!("GnuPG integration operation: {}", args[0]);
    Command::new("gpg")
        .args([
            "--status-fd",
            "2",
            "--homedir",
            home.to_str().unwrap(),
            "--batch",
            "--yes",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "integration-test-only",
        ])
        .args(args)
        .output()
        .expect("GnuPG must be installed for this ignored test")
}
struct AgentHome(tempfile::TempDir);
impl AgentHome {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self(dir)
    }
}
impl Drop for AgentHome {
    fn drop(&mut self) {
        let _ = Command::new("gpgconf")
            .args([
                "--homedir",
                self.0.path().to_str().unwrap(),
                "--kill",
                "gpg-agent",
            ])
            .output();
    }
}

#[test]
#[ignore = "requires GnuPG and permission to launch gpg-agent; uses isolated temporary keyrings"]
fn gpg_import_add_subkeys_and_recover() {
    for kind in [SecretKind::CompactEntropy, SecretKind::Raw] {
        let home = AgentHome::new();
        let recovered_home = AgentHome::new();
        let secret = match kind {
            SecretKind::CompactEntropy => BackupSecret::CompactEntropy(Zeroizing::new([0; 20])),
            SecretKind::Raw => {
                let mut seed = Zeroizing::new([42; 32]);
                seed[0] = 0;
                BackupSecret::Raw(seed)
            }
        };
        let backup = Backup::new(secret, 1234567890);
        let cert = master::certificate(
            &backup,
            "Recovery Test <test@example.org>",
            SystemTime::now(),
            None,
        )
        .unwrap();
        let fingerprint = cert.fingerprint().to_string();
        let protected = master::protect(cert.clone(), b"integration-test-only").unwrap();
        let export = home.0.path().join("master.asc");
        let mut armor = Vec::new();
        protected.as_tsk().armored().serialize(&mut armor).unwrap();
        fs::write(&export, armor).unwrap();
        succeeds(gpg(home.0.path(), &["--import", export.to_str().unwrap()]));
        succeeds(gpg(
            home.0.path(),
            &["--quick-add-key", &fingerprint, "ed25519", "sign", "1y"],
        ));
        succeeds(gpg(
            home.0.path(),
            &["--quick-add-key", &fingerprint, "cv25519", "encr", "1y"],
        ));
        let listing = String::from_utf8(
            succeeds(gpg(
                home.0.path(),
                &["--with-colons", "--list-secret-keys", &fingerprint],
            ))
            .stdout,
        )
        .unwrap();
        assert_eq!(listing.lines().filter(|l| l.starts_with("ssb:")).count(), 2);
        let public = succeeds(gpg(home.0.path(), &["--export", &fingerprint]));
        let public_file = home.0.path().join("public.pgp");
        fs::write(&public_file, &public.stdout).unwrap();
        // Import an actual GnuPG export (which also contains subkeys); select only
        // its primary key, preserve the timestamp, and bypass HKDF on recovery.
        let secret_export = succeeds(gpg(home.0.path(), &["--export-secret-keys", &fingerprint]));
        let raw = master::import(&secret_export.stdout, Some(b"integration-test-only")).unwrap();
        assert_eq!(raw.kind(), SecretKind::Raw);
        assert_eq!(raw.created_at(), backup.created_at());
        let native_recovery = master::certificate(
            &Backup::decode(&raw.encode()).unwrap(),
            "Native recovery",
            SystemTime::now(),
            None,
        )
        .unwrap();
        assert_eq!(native_recovery.fingerprint(), cert.fingerprint());
        let recovered = master::certificate(
            &Backup::decode(&backup.encode()).unwrap(),
            "Recovery Test <test@example.org>",
            SystemTime::now(),
            None,
        )
        .unwrap();
        assert_eq!(recovered.fingerprint(), cert.fingerprint());
        let recovered_file = home.0.path().join("recovered.pgp");
        let mut bytes = Vec::new();
        recovered.as_tsk().serialize(&mut bytes).unwrap();
        fs::write(&recovered_file, bytes).unwrap();
        succeeds(gpg(
            recovered_home.0.path(),
            &["--import", recovered_file.to_str().unwrap()],
        ));
        succeeds(gpg(
            recovered_home.0.path(),
            &["--import", public_file.to_str().unwrap()],
        ));
        let merged = Cert::from_bytes(
            &succeeds(gpg(recovered_home.0.path(), &["--export", &fingerprint])).stdout,
        )
        .unwrap();
        assert_eq!(merged.fingerprint(), cert.fingerprint());
        assert_eq!(merged.keys().count(), 3);
        succeeds(gpg(
            recovered_home.0.path(),
            &["--quick-add-key", &fingerprint, "ed25519", "auth", "1y"],
        ));
    }
}
