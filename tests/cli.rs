use gpg_keys::{
    backup::{Backup, ENTROPY_LEN, WORD_COUNT, WORDLIST, WORDLIST_SHA256},
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
fn file_workflow_and_protection() {
    let dir = tempfile::tempdir().unwrap();
    let words_path = dir.path().join("words.txt");
    let words = words_path.to_str().unwrap();
    let before = gpg_keys::backup::timestamp(SystemTime::now()).unwrap();
    succeeds(cli(&["random", "-o", words]));
    let after = gpg_keys::backup::timestamp(SystemTime::now()).unwrap();
    let original = fs::read(words).unwrap();
    let backup = Backup::decode(std::str::from_utf8(&original).unwrap()).unwrap();
    assert!((before & !1023..=after).contains(&backup.created_at()));
    assert_eq!(backup.created_at() % 1024, 0);
    assert_eq!(backup.version(), 1);
    assert_eq!(
        original.iter().filter(|b| **b == b' ').count(),
        WORD_COUNT - 1
    );
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
    assert_eq!(decoded.stdout.len(), ENTROPY_LEN * 2 + 1);
    let seed_file = dir.path().join("seed.hex");
    fs::write(&seed_file, &decoded.stdout).unwrap();
    assert_eq!(
        succeeds(cli(&[
            "encode",
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
    fs::write(&password, "\n").unwrap();
    assert!(!cli(&args).status.success());
    // Existing keys are not imported; the command no longer exists.
    let exported = dir.path().join("master.asc");
    fs::write(&exported, &secret_bytes).unwrap();
    assert!(
        !cli(&["import", "-i", exported.to_str().unwrap()])
            .status
            .success()
    );
    let typst = String::from_utf8(succeeds(cli(&["template"])).stdout).unwrap();
    assert!(typst.contains("paper: \"a5\""));
    assert!(typst.contains("#backup-document(("));
    assert!(!typst.contains("read("));
    for word in WORDLIST.lines() {
        assert!(typst.contains(&format!("  \"{word}\",\n")));
    }
    assert!(!typst.contains(std::str::from_utf8(&original).unwrap().trim()));
    assert!(typst.contains(WORDLIST_SHA256));
}

#[test]
fn explicit_input_rounding_and_entropy_derivation() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("bits.txt");
    fs::write(&input, "10101010\n".repeat(ENTROPY_LEN)).unwrap();
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
    assert_eq!(backup.secret(), &[170; ENTROPY_LEN]);
    assert_eq!(backup.created_at(), 1699999744);
    assert!(String::from_utf8_lossy(&encoded.stderr).contains("created-at: 1699999744"));
    let derived = succeeds(cli(&[
        "derive",
        "--created-at",
        "1700000000",
        "-i",
        input.to_str().unwrap(),
    ]));
    let derived = Backup::decode(std::str::from_utf8(&derived.stdout).unwrap()).unwrap();
    assert_eq!(derived.created_at(), backup.created_at());
    assert_ne!(derived.secret(), backup.secret());
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
    fs::write(&input, format!("zz{}", "f".repeat(ENTROPY_LEN * 2 - 2))).unwrap();
    let invalid = cli(&["encode", "-i", input.to_str().unwrap()]);
    assert!(!invalid.status.success());
    let stderr = String::from_utf8_lossy(&invalid.stderr);
    assert!(
        stderr.contains("hexadecimal") && !stderr.contains("position"),
        "{stderr}"
    );
}

#[test]
fn decode_locates_single_wrong_word_and_accepts_bom() {
    let dir = tempfile::tempdir().unwrap();
    let words = dir.path().join("words.txt");
    let backup = Backup::new(Zeroizing::new([7; ENTROPY_LEN]), 1767225344);
    let mnemonic = backup.encode();
    let original: Vec<_> = mnemonic.split_whitespace().collect();
    let other = |word: &str| {
        if word == "academic" {
            "zero"
        } else {
            "academic"
        }
    };
    let mut wrong = original.clone();
    wrong[6] = other(wrong[6]);
    fs::write(&words, wrong.join(" ")).unwrap();
    let result = cli(&["decode", "-i", words.to_str().unwrap()]);
    assert_eq!(result.status.code(), Some(1));
    assert!(result.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(stderr.contains("word 7 is probably wrong"), "{stderr}");
    assert!(!stderr.contains(original[6]), "{stderr}");
    wrong[15] = other(wrong[15]);
    fs::write(&words, wrong.join(" ")).unwrap();
    let result = cli(&["decode", "-i", words.to_str().unwrap()]);
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stderr).contains("at least two words are wrong"));
    let expected_hex = format!("{}\n", hex::encode(backup.secret()));
    fs::write(&words, format!("\u{feff}{}", original.join("\r\n"))).unwrap();
    let decoded = succeeds(cli(&["decode", "-i", words.to_str().unwrap()]));
    assert_eq!(decoded.stdout, expected_hex.as_bytes());
    fs::write(&words, original.join(" ").to_uppercase()).unwrap();
    let decoded = succeeds(cli(&["decode", "-i", words.to_str().unwrap()]));
    assert_eq!(decoded.stdout, expected_hex.as_bytes());
}

#[test]
fn identity_is_trimmed() {
    let dir = tempfile::tempdir().unwrap();
    let words = dir.path().join("words.txt");
    let backup = Backup::new(Zeroizing::new([9; ENTROPY_LEN]), 1767225344);
    fs::write(&words, backup.encode().as_bytes()).unwrap();
    let result = succeeds(cli(&[
        "export",
        "-i",
        words.to_str().unwrap(),
        "--identity",
        "  Alice <alice@example.org>  ",
        "--public",
    ]));
    let cert = Cert::from_bytes(&result.stdout).unwrap();
    assert_eq!(
        cert.userids().next().unwrap().userid().value(),
        b"Alice <alice@example.org>"
    );
    assert!(
        !cli(&[
            "export",
            "-i",
            words.to_str().unwrap(),
            "--identity",
            "   ",
            "--public",
        ])
        .status
        .success()
    );
}

#[test]
fn expiration_errors_do_not_panic_or_create_output() {
    let dir = tempfile::tempdir().unwrap();
    let words = dir.path().join("words.txt");
    let output = dir.path().join("master.asc");
    let backup = Backup::new(Zeroizing::new([42; ENTROPY_LEN]), 0);
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
    let backup = Backup::new_now(Zeroizing::new([42; ENTROPY_LEN])).unwrap();
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
    data.push_str(&"2a".repeat(ENTROPY_LEN));
    fs::write(&input, &data).unwrap();
    let result = succeeds(cli(&["encode", "--input", input.to_str().unwrap()]));
    let backup = Backup::decode(std::str::from_utf8(&result.stdout).unwrap()).unwrap();
    assert_eq!(backup.secret(), &[42; ENTROPY_LEN]);
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
    let home = AgentHome::new();
    let recovered_home = AgentHome::new();
    let backup = Backup::new(Zeroizing::new([0; ENTROPY_LEN]), 1234567890);
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
