use gpg_keys::{backup, master};
use sequoia_openpgp::{Cert, parse::Parse, serialize::Serialize};
use std::{
    fs,
    path::Path,
    process::{Command, Output},
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
    let words = dir.path().join("words.txt");
    let words = words.to_str().unwrap();
    succeeds(cli(&["random", "-o", words]));
    let original = fs::read(words).unwrap();
    assert!(backup::decode(std::str::from_utf8(&original).unwrap()).is_ok());
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
    let hex = succeeds(cli(&["decode", "-i", words]));
    let seed_file = dir.path().join("seed.hex");
    fs::write(&seed_file, &hex.stdout).unwrap();
    assert_eq!(
        succeeds(cli(&["encode", "-i", seed_file.to_str().unwrap()])).stdout,
        original
    );
    let export_args = [
        "export",
        "-i",
        words,
        "--identity",
        "Test <test@example.org>",
    ];
    assert!(!cli(&export_args).status.success());
    let mut args = export_args.to_vec();
    args.push("--public");
    let public = Cert::from_bytes(&succeeds(cli(&args)).stdout).unwrap();
    assert!(!public.is_tsk());
    let password = dir.path().join("password");
    fs::write(&password, "test password\r\n").unwrap();
    let mut args = export_args.to_vec();
    args.extend(["--passphrase-file", password.to_str().unwrap()]);
    let private = Cert::from_bytes(&succeeds(cli(&args)).stdout).unwrap();
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
    let form = succeeds(cli(&["template"]));
    let typst = String::from_utf8(form.stdout).unwrap();
    assert!(typst.contains("paper: \"a5\""));
    assert!(typst.contains("#backup-document(("));
    assert!(!typst.contains("read(")); // No external files are needed to compile it.
    for word in backup::WORDLIST.lines() {
        assert!(typst.contains(&format!("  \"{word}\",\n")));
    }
    assert!(!typst.contains(std::str::from_utf8(&original).unwrap().trim()));
    assert!(typst.contains(backup::WORDLIST_SHA256));
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
    let home = AgentHome(tempfile::tempdir().unwrap());
    let recovered_home = AgentHome(tempfile::tempdir().unwrap());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for directory in [&home, &recovered_home] {
            fs::set_permissions(directory.0.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
    let seed = Zeroizing::new([0; 32]); // Edge case: the backup seed is not a raw GnuPG MPI.
    let cert = master::certificate(&seed, "Recovery Test <test@example.org>").unwrap();
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
    let keys = succeeds(gpg(
        home.0.path(),
        &["--with-colons", "--list-secret-keys", &fingerprint],
    ));
    let listing = String::from_utf8(keys.stdout).unwrap();
    assert_eq!(listing.lines().filter(|l| l.starts_with("ssb:")).count(), 2);
    assert!(listing.contains(&fingerprint));
    let public = succeeds(gpg(home.0.path(), &["--export", &fingerprint]));
    let public_file = home.0.path().join("public.pgp");
    fs::write(&public_file, &public.stdout).unwrap();
    let secret = backup::decode(&backup::encode(&seed)).unwrap();
    let recovered = master::certificate(&secret, "Recovery Test <test@example.org>").unwrap();
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
    let merged = succeeds(gpg(recovered_home.0.path(), &["--export", &fingerprint]));
    let merged = Cert::from_bytes(&merged.stdout).unwrap();
    assert_eq!(merged.fingerprint(), cert.fingerprint());
    assert_eq!(merged.keys().count(), 3);
    succeeds(gpg(
        recovered_home.0.path(),
        &["--quick-add-key", &fingerprint, "ed25519", "auth", "1y"],
    ));
}
