# PGP key backups with pen and paper

`paper-pgp` is a command-line tool for creating an Ed25519 OpenPGP primary key
that you can back up as a short list of handwritten words. Type the words
back in to recover the same key, with the same fingerprint.

It is built for keeping your **primary key offline**. The primary key certifies
your identities and subkeys; separate subkeys handle everyday signing,
encryption, and authentication. The paper is your backup if the offline copy
is lost. The tool creates keys; it does not back up keys created elsewhere.

- **22 words** for a new key, generated from secure random data.
- A checksum that detects up to three wrong words and points to a single
  wrong word.
- A printable A5 booklet with space for the words, recovery instructions,
  and the full wordlist.

The words contain the secret itself, without encryption. Anyone with them
can recover the primary key, so keep the paper private. This project is
unreleased and has not received an independent security audit.

## Build

From the repository root, use Nix to open a shell with `paper-pgp` available:

```sh
nix shell .
```

Or build with `cargo build --release --locked` and use
`./target/release/paper-pgp`. This requires Rust with edition 2024 support,
OpenSSL 3 development libraries, `pkg-config`, and Clang/libclang.
`nix develop` provides the development tools; `nix flake check` runs the
Rust tests and validates the printable documents.

## Create a key and its paper backup

On your offline machine, save your chosen export passphrase in a private
file named `passphrase.txt`. Then generate the words and export the key:

```sh
paper-pgp random --output words.txt
paper-pgp export --input words.txt --identity 'Alice <alice@example.org>' \
  --passphrase-file passphrase.txt --output primary.asc
```

Write the 22 words from `words.txt` on paper, in order. Also record the exact
identity (`Alice <alice@example.org>`) and the fingerprint printed by
`export`. The [printable booklet](paper-backup/README.md) gives you a layout
and recovery instructions to keep with the words.

`primary.asc` is a passphrase-protected secret key you can import into an
offline GnuPG keyring. Use GnuPG to create subkeys for daily work; the
[tutorial](docs/tutorial/README.md) explains how the pieces fit together.

The passphrase protects the exported file. It is **not needed to recover
from the words**. Treat `words.txt` as secret too. Use `--output` for secret
files: it creates private files on Unix and refuses to overwrite existing ones.
Shell redirection does not provide these protections.

## Recover from paper

Type the words into `recovered-words.txt`, separated by spaces or newlines,
without numbering. If you still have your saved public certificate, restore
the secret into it. Nothing is signed, so identities, subkeys, expiry, and
revocations stay exactly as saved:

```sh
paper-pgp export --input recovered-words.txt --certificate alice-public.asc \
  --passphrase-file passphrase.txt --output recovered-primary.asc
```

Without the saved certificate, export a fresh certificate instead. Choose an
identity you intend to certify now; check that the one recorded on paper is
still appropriate:

```sh
paper-pgp export --input recovered-words.txt --identity 'Alice <alice@example.org>' \
  --passphrase-file passphrase.txt --output recovered-primary.asc
```

In both cases, compare the printed fingerprint with the one on paper. Try a
recovery before relying on your backup.

Fresh exports have no expiry by default. Add `--expires 2y` to set a two-year
validity from now. If you use expiry, set it again during a fresh recovery;
it is not stored in the words.

**The words recover only the primary secret and its creation time**, which is
stored rounded down to a multiple of 1024 seconds. Keep separate backups of
your public certificate (identities, signatures, and subkey bindings),
revocation certificate, and private subkeys. A recovered primary can create
new subkeys, but cannot decrypt messages encrypted to a lost encryption
subkey.

A fresh export certifies the supplied identity anew. If you later merge it
with a saved certificate, the fresh certification can change capabilities or
expiry and reactivate a revoked User ID. Check the merged certificate before
use; the
[recovery walkthrough](docs/tutorial/backup-recovery.md#recovering-after-losing-the-offline-keyring)
explains which settings can change. Restoring with `--certificate` avoids
this.

## More information

- [Tutorial](docs/tutorial/README.md) — primary keys, identities, subkeys,
  trust, backup and recovery, and a technical appendix.
- [Nitrokey guide](docs/tutorial/nitrokey.md) — moving the subkeys onto a
  Nitrokey 3 or another OpenPGP card, with the paper and offline keyring as
  the backup.
- [FORMAT.md](docs/FORMAT.md) — the exact backup format, supported key types,
  and recovery without this application.
- [Paper booklet](paper-backup/README.md) — build, print, or customize the
  blank backup document.
- `paper-pgp --help` and `paper-pgp <command> --help` — all commands and options.

The backup uses the SLIP-39 wordlist and checksum, but is its own format, not
a SLIP-39 share or wallet mnemonic. The code is [MIT-licensed](LICENSE); the wordlist
is [CC BY-SA 4.0](data/LICENSE.slip39), with [attribution](data/README.md).
