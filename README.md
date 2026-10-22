# PGP key backups with pen and paper

`gpg-keys` is a command-line tool for creating an Ed25519 OpenPGP primary key
that you can back up as a short list of handwritten words. Type the words
back in to recover the same key, with the same fingerprint.

It is built for keeping your **primary key offline**. The primary key certifies
your identities and subkeys; separate subkeys handle everyday signing,
encryption, and authentication. The paper is your backup if the offline copy
is lost.

- **35 words** for a new key, generated from secure random data.
- **44 words** to back up an existing compatible Ed25519 primary key.
- A checksum to detect transcription errors.
- A printable A5 booklet with space for the words, recovery instructions,
  and the full wordlist.

The words contain the secret itself, without encryption. Anyone with them
can recover the primary key, so keep the paper private. This project is
unreleased and has not received an independent security audit.

## Build

From the repository root, use Nix to open a shell with `gpg-keys` available:

```sh
nix shell .
```

Or build with `cargo build --release --locked` and use
`./target/release/gpg-keys`. This requires Rust with edition 2024 support,
OpenSSL 3 development libraries, `pkg-config`, and Clang/libclang.
`nix develop` provides the development tools; `nix flake check` runs the
Rust tests and validates the printable documents.

## Create a key and its paper backup

On your offline machine, save your chosen export passphrase in a private
file named `passphrase.txt`. Then generate the words and export the key:

```sh
gpg-keys random --output words.txt
gpg-keys export --input words.txt --identity 'Alice <alice@example.org>' \
  --passphrase-file passphrase.txt --output primary.asc
```

Write the 35 words from `words.txt` on paper, in order. Also record the exact
identity (`Alice <alice@example.org>`) and the fingerprint printed by
`export`. The [printable booklet](paper-backup/README.md) gives you a layout
and recovery instructions to keep with the words.

`primary.asc` is a passphrase-protected secret key you can import into an
offline GnuPG keyring. Use GnuPG to create subkeys for daily work; the
[tutorial](TUTORIAL.md) explains how the pieces fit together.

The passphrase protects the exported file. It is **not needed to recover
from the words**. Treat `words.txt` as secret too. Use `--output` for secret
files: it creates private files on Unix and refuses to overwrite existing ones.

## Recover from paper

Type the words into `recovered-words.txt`, separated by spaces or newlines,
without numbering. Export again with your recorded identity and a passphrase
file for the recovered key:

```sh
gpg-keys export --input recovered-words.txt --identity 'Alice <alice@example.org>' \
  --passphrase-file passphrase.txt --output recovered-primary.asc
```

Compare the printed fingerprint with the one on paper. Try this recovery
before relying on your backup.

Keys do not expire by default. Add `--expires 2y` to an export to set a
two-year validity from now. If you use expiry, set it again during recovery;
it is not stored in the words.

**The words recover only the primary secret and its creation time.** Keep
separate backups of your public certificate (identities, signatures, and
subkey bindings), revocation certificate, and private subkeys. Merge the
saved public certificate after recovery. A recovered primary can create new
subkeys, but cannot decrypt messages encrypted to a lost encryption subkey.

## More information

- [TUTORIAL.md](TUTORIAL.md) — primary keys, identities, subkeys, trust,
  and practices for keeping the primary offline.
- [FORMAT.md](FORMAT.md) — the exact backup format, supported key types,
  and recovery without this application.
- [Paper booklet](paper-backup/README.md) — build, print, or customize the
  blank backup document.
- `gpg-keys --help` and `gpg-keys <command> --help` — all commands and options,
  including `import` for existing v4/algorithm-22 Ed25519 primary keys.

The backup uses the SLIP-39 wordlist, but is its own format, not a SLIP-39
share or wallet mnemonic. The code is [MIT-licensed](LICENSE); the wordlist
is [CC BY-SA 4.0](data/LICENSE.slip39), with [attribution](data/README.md).
