# gpg-keys

A Rust CLI for a 256-bit secret backed up as 40 handwritten words, with a
recoverable Ed25519 OpenPGP certification master key. Subkeys are managed by
GnuPG or other OpenPGP tools.

The wordlist is SLIP-39's 1024-word list; **GPKB v1 is its own format**, not a
SLIP-39 share, wallet mnemonic, or secret-sharing scheme. The exact binary
format and recovery rules are in [FORMAT.md](FORMAT.md).

## Build

The flake pins nixpkgs, Rust, Typst, OpenSSL, Clang, and document fonts. It
offers the Rust app as the default package and the A5 PDF as a separate package:

```sh
nix build                              # result/bin/gpg-keys
nix run . -- --help
nix build .#paper-backup --out-link result-paper-backup
# PDF: result-paper-backup/paper-backup.pdf
nix flake check                        # Rust tests + document validation
nix develop                            # Rust/Typst development tools
nix fmt                                # Nix formatter
```

The flake exposes packages for x86_64/aarch64 Linux and macOS. The build was
verified on x86_64 Linux. Sources and package definitions are separated:

```text
flake.nix / flake.lock       # pinned inputs and packages/apps/checks/devShells
nix/package.nix             # Rust package, Cargo.lock, OpenSSL and bindgen
nix/paper-backup.nix         # Typst PDF build with pinned fonts
nix/check-paper-backup.*     # checks the actual compiled recovery document
paper-backup/main.typ        # document entry point; reads the shared wordlist
paper-backup/template.typ    # layout also embedded by the Rust CLI
src/                        # Rust application
data/slip39.txt              # canonical wordlist for both app and document
```

This is a small `callPackage` layout: the root flake wires the outputs, while
ordinary package functions live under `nix/`. `buildRustPackage` vendors
dependencies from `Cargo.lock`; no separate cargo hash or Rust overlay is
needed. `flake.lock` pins the toolchain and `Cargo.lock` pins the crates.
Source filtering keeps generated PDFs and document edits out of the Rust build
unless its embedded template changes. PDFs and `result*` links are generated
outputs, not versioned sources. Git-backed flakes only include files known to
Git; add new source files before building them.

To build with Cargo directly (or from `nix develop`):

Requires Rust with edition 2024 support, OpenSSL 3 development libraries,
`pkg-config`, and Clang/libclang (Sequoia's OpenSSL bindings use bindgen).
GnuPG is only needed to import and manage keys and to run the optional
integration test. The cryptography uses Sequoia's OpenSSL backend.

```sh
cargo build --release --locked
./target/release/gpg-keys --help
```

## Create a paper backup and master key

```sh
gpg-keys random --output words.txt
nix build .#paper-backup --out-link result-paper-backup
```

Print `result-paper-backup/paper-backup.pdf` at actual size on A5 paper
(148 × 210 mm). The ten-page document has two handwriting pages, two recovery
pages, and six pages containing the full indexed wordlist. Handwrite the words
from `words.txt` in order and retain all pages together. Do a recovery check
before relying on the paper. See [paper-backup/README.md](paper-backup/README.md)
for editing and compiling the Typst source.

The CLI also exports a **self-contained Typst source** using the same template,
with the wordlist embedded. It does not fill in your secret words:

```sh
gpg-keys template --output backup.typ
typst compile backup.typ backup.pdf
```

The `template` command now produces Typst rather than HTML. Use the pinned
Typst and fonts in `nix develop` for the same layout as the Nix PDF build.

Create a file containing your export passphrase, then export:

```sh
gpg-keys export --input words.txt --identity 'Alice <alice@example.org>' \
  --passphrase-file passphrase.txt --output master.asc
gpg-keys export --input words.txt --identity 'Alice <alice@example.org>' \
  --public --output public.asc
```

The fingerprint is printed to stderr. Write it and the exact User ID on the
paper. `--unprotected` is available as an explicit alternative to
`--passphrase-file`. The export passphrase protects the exported secret key;
it is **not** needed to recover from the words. Keep the paper confidential.

Every input/output option defaults to `-` (stdin/stdout). Secrets never need
to appear in command-line arguments. Input is capped at 1 MiB. New output files
are mode 0600 on Unix, and existing files are never overwritten. Shell
redirection bypasses these file protections; use `--output` for secret files.
One final LF or CRLF is removed from passphrase files; other bytes are preserved.
Secret buffers owned by this application are cleared when dropped, but this
does not protect terminal scrollback, swap, process snapshots, or copies outside
those buffers.

## Other seed sources

To derive a seed from a long, high-entropy binary string:

```sh
gpg-keys derive --input entropy-bits.txt --output words.txt
```

Input must contain at least 256 bits, in whole bytes, using `0` and `1` with
optional ASCII whitespace. Bits are packed most significant bit first before
Argon2id. The KDF is deterministic with fixed, versioned parameters. It cannot
turn predictable input into a secure key. Use `random` unless you have a reliable
source of independent random bits.

Advanced users can supply exactly 256 bits, as 64 hexadecimal digits or 256
binary digits. ASCII whitespace is allowed; no `0x` prefix is accepted.

```sh
gpg-keys encode --input seed.hex --output words.txt
gpg-keys encode --format binary --input seed-bits.txt --output words.txt
gpg-keys decode --input words.txt --output recovered-seed.hex
gpg-keys wordlist --output wordlist.txt
```

`decode` checks the marker, version, wordlist identifier, and checksum before
returning a seed. Words are case-insensitive and separated by whitespace.
Numbers, punctuation, unknown words, wrong word counts, and checksum failures
are rejected; words are not silently corrected.

## Import, subkeys, and recovery

Use a dedicated offline GnuPG home for the certification master:

```sh
mkdir -m 700 offline-gnupg
gpg --homedir offline-gnupg --import master.asc
gpg --homedir offline-gnupg --quick-add-key PRIMARY_FINGERPRINT ed25519 sign 1y
gpg --homedir offline-gnupg --quick-add-key PRIMARY_FINGERPRINT cv25519 encr 1y
```

Replace `PRIMARY_FINGERPRINT` with the actual fingerprint. GnuPG handles
passphrase prompts and subkey creation. The primary key has certification-only
flags and no expiration; daily signing and encryption belong on subkeys.
Record any later expiration changes in the separately saved public certificate.
GnuPG's [key-management manual](https://www.gnupg.org/documentation/manuals/gnupg/OpenPGP-Key-Management.html)
documents these commands.

On recovery, type only the 40 words into a text file, validate them with
`decode`, then use `export` again with the recorded identity. Compare the
fingerprint with the paper and your saved public certificate before using the
key. The master fingerprint is stable across recovery, identity changes, export
passphrases, and the current time. Exported certificate bytes can differ because
Sequoia randomizes signature salt and secret-key protection.

The ASCII-armored exports also parse as Sequoia certificates. GnuPG imports,
creation of signing/encryption subkeys, and recovery followed by merging the
saved public certificate are covered by the optional integration test.

**The words recover the master secret only.** Separately back up your public
certificate (including User IDs, certifications, revocations, and subkey
bindings), revocation certificate, and private subkeys. Recovering the master
can create new subkeys but cannot decrypt messages encrypted to lost old
subkeys. Ownertrust and GnuPG configuration are separate local state.

This is a new backup format and has not received an independent security audit.
The seed contains 256 bits; Ed25519 provides about 128-bit classical security.
The words are an encoding of a secret, not encrypted storage, and the checksum
detects accidental damage rather than malicious modification.

## Verification

```sh
nix flake check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --check
cargo test --locked --test cli gpg_import_add_subkeys_and_recover -- --ignored
```

The last test starts `gpg-agent` in temporary keyrings, kills those agents on
exit, and never uses your normal keyring. It requires GnuPG and an environment
that allows agents to run. Other tests cover independent serialization, KDF and
master-key vectors, transcription errors, metadata validation, export
protection, restrictive output permissions, and overwrite refusal.

## Wordlist attribution

[data/slip39.txt](data/slip39.txt) is the unmodified wordlist from
[SatoshiLabs' SLIP-0039](https://github.com/satoshilabs/slips/blob/master/slip-0039.md#wordlist),
retrieved on 2026-10-14. It is distributed under CC BY-SA 4.0; see
[data/LICENSE.slip39](data/LICENSE.slip39). Its SHA-256 is pinned in the format
specification and verified by tests. The application is under the repository's
[MIT license](LICENSE).
