# Technical appendix

The details below explain how the relationships described in
[openpgp-keys.md](openpgp-keys.md) are represented.
They are optional for following Alice's setup. The packet and fingerprint
examples describe the version 4 keys produced by this project.

## Secret handling

The application wipes its secret buffers and Argon2 workspace when dropped.
It allocates input/output buffers before filling them to avoid leaving
unwiped copies when those buffers grow. This is best-effort cleanup:
temporary stack or library copies, I/O buffers, terminal scrollback, swap,
and process snapshots can retain secrets. Alice still protects her files
and the machine on which she generates or recovers keys.

## The primary-key packet and fingerprint

The primary public-key packet contains a version, creation time, algorithm,
and public key material. For `paper-pgp`, these are version 4, the backed-up
timestamp, algorithm 22 (legacy OpenPGP Ed25519), and the curve identifier
plus encoded Ed25519 public point.

```text
fingerprint = SHA-1(0x99 || two-byte body length || public-key packet body)
```

Names, expiry, and capabilities are not fields in that packet. For the
certificates this tool exports, they are represented by User IDs and their
self-signatures. The primary secret is a 32-byte native Ed25519 seed,
derived from the stored 20-byte entropy. The precise
derivation and encoding are specified in [FORMAT.md](../FORMAT.md).

## Who signs what

| Signature | Type | Signer | What it connects or affects |
| --- | --- | --- | --- |
| Data signature | `0x00` / `0x01` | A signing key | Binary data / canonical text |
| User ID certification | `0x10`–`0x13` | The primary itself or another certifier | Primary key and User ID |
| Subkey binding | `0x18` | Primary key | Primary key and subkey |
| Back-signature | `0x19` | Signing subkey | The same primary key and subkey |
| Key revocation | `0x20` | Primary key in Alice's setup | Primary key |
| Subkey revocation | `0x28` | Primary key in Alice's setup | Primary key and subkey |
| Certification revocation | `0x30` | The certifier | Its earlier certification |

`paper-pgp` creates a type `0x13` self-certification. It carries the certify
flag, optional primary expiry, algorithm preferences, and a primary-User-ID
marker. Subkey bindings carry the subkey's capabilities and expiry instead.

For version 4 keys, the signed inputs have these shapes:

```text
User ID certification:
    0x99 || two-byte primary body length || primary body
    0xB4 || four-byte User ID length || User ID
    signature metadata and trailer

Subkey binding and back-signature:
    0x99 || two-byte primary body length || primary body
    0x99 || two-byte subkey body length || subkey body
    signature metadata and trailer
```

These are structural sketches, not a complete signing implementation.

## Why a signing subkey signs back

A primary signs the binding to a subkey. A signing subkey also signs back,
confirming the association with that primary. Its back-signature is embedded
in the primary's binding signature. This prevents another primary holder
from simply attaching someone else's public signing subkey and claiming its
signatures. GnuPG explains the mechanism in its
[cross-certification guide](https://www.gnupg.org/faq/subkey-cross-certify.html).

A holder of the necessary secrets can deliberately bind a subkey under a
different primary. Its fingerprint stays the same, but the new primary must
make a new binding, and a signing subkey must make a new back-signature.
This is an advanced migration operation; it is not needed for paper recovery.

## Updating metadata and delegating trust

For multiple self-signatures on the same component, the newest valid one
determines its metadata. This is how expiry and preferences can change
without changing the key. Do not depend on ordering between signatures made
in the same second. See the specification's
[notes on self-signatures](https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.10).

A third-party certification can also carry a **trust signature**, delegating
authority to certify other identities within a stated scope and depth.
This supports arrangements such as organizational certifiers; Alice does not
need it for the personal setup described here.
