# GPKB version 1

GPKB means **GPG Key Backup**. It is this project's format marker, not an
OpenPGP standard. The format uses the SLIP-39 wordlist only; it does not
implement SLIP-39 shares, encryption, or its checksum.

This project is unreleased. Version 1 now includes a creation timestamp and a
tagged secret. Earlier experimental 40-word backups are not supported by this
layout; the version has not been bumped before release.

## Logical structure and binary envelope

```text
Backup {
    version:     u8 = 1,
    wordlist_id: [u8; 8],
    created_at:  u32,        // OpenPGP primary-key creation time, Unix seconds
    secret:      Raw([u8; 32]) | CompactEntropy([u8; 20]),
}

GPKB | version | wordlist_id | BE32(created_at) | tag | payload | checksum
```

The Rust structure stores validated fields, and its secret arrays are cleared
on drop. Magic, checksum, and word padding belong to the envelope. Serialization
uses explicit field widths and stable tags, without Serde or MessagePack.
All byte ranges below are zero-based and half-open. All bit conversions are
most significant bit first.

| Byte range | Length | Meaning |
| --- | ---: | --- |
| `[0,4)` | 4 | ASCII `GPKB` (`47 50 4b 42`) |
| `[4,5)` | 1 | Scheme version `01` |
| `[5,13)` | 8 | First 8 bytes of the canonical wordlist's SHA-256 |
| `[13,17)` | 4 | Unsigned big-endian OpenPGP primary creation timestamp |
| `[17,18)` | 1 | Secret variant: `00` = Raw, `01` = CompactEntropy |
| `[18,body_len)` | 32 or 20 | Exact secret payload, including leading zeros |
| `[body_len,body_len+5)` | 5 | First 5 bytes of the checksum digest |

| Variant | Payload | `body_len` | Serialized bytes | Word count | Final word padding |
| --- | ---: | ---: | ---: | ---: | ---: |
| Raw (`00`) | 32 bytes | 50 | 55 | 44 | none |
| CompactEntropy (`01`) | 20 bytes | 38 | 43 | 35 | 6 zero bits |

The checksum digest is:

```text
SHA-256(ASCII("gpg-keys/backup/v1") || 0x00 || serialized_bytes[0:body_len])
```

It covers **all preceding bytes, including GPKB**, the timestamp, variant, and
secret. There is no padding inside the binary serialization. Word padding is
outside the checksum and must be checked separately. Reject unknown markers,
versions, wordlist identifiers, and tags; truncated or extra bytes; lengths
inconsistent with the variant; and checksum failures. Do not infer a variant
by ignoring its tag or attempt an implicit version fallback.

The checksum is unkeyed: it detects accidental damage, not malicious changes.
Random corruptions have approximately a 2^-40 chance of passing. It is not
SLIP-39's Reed–Solomon checksum and does not promise detection of every error
affecting up to three words.

## Wordlist and encoding

The canonical wordlist is `data/slip39.txt`: exactly 1024 lowercase ASCII words,
one per line in original SLIP-39 order, each followed by LF, including the last.
Index 0 is `academic`; index 1023 is `zero`.

```text
SHA-256(wordlist bytes):
bcc4555340332d169718aed8bf31dd9d5248cb7da6e5d355140ef4f1e601eec3

Stored 8-byte identifier:
bc c4 55 53 40 33 2d 16
```

Expand serialized bytes into bits, most significant bit first. For compact
backups, append exactly six zero bits to the 344 bits; raw backups already have
440 bits. Split into 35 or 44 consecutive 10-bit groups. Each group selects
the word at that zero-based index. Emit words separated by whitespace.

Decoding accepts case-insensitive word spelling and arbitrary whitespace.
Require exactly 35 or 44 known words. Concatenate their 10-bit indices. For
35 words, check that the final six bits are zero and remove them; regroup into
43 bytes. For 44 words, regroup into 55 bytes with no padding. Validate the
entire envelope before returning a `Backup`. Its tag must agree with the word
count. Reject numbering, punctuation, and unknown words; never autocorrect.

## Secret acquisition and creation time

- **Random:** obtain 20 bytes from the operating system cryptographic RNG and
  store `CompactEntropy`.
- **Exact compact:** parse exactly 40 hexadecimal digits or 160 binary digits
  as 20 bytes of `CompactEntropy`.
- **Exact raw:** parse exactly 64 hexadecimal digits or 256 binary digits as
  the native 32-byte Ed25519 private seed. Store `Raw` without a KDF.
- **Entropy derivation:** parse at least 160 binary digits in whole bytes.
  Pack bits most significant bit first and derive 20 bytes with Argon2id;
  store `CompactEntropy`. Do not hash the ASCII digit characters.
- **Existing OpenPGP master:** import the native Ed25519 private seed and
  original packet timestamp as `Raw`, as specified below.

Exact and entropy inputs ignore only ASCII whitespace and preserve leading
zeros; hexadecimal inputs do not accept a `0x` prefix. Short inputs are rejected,
not zero-padded. Padding an input or running a KDF cannot create missing entropy.

New backups store the current Unix time, in whole seconds. `--created-at` can
override it for exact reproduction. Imported keys use their original creation
time. Timestamps must fit OpenPGP's unsigned 32-bit range. The same secret with
a different timestamp has a different OpenPGP fingerprint; re-encoding decoded
hex therefore requires both the original variant and timestamp.

Entropy derivation uses Argon2id version 0x13, memory cost 65536 KiB, time cost 3,
parallelism 1, and **output length 20 bytes**. There is no optional secret or
associated data. The salt is the first 16 bytes of:

```text
SHA-256(ASCII("gpg-keys/entropy/v1"))
```

No trailing NUL is included. The fixed salt deliberately makes extraction from
high-entropy bits deterministic; this is not a password-storage scheme. Equal
inputs produce equal entropy payloads. Original input and Argon2 settings are
not needed to recover the already-derived payload from the words.

## Mapping to the OpenPGP primary key

```text
Backup.secret
  Raw(32 bytes) ------------------------------> native Ed25519 private seed
  CompactEntropy(20 bytes) -- HKDF-SHA256 -----> native Ed25519 private seed
                                                        |
                                              RFC 8032 public-key derivation
                                                        |
Backup.created_at ---------------------> v4 algorithm-22 primary-key packet
                                                        |
                                              OpenPGP v4 fingerprint
```

**Raw bypasses HKDF.** It already holds the native private seed, which must be
used unchanged. CompactEntropy uses HKDF-SHA256 (RFC 5869):

```text
IKM  = 20-byte CompactEntropy payload
salt = ASCII("gpg-keys/master/v1")
info = ASCII("ed25519-certification")
L    = 32 bytes

PRK = HMAC-SHA256(key=salt, message=IKM)
Ed25519_seed = HMAC-SHA256(key=PRK, message=info || 0x01)
```

These ASCII strings have no trailing NUL. Use the native private seed as
specified by RFC 8032, not an already clamped scalar. HKDF expands its length;
it does not increase its entropy. Compact backups provide at most 160 bits of
seed entropy; Ed25519 has about 128-bit classical security.

Create a **version 4** OpenPGP primary key with:

- Creation time exactly equal to `Backup.created_at`.
- Legacy EdDSA public-key algorithm ID 22, chosen for GnuPG 2.4 compatibility.
- Ed25519 curve OID `1.3.6.1.4.1.11591.15.1`, encoded with length as
  `09 2b 06 01 04 01 da 47 0f 01`.
- Public MPI: `0x40 || 32-byte Ed25519 public key`, bit length 263.
- Secret MPI: native private seed as a big-endian integer with standard MPI
  bit-length encoding. Restore leading zero bytes to obtain the 32-byte seed.

The public-key packet body and fingerprint are:

```text
body = 04 || BE32(created_at) || 16 || OID-length-and-bytes || MPI(public-point)
fingerprint = SHA-1(0x99 || BE16(length(body)) || body)
```

Here `16` is hexadecimal (algorithm 22). SHA-1 is prescribed by OpenPGP v4 for
the fingerprint, independently of the SHA-256 backup checksum. Changing the
timestamp, packet version, or algorithm changes the fingerprint.

Add the supplied UTF-8 User ID and a positive self-certification (type 0x13),
hashed with SHA-256, created at export time, with key flags 0x01
(certification only), primary-User-ID flag set, and no signature expiry. A key
expiration time subpacket (type 9) is present only when requested. It holds the
seconds from the key creation time to the expiry, where the expiry is the
requested validity added to the signing time, and must fit in 32 bits.
The signature time must not precede the key creation time; exports reject an
earlier clock. Dating the self-signature at export time makes it the newest
self-signature when the recovered certificate is merged with a saved copy, so
OpenPGP implementations apply its metadata unambiguously.
Preferred hashes are SHA-512, SHA-256; preferred symmetric algorithms are
AES-256, AES-128. Identity must be nonempty and contain no control characters.
Use an OpenPGP library to construct and sign these packets.

The User ID is recorded separately on paper, not stored in the backup. It and
the self-signature do not affect the primary fingerprint. Recovering with a
different identity produces the same primary key in a different certificate.
Sequoia's random signature salt notation and secret-key protection mean that
repeated exports need not match byte-for-byte. Export passphrases are separate
from word recovery and are not needed to recover the secret.

## Importing an existing key

Accept exactly one OpenPGP certificate, armored or binary, containing an
exportable version 4, algorithm-22 Ed25519 **primary** secret key. Extract its
native seed, left-padding its MPI to 32 bytes, and retain its packet creation
timestamp. Store it as `Raw`. Reject other key types or versions, public-only
certificates, multiple certificates, unavailable secret stubs, and invalid
private lengths. Decrypt protected exports using the supplied passphrase.
Before emitting words, reconstruct the primary key and require its fingerprint
to match the imported one.

GnuPG 2.4 may export a noncanonical byte-aligned secret MPI (its opaque SOS
representation). For v4 CFB/SHA1-protected Ed25519 exports only, a narrow
compatibility path accepts at most 32 payload bytes after validating the original
SHA-1 secret checksum and byte-aligned length header. The reconstructed public
fingerprint must still match. Other protected encodings use Sequoia's normal
parser and decryption.

The backup deliberately contains only the primary secret and its timestamp.
Imported primary capabilities, User IDs, expirations, revocations, third-party
certifications, and subkey bindings remain in the public certificate. Recovery
initially creates the certification-only certificate described above; **save
and merge the original public certificate** to retain its original metadata.
Never discard revocations when reconstructing a usable certificate.

Private subkeys require separate backups. The master seed cannot recreate their
private material or decrypt messages encrypted to lost encryption subkeys.
This format cannot import arbitrary RSA keys, entire keyrings, or secret-key
packet blobs; Raw is specifically a 32-byte native Ed25519 private seed.

## Independent vectors

`tests/vectors.txt` is tab-separated, with three lines:

1. `compact`, timestamp, payload hex (bytes `00` through `13`), serialized hex,
   35 words, HKDF-derived native seed hex, expected primary fingerprint.
2. `raw`, timestamp, RFC 8032 native seed hex, serialized hex, 44 words,
   unchanged native seed hex, expected primary fingerprint.
3. `argon2id`, input hex (bytes `00` through `13`), 20-byte output hex.

Serialization, HKDF, and fingerprints were calculated independently with
Python's standard-library hash/HMAC functions and the OpenSSL CLI for Ed25519
public-key derivation. Argon2 was cross-checked with the system `libargon2`
reference implementation. Tests compare production results against these
vectors and exercise both recovery branches through GnuPG.

## Standalone secret recovery

This Python 3 program needs only the pinned wordlist and words. It validates
either variant and prints the metadata plus its **native Ed25519 private seed**.
Its output is secret. Do not run with `-O`, which disables assertions.

```python
import hashlib
import hmac
from pathlib import Path

wordlist_bytes = Path("wordlist.txt").read_bytes()
expected = "bcc4555340332d169718aed8bf31dd9d5248cb7da6e5d355140ef4f1e601eec3"
assert hashlib.sha256(wordlist_bytes).hexdigest() == expected
lookup = {word: i for i, word in enumerate(wordlist_bytes.decode("ascii").splitlines())}
tokens = Path("words.txt").read_text().lower().split()
assert len(tokens) in (35, 44)
number = 0
for word in tokens:
    number = (number << 10) | lookup[word]
if len(tokens) == 35:
    assert number & 63 == 0  # six trailing zero padding bits
    number >>= 6
    data = number.to_bytes(43, "big")
    assert data[17] == 1
else:
    data = number.to_bytes(55, "big")
    assert data[17] == 0
assert data[:5] == b"GPKB\x01"
assert data[5:13] == bytes.fromhex(expected)[:8]
assert data[-5:] == hashlib.sha256(b"gpg-keys/backup/v1\0" + data[:-5]).digest()[:5]
created_at = int.from_bytes(data[13:17], "big")
native_seed = data[18:-5]
if data[17] == 1:
    prk = hmac.new(b"gpg-keys/master/v1", native_seed, hashlib.sha256).digest()
    native_seed = hmac.new(prk, b"ed25519-certification\x01", hashlib.sha256).digest()
print("variant:", "compact" if data[17] == 1 else "raw", "created-at:", created_at)
print("native Ed25519 seed:", native_seed.hex())
```

To reconstruct an OpenPGP key without this application, use the resulting native
seed and stored creation time to construct the packets specified above with a
compatible library. Compare the fingerprint against the paper and saved public
certificate before use.
