# GPKB version 1

All byte offsets below are zero-based and half-open. All bit conversions are
most significant bit first. This format uses the SLIP-39 wordlist only;
it does not implement SLIP-39's share structure, encryption, or checksum.

## Serialization

| Byte range | Length | Meaning |
| --- | ---: | --- |
| `[0,4)` | 4 | ASCII `GPKB` (`47 50 4b 42`) |
| `[4,5)` | 1 | Scheme version `01` |
| `[5,13)` | 8 | First 8 bytes of the wordlist's SHA-256 |
| `[13,45)` | 32 | Exact 256-bit backup seed |
| `[45,50)` | 5 | First 5 bytes of the checksum digest |

The checksum digest is:

```text
SHA-256(ASCII("gpg-keys/backup/v1") || 0x00 || serialized_bytes[0:45])
```

There are no separators or padding in the binary serialization. The checksum
covers every field, including the seed. It is unkeyed and does not authenticate
against an attacker; random corruptions have approximately a 2^-40 chance of
passing the checksum. This is not SLIP-39's Reed–Solomon checksum and does not
promise detection of every error affecting up to three words.

## Wordlist and encoding

The canonical wordlist is `data/slip39.txt`: exactly 1024 lowercase ASCII words,
one per line in original SLIP-39 order, each followed by LF (including the last
word). Index 0 is `academic`; index 1023 is `zero`.

```text
SHA-256(wordlist bytes):
bcc4555340332d169718aed8bf31dd9d5248cb7da6e5d355140ef4f1e601eec3

Stored 8-byte identifier:
bc c4 55 53 40 33 2d 16
```

Interpret the 50-byte serialization as 400 bits. Split consecutively into
40 groups of 10 bits. Each group is an integer from 0 to 1023 and selects the
word at that zero-based index. There is no padding, numbering, or extra word.
A mnemonic is these 40 words separated by whitespace.

For decoding, accept case-insensitive word spelling and arbitrary whitespace,
but require exactly 40 known words. Concatenate their 10-bit indices and turn
them back into 50 bytes. Require the exact marker, version, and wordlist
identifier, and recompute and compare the checksum. Only then return bytes
`[13,45)`. Do not autocorrect words. A later version must be rejected until its
rules are implemented; no implicit version fallback is allowed.

## Seed acquisition

- **Random:** obtain 32 bytes from the operating system cryptographic RNG.
- **Exact:** parse exactly 64 hex digits or 256 binary digits; ignore only ASCII
  whitespace. Preserve leading zeros. User-provided exact seeds may have poor
  entropy; warn the user that this is an advanced operation.
- **Entropy derivation:** parse at least 256 binary digits in whole bytes,
  ignoring only ASCII whitespace. Pack bits into bytes, most significant bit
  first. The packed bytes are the Argon2 password input. Do not hash the ASCII
  digit characters.

Entropy derivation is Argon2id version 0x13, with memory cost 65536 KiB, time
cost 3, parallelism 1, and output length 32 bytes. There is no optional secret
or associated data. The salt is the first 16 bytes of:

```text
SHA-256(ASCII("gpg-keys/entropy/v1"))
```

No trailing NUL is included in that domain string. The fixed salt is deliberate:
this is deterministic extraction from high-entropy bits, not a password-storage
scheme. Equal inputs produce equal seeds. Original entropy and KDF settings
are not needed to restore a seed from its words. The KDF cannot supply missing
entropy or guarantee a user's input is random.

## Deterministic OpenPGP master key

Use HKDF-SHA256 (RFC 5869) with:

```text
IKM  = 32-byte backup seed
salt = ASCII("gpg-keys/master/v1")
info = ASCII("ed25519-certification")
L    = 32 bytes

PRK = HMAC-SHA256(key=salt, message=IKM)
Ed25519_seed = HMAC-SHA256(key=PRK, message=info || 0x01)
```

These ASCII strings contain no trailing NUL. The output is the private seed for
Ed25519 as specified by RFC 8032; pass the seed to an Ed25519 implementation,
not an already clamped scalar. This separates backup seed material from the
OpenPGP key and avoids passing an all-zero backup seed directly through
GnuPG's legacy secret-MPI representation.

Create a **version 4** OpenPGP primary key with:

- Creation time `1767225600` = `2026-01-01T00:00:00Z`, fixed for this scheme.
- Legacy EdDSA public-key algorithm ID 22.
- Ed25519 curve OID `1.3.6.1.4.1.11591.15.1`, encoded as
  `09 2b 06 01 04 01 da 47 0f 01` (length plus OID).
- Public MPI: `0x40 || 32-byte Ed25519 public key`, bit length 263.
- Secret MPI: derived private seed interpreted as a big-endian integer,
  with standard MPI bit-length encoding. Implementations must restore any
  leading zero bytes when importing it as an Ed25519 seed.

The public key packet body is:

```text
04 || BE32(1767225600) || 16 || OID-length-and-bytes || MPI(public-point)
```

Here `16` is hexadecimal (algorithm 22). Its OpenPGP fingerprint is:

```text
SHA-1(0x99 || BE16(length(public-key-packet-body)) || public-key-packet-body)
```

This is OpenPGP v4's prescribed fingerprint algorithm, independent of the
SHA-256 backup checksum. Changing the timestamp, packet version, or algorithm
changes the fingerprint. The fixed timestamp is a recovery parameter, not
an assertion about when the user generated the key.

Add the supplied UTF-8 User ID and a positive self-certification (type 0x13),
hashed with SHA-256, created at the same fixed time, with key flags 0x01
(certification only), the primary-User-ID flag set, and no key or signature
expiry. Preferred hashes are SHA-512, SHA-256; preferred symmetric algorithms
are AES-256, AES-128. Use an OpenPGP library to construct and sign packets.
Identity must be nonempty and contain no control characters.

The identity and signature are not inputs to the fingerprint; recovering with
a different identity recovers the same primary key but a different certificate.
Sequoia inserts a random signature salt notation. Repeated exports therefore
need not match byte-for-byte. Passphrase encryption of secret material also
uses randomness and is separate from recovery. The program exports only the
master key; subkeys are managed by GnuPG or other OpenPGP tools.

Save and merge the public certificate after recovery to retain later User IDs,
subkey bindings, third-party certifications, expiration updates, and revocations.
Private subkeys must be backed up separately. The master seed cannot recover
their secret material. Do not remove revocations while reconstructing a usable
certificate.

## Independent vectors

`tests/vectors.txt` has six lines, in this order:

1. Backup seed hex: bytes `00` through `1f`.
2. Serialized backup hex.
3. Encoded 40 words.
4. Argon2id result for entropy bytes `00` through `1f`.
5. HKDF-derived Ed25519 seed for the backup seed.
6. Expected OpenPGP primary fingerprint.

Encoding, HKDF, and the v4 fingerprint were calculated independently using
Python's standard-library hash/HMAC functions and the OpenSSL CLI for Ed25519
public-key derivation. The Argon2 vector was cross-checked with the system
`libargon2` reference implementation. Production decoding, derivation, and
master-key generation are tested against these vectors.

## Standalone seed recovery

The following Python 3 program needs only a copy of the pinned wordlist and
the words, and does not depend on this Rust application. Its output is secret.

```python
import hashlib
from pathlib import Path

wordlist_bytes = Path("wordlist.txt").read_bytes()
expected = "bcc4555340332d169718aed8bf31dd9d5248cb7da6e5d355140ef4f1e601eec3"
assert hashlib.sha256(wordlist_bytes).hexdigest() == expected
words = wordlist_bytes.decode("ascii").splitlines()
lookup = {word: i for i, word in enumerate(words)}
tokens = Path("words.txt").read_text().lower().split()
assert len(tokens) == 40
number = 0
for word in tokens:
    number = (number << 10) | lookup[word]
data = number.to_bytes(50, "big")
assert data[:5] == b"GPKB\x01"
assert data[5:13] == bytes.fromhex(expected)[:8]
assert data[45:] == hashlib.sha256(b"gpg-keys/backup/v1\0" + data[:45]).digest()[:5]
print(data[13:45].hex())
```

Do not run Python with `-O`, which disables these assertions. To recover an
OpenPGP key without this application, derive the Ed25519 seed using the HKDF
formula above, then construct the specified OpenPGP packets with a compatible
library. Compare the result against the written fingerprint.
