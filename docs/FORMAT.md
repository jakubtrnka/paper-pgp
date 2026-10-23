# GPG Key Backup, version 1

GPG Key Backup, abbreviated GPKB, is this project's backup format, not an
OpenPGP standard. The format uses the SLIP-39 wordlist and SLIP-39's `rs1024`
checksum; it does not implement SLIP-39 shares or encryption, and a GPG Key
Backup is not a SLIP-39 share.

This project is unreleased. Earlier experimental layouts (40, 35 and 44 words)
are not supported; the version has not been bumped before release.

## Scope

A backup holds the 160-bit entropy from which this tool derives an Ed25519
OpenPGP primary key, plus that key's creation time. The tool creates keys; it
does not back up keys created elsewhere. To move an existing key to a
paper-backed primary, generate a new primary with this tool and either
cross-certify the old and new certificates or rebind the existing subkeys
under the new primary with a tool such as Sequoia's `sq`. For a plain backup of
an existing key, use an encrypted secret-key export or `paperkey`.

## Layout

A backup is 22 words: 19 data words followed by 3 checksum words. Each word is
one 10-bit symbol, its zero-based index in the wordlist.

```text
 bit    0        8                       30                                  190
        ┌────────┬───────────────────────┬────────────────────────────────────┐
        │ ver=01 │ created_at >> 10      │ entropy                            │
        │ 8 bits │ 22 bits               │ 160 bits                           │
        └────────┴───────────────────────┴────────────────────────────────────┘
                                          190 bits = 19 words, no padding

 word    1       5         10        15          20–22
        ┌─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┬─┐ ┌─┬─┬─┐
        │d│d│d│d│d│d│d│d│d│d│d│d│d│d│d│d│d│d│d│ │c│c│c│
        └─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┴─┘ └─┴─┴─┘
          ╰─┬─╯ ╰──────────────┬──────────────╯╰─┬─╯
        ver + time     entropy, 160 bits      rs1024
```

## Fields

Bit ranges are zero-based, half-open, and most significant bit first within the
190 data bits. Words are numbered from 1.

| Field | Bits | Words | Meaning |
| --- | --- | --- | --- |
| version | `[0,8)` | 1 | `01` |
| created_at >> 10 | `[8,30)` | 1–3 | Primary creation time in units of 1024 seconds |
| entropy | `[30,190)` | 4–19 | 20-byte entropy, leading zeros preserved |
| checksum | | 20–22 | `rs1024` over words 1–19 |

The creation time is stored with 1024-second granularity: the key's creation
time is the stored field shifted left by 10 bits. `random`, `derive`, and
`encode` round the current or supplied time down to a multiple of 1024
seconds, at most 17 minutes earlier, and print the stored value. The same
entropy with a different stored time has a different OpenPGP fingerprint, so
re-encoding decoded entropy requires the stored time.

## Checksum

The checksum is `rs1024` exactly as specified by SLIP-0039, with the
customization string `gpkb`. Its symbols are the word indices.

```python
GEN = [0xe0e040, 0x1c1c080, 0x3838100, 0x7070200, 0xe0e0009,
       0x1c0c2412, 0x38086c24, 0x3090fc48, 0x21b1f890, 0x3f3f120]

def rs1024_polymod(values):
    chk = 1
    for v in values:
        b = chk >> 20
        chk = (chk & 0xfffff) << 10 ^ v
        for i in range(10):
            chk ^= GEN[i] if (b >> i) & 1 else 0
    return chk

CS = [ord(c) for c in "gpkb"]

def rs1024_create_checksum(data):          # data: the 19 data word indices
    polymod = rs1024_polymod(CS + data + [0, 0, 0]) ^ 1
    return [(polymod >> 10 * (2 - i)) & 1023 for i in range(3)]

def rs1024_verify_checksum(all_words):    # all 22 word indices
    return rs1024_polymod(CS + all_words) == 1
```

Any error affecting at most three words is detected with certainty. Four or
more wrong words, or an unrelated sequence of 22 words, pass with probability
about 2^-30. A SLIP-39 share fails this checksum because of the customization
string and its word count. The checksum is unkeyed: it detects accidental
damage, not malicious changes. [The tutorial](tutorial/reed-solomon.md)
explains on a toy example why these properties hold.

## Wordlist and encoding

The canonical wordlist is `data/slip39.txt`: exactly 1024 lowercase ASCII words,
one per line in original SLIP-39 order, each followed by LF, including the last.
Index 0 is `academic`; index 1023 is `zero`. Every word is identified by its
first four letters.

```text
SHA-256(wordlist bytes):
bcc4555340332d169718aed8bf31dd9d5248cb7da6e5d355140ef4f1e601eec3
```

Encoding: concatenate the version byte, the 22-bit stored time, and the 20
entropy bytes into 190 bits, most significant bit first. Split them into 19
consecutive 10-bit groups, append the 3 checksum symbols, and emit the word at
each index, separated by whitespace.

Decoding:

```text
 words ──► 10-bit indices ──► rs1024 verify ──ok──► unpack bits ──► version,
                                   │                                 created_at,
                                   │ fail                            secret
                                   ▼
                  try every single-word substitution (22 × 1023 or 33 × 1023)
                     ├─ exactly one valid ──► "word N is probably X"  (suggest only)
                     └─ none ──────────────► "at least two words are wrong"
```

- Accept exactly 22 known words, case-insensitive, separated by any whitespace.
  Reject numbering, punctuation, and unknown words; never autocorrect. The CLI
  strips a leading UTF-8 byte order mark.
- Verify the checksum over all 22 indices before reading any field.
- Require version `01`. The version byte fixes both the layout and the
  derivation: version 1 means this layout, `rs1024`, and the HKDF mapping
  below with its labels and no passphrase. Any change to how the words become
  a key, such as a passphrase or a different KDF, is a new version with its
  own specification. Reject other versions instead of guessing.
- On a checksum failure, trying all 1023 alternatives at each of the 22
  positions finds at most one valid sequence, because `rs1024` has minimum
  distance 4. The implementation reports that position and never applies the
  correction, since a sequence with three wrong words can be one substitution
  away from a different valid backup. If no substitution helps, at least two
  words are wrong. The fingerprint comparison remains the final check.

## Secret acquisition and creation time

- **Random:** obtain 20 bytes from the operating system cryptographic RNG.
- **Exact:** parse exactly 40 hexadecimal digits or 160 binary digits as the
  20 entropy bytes.
- **Entropy derivation:** parse at least 160 binary digits in whole bytes.
  Pack bits most significant bit first and derive 20 bytes with Argon2id. Do
  not hash the ASCII digit characters.

Exact and derivation inputs ignore only ASCII whitespace and preserve leading
zeros; hexadecimal input does not accept a `0x` prefix. Short inputs are
rejected, not zero-padded. Padding an input or running a KDF cannot create
missing entropy.

New backups store the current Unix time rounded down as described above.
`--created-at` overrides it for exact reproduction and is rounded the same way.
Timestamps must fit OpenPGP's unsigned 32-bit range.

Entropy derivation uses Argon2id version 0x13, memory cost 65536 KiB, time cost 3,
parallelism 1, and **output length 20 bytes**. There is no optional secret or
associated data. The salt is the first 16 bytes of:

```text
SHA-256(ASCII("GPG Key Backup v1 entropy"))
```

No trailing NUL is included. The fixed salt deliberately makes extraction from
high-entropy bits deterministic; this is not a password-storage scheme. Equal
inputs produce equal entropy. The original input and the Argon2 settings are
not needed to recover the already-derived entropy from the words.

## Mapping to the OpenPGP primary key

```text
entropy (20 bytes) ---- HKDF-SHA256 ----> native Ed25519 private seed
                                                   |
                                         RFC 8032 public-key derivation
                                                   |
created_at ----------------------------> v4 algorithm-22 primary-key packet
                                                   |
                                         OpenPGP v4 fingerprint
```

HKDF-SHA256 (RFC 5869):

```text
IKM  = 20-byte entropy
salt = ASCII("GPG Key Backup v1")
info = ASCII("ed25519-certification")
L    = 32 bytes

PRK = HMAC-SHA256(key=salt, message=IKM)
Ed25519_seed = HMAC-SHA256(key=PRK, message=info || 0x01)
```

These ASCII strings have no trailing NUL. Use the native private seed as
specified by RFC 8032, not an already clamped scalar. HKDF expands its length;
it does not increase its entropy. A backup provides at most 160 bits of seed
entropy; Ed25519 has about 128-bit classical security.

Create a **version 4** OpenPGP primary key with:

- Creation time exactly equal to the stored time (the 22-bit field shifted
  left by 10 bits).
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
the fingerprint. Changing the timestamp, packet version, or algorithm changes
the fingerprint.

Add the supplied UTF-8 User ID, trimmed of surrounding whitespace, and a
positive self-certification (type 0x13), hashed with SHA-256, created at export
time, with key flags 0x01 (certification only), primary-User-ID flag set, and
no signature expiry. A key expiration time subpacket (type 9) is present only
when requested. It holds the seconds from the key creation time to the expiry,
where the expiry is the requested validity added to the signing time, and must
fit in 32 bits. The signature time must not precede the key creation time;
exports reject an earlier clock. Use the current export time for the fresh
self-signature, preserving the stored creation time only in the primary-key
packet. This does not guarantee that the fresh signature becomes active when
merged with a saved certificate: equal-second timestamps, clock rollback, or
existing future-dated signatures can affect selection. Check the effective
metadata after merging. Preferred hashes are SHA-512, SHA-256; preferred
symmetric algorithms are AES-256, AES-128. The identity must be nonempty and
contain no control characters. Use an OpenPGP library to construct and sign
these packets.

The User ID is recorded separately on paper, not stored in the backup. It and
the self-signature do not affect the primary fingerprint. Recovering with a
different identity produces the same primary key in a different certificate.
Sequoia's random signature salt notation and secret-key protection mean that
repeated exports need not match byte-for-byte. Export passphrases are separate
from word recovery and are not needed to recover the secret.

The backup deliberately contains only the entropy and the creation time.
User IDs, expirations, revocations, third-party certifications, and subkey
bindings remain in the public certificate. Export creates a fresh
certification-only certificate and certifies the supplied User ID anew.
**Save and merge the original public certificate** to retain its packets,
including revocations and subkey bindings. Their presence does not guarantee
preservation of the original effective policy: a fresh certification can change
capabilities and expiry or reactivate a revoked User ID. This does not undo a
compromised-primary-key revocation. Verify effective metadata before using or
publishing the merged certificate. Private subkeys require separate backups.

## Independent vectors

`tests/vectors.txt` is tab-separated, with three lines:

1. `compact`, requested timestamp, stored timestamp, entropy hex (bytes `00`
   through `13`), the 22 words, HKDF-derived native seed hex, expected primary
   fingerprint.
2. `argon2id`, input hex (bytes `00` through `13`), 20-byte output hex.
3. `slip39`, a valid SLIP-39 share from the SLIP-0039 reference vectors, and
   the same share with a wrong final word. The `rs1024` implementation must
   accept the first with customization string `shamir`, reject the second, and
   reject the first with customization string `gpkb`.

Words, HKDF, and fingerprints were calculated independently with Python's
standard-library hash/HMAC functions and OpenSSL's Ed25519 implementation.
Argon2 was cross-checked with the system `libargon2` and OpenSSL. Tests compare
production results against these vectors and exercise recovery through GnuPG.

## Standalone secret recovery

This Python 3 program needs only the pinned wordlist and the words. It verifies
the checksum and prints the stored creation time and the **native Ed25519
private seed**. Its output is secret. Do not run with `-O`, which disables
assertions.

```python
import hashlib
import hmac
from pathlib import Path

wordlist_bytes = Path("wordlist.txt").read_bytes()
expected = "bcc4555340332d169718aed8bf31dd9d5248cb7da6e5d355140ef4f1e601eec3"
assert hashlib.sha256(wordlist_bytes).hexdigest() == expected
lookup = {word: i for i, word in enumerate(wordlist_bytes.decode("ascii").splitlines())}
tokens = Path("words.txt").read_text().lower().split()
assert len(tokens) == 22
symbols = [lookup[word] for word in tokens]

GEN = [0xe0e040, 0x1c1c080, 0x3838100, 0x7070200, 0xe0e0009,
       0x1c0c2412, 0x38086c24, 0x3090fc48, 0x21b1f890, 0x3f3f120]
chk = 1
for value in [ord(c) for c in "gpkb"] + symbols:
    b = chk >> 20
    chk = (chk & 0xfffff) << 10 ^ value
    for i in range(10):
        chk ^= GEN[i] if (b >> i) & 1 else 0
assert chk == 1, "checksum mismatch"

number = 0
for symbol in symbols[:19]:
    number = (number << 10) | symbol
assert number >> 182 == 1, "unsupported version"
created_at = ((number >> 160) & (2**22 - 1)) << 10
entropy = (number & (2**160 - 1)).to_bytes(20, "big")
prk = hmac.new(b"GPG Key Backup v1", entropy, hashlib.sha256).digest()
native_seed = hmac.new(prk, b"ed25519-certification\x01", hashlib.sha256).digest()
print("created-at:", created_at)
print("native Ed25519 seed:", native_seed.hex())
```

To reconstruct an OpenPGP key without this application, use the resulting native
seed and stored creation time to construct the packets specified above with a
compatible library. Compare the fingerprint against the paper and saved public
certificate before use.
