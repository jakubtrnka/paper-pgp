# Deterministic subkey backup proposal

Status: Draft design for exploration. The layouts and derivation labels below
are candidates, not a stable format specification.

Extend the paper backup with one independently recorded descriptor per
generation of subkeys. Each generation contains three distinct keys for
signing `[S]`, authentication `[A]`, and encryption `[E]`, sharing a suite,
generation index, creation time, and checksum. The existing root secret would
derive the primary key and each subkey's separate secret. A descriptor would
preserve the information needed to reproduce all three original fingerprints.

This is a promising extension of the current design. It addresses the main
gap in primary-only recovery: replacing a lost encryption subkey does not
restore access to messages encrypted to that subkey. Signing and
authentication subkeys can use the same mechanism, although replacing those
keys is often sufficient.

The proposal applies to subkeys generated through this scheme. It cannot
retroactively recover independently generated GnuPG subkeys. Public
certificate history would still need a separate backup.

## Intended lifecycle

Generate the primary and an initial generation of subkeys, record the paper
backup, and import the subkey secrets into a hardware token. Stable keys with
occasional replacements are the expected workflow; a generation index does
not imply scheduled rotation.

A failed token that remains under the owner's control can be replaced by
restoring the same generation. When a token is lost or stolen and the owner
chooses to retire its credentials, generate a new set under the same primary
and append one backup row. Retain earlier rows for historical decryption.

Generating a set together is a tool policy. OpenPGP still treats its members
as distinct keys with independent bindings, expiry, and revocation. The
backup grouping does not require all three to remain active together.

## Derivation from the existing root

Preserve the primary derivation defined in [FORMAT.md](FORMAT.md). Derive
subkeys as separate outputs from the same HKDF pseudorandom key:

```text
PRK = HMAC-SHA256(
    key = ASCII("GPG Key Backup v1"),
    message = stored 20-byte entropy
)

context = ASCII("gpkb-subkey-set-v1")
          || primary_fingerprint
          || encoded_generation_descriptor

S = HKDF-Expand(PRK, context || ASCII("S"), 32)
A = HKDF-Expand(PRK, context || ASCII("A"), 32)
E = HKDF-Expand(PRK, context || ASCII("E"), 32)

HKDF-Expand(PRK, info, 32)
    = HMAC-SHA256(key = PRK, message = info || 0x01)
```

The final expression is the standard single-block HKDF expansion from
[RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html#section-2.3).
The domain label separates subkey derivation from the existing primary
derivation, and the role suffix separates the three subkey secrets.
The parent fingerprint explicitly associates derivation with the primary's
identity, including its creation time. Including the descriptor's timestamp
also separates otherwise identical descriptors created at different stored
times.

The final specification must fix the exact byte encoding, field widths, and
domain labels. For the current v4 primary, the fingerprint is 20 raw bytes.
The 30-bit descriptor candidate below needs specified padding when passed
to the byte-oriented KDF, such as two leading zero bits in four bytes; its
word representation still contains exactly 30 data bits. The 40-bit
alternative fits five bytes. Human-readable strings must not introduce
ambiguous concatenations.

Derive from `PRK`, not from the exported Ed25519 primary seed. The exported
primary secret should not become a means of deriving encryption subkeys.

## Suites and purposes

Use an immutable suite ID that defines the algorithm, OpenPGP packet
version, key encoding, and any encryption KDF parameters for each of the
three roles. Those choices must remain reproducible even if library defaults
change. The suite implies all three roles, so the descriptor needs no
per-subkey purpose fields.

The initial suite would contain:

| Purpose | Key material |
| --- | --- |
| Signing `[S]` | A separately derived Ed25519 seed |
| Authentication `[A]` | A separately derived Ed25519 seed |
| Encryption `[E]` | A separately derived X25519 private value |

Ed25519 handles signatures; encryption requires its own algorithm and
encoding. Legacy Curve25519 ECDH and the newer X25519 OpenPGP algorithm have
different packet representations. The initial suite must make that choice
explicitly for its encryption member. See the
[OpenPGP algorithm registry](https://www.rfc-editor.org/rfc/rfc9580.html#section-9.1).

The three members have independently derived private material. Grouping them
in one backup row does not create a single key with combined capabilities.

The derivation suite is permanent. Recovery must not infer it solely from
the current certificate's usage flags, which can change through new binding
signatures.

## Creation time and exact identity

Preserve each subkey's creation time. Its fingerprint depends on the time,
packet version, algorithm, and algorithm-specific public fields. Recreating
the same mathematical key with a different timestamp produces a different
OpenPGP identity. See the
[v4 fingerprint definition](https://www.rfc-editor.org/rfc/rfc9580.html#section-5.5.4.2).

For legacy ECDH, the recipient fingerprint also participates in deriving the
key that wraps the message's session key. A changed timestamp can therefore
prevent decryption even when the private scalar is correct. See
[RFC 6637 section 8](https://www.rfc-editor.org/rfc/rfc6637.html#section-8).

Reuse the primary backup's 1024-second granularity: choose and round the
generation's time once, before creating its members. Put that same rounded
value into all three original subkey packets and reproduce it exactly during
recovery. Do not independently sample the clock for each member. Trimming or
unifying timestamps of already published keys during backup would change
their identities.

This preserves the existing unsigned 32-bit OpenPGP timestamp range while
storing one 22-bit timestamp per generation.

## Candidate extension format

Keep the existing primary record and append one fixed-size row for each
generation. A compact candidate uses six words per row:

```text
primary:     19 data words + 3 checksum words
generation:   3 data words + 3 checksum words
generation:   3 data words + 3 checksum words
...
```

Its descriptor uses all 30 bits without padding in the word representation:

| Field | Bits | Meaning |
| --- | ---: | --- |
| Suite ID | 2 | Immutable algorithms and encodings for S, A, and E |
| Generation index | 6 | Index from 0 through 63 under the primary |
| Creation time shifted right by 10 | 22 | Shared creation time in units of 1024 seconds |
| **Descriptor total** | **30** | **3 words** |
| RS1024 checksum | 30 | 3 additional words |

This gives four suite IDs and 64 generations: the initial set plus 63
replacements. The complete backup contains `22 + 6n` words for `n` recorded
generations, each restoring three subkeys. The primary and initial trio
therefore require 28 words, with six more words for each replacement set.

A larger alternative uses an eight-bit suite ID, ten-bit generation index,
and the same 22-bit timestamp. Its 40 data bits occupy four words, giving
seven words per generation including the checksum. It offers 256 suite IDs
and 1024 generations; the initial complete backup is 29 words. Both candidates
avoid repeating timestamps and checksums for individual members.

Choose the final size alongside extension versioning and suite allocation.
Do not guess the layout during recovery. Generation indices must not wrap
or be silently reused, including when changing suites. The generation index
is recorded explicitly and does not depend on a row's position on paper.

## Checksums and missing records

Compute each extension's RS1024 checksum over the primary's 19 data symbols
followed by that generation's three data symbols, or four for the larger
candidate, using a specified extension customization string. A single
checksum covers the shared recipe for all three keys. The original primary
checksum remains unchanged, and adding a generation does not require
rewriting previous rows.

Do not include the primary's three checksum words in the prefix. Processing
a complete valid RS1024 record reaches a fixed checksum state; using that
record as the prefix would cancel the dependence on the primary's contents.
This remains a problem even if the extension uses a different customization
string. Using the 190-bit primary body avoids it.

The checksum detects transcription errors and accidental association with
the wrong primary. It provides no cryptographic authentication. Recovery
should validate the primary first, then validate each extension against it.

Independent rows cannot prove that the set is complete. Losing an entire
row leaves the remaining records valid. Retain every generation row needed
for historical decryption, including generations whose encryption member
has expired or been revoked. Loss of one row affects the recovery information
for all three members. A separate inventory or saved public certificate can
help identify missing records. Adding a global manifest could detect
omissions, but would require updates when generations are added; whether
that tradeoff is worthwhile remains open.

## Security and rotation

Under the usual HKDF assumptions, exposure of one derived subkey should not
reveal the root or sibling secrets. The root's entropy remains the existing
160 bits; deriving more keys does not create more root entropy.

Possession of an exported primary private key does not itself reveal the
root or derived encryption secrets. Compromise of that primary still permits
unauthorized certifications and subkey bindings.

Possession of the paper root enables derivation of all past and future
subkeys given their descriptors. Those descriptors must not be treated as
an additional secret factor. Advancing the index cannot restore security
after root compromise; that requires a new root.

Rotation remains useful after compromise of an individual subkey. However,
deleting an old encryption secret does not make it irrecoverable while the
root and descriptor survive. That recoverability is the purpose of this
backup mechanism.

Generation index allocation also needs a recovery policy: an old snapshot
may not know the latest index. Restoring an old snapshot must not silently
reuse a prior allocation. Including creation time in derivation helps
distinguish generations created at different stored times, but does not
replace allocation tracking.

## Recovery and certificate history

Extend the existing `--certificate` recovery behavior to derive the three
members of each supplied generation, verify each requested member's public
packet against the saved certificate, and insert the corresponding secret
without issuing new signatures. Allow selection of individual members, such
as an old encryption key, without activating the rest of its generation.
Report missing or mismatching public packets rather than silently creating
new bindings. Preserve the saved bindings, expiry, revocations, and identities.

Recover historical encryption secrets for decryption without automatically
making those subkeys active recipients for new messages. A descriptor
identifies three recoverable keys; it does not describe their current status.

Without a saved public certificate, the program can reconstruct the keys
and create fresh bindings, but cannot infer historical expiry or revocations.
Signing subkeys require the appropriate embedded primary-key binding
signature. See the
[OpenPGP subkey binding requirements](https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.1.8).

This extends secret-key recovery while retaining the need to back up the
public certificate. It does not reproduce the complete certificate history
from the words alone.

## Decisions before implementation

- Choose the six-word or seven-word generation format and allocate suite IDs
  with room for versioning and future algorithms.
- Fix the initial suite's packet encodings, encryption parameters, and
  conversion of each role's derived bytes into private material.
- Specify the derivation context, role labels, and descriptor serialization
  exactly, including byte padding for the 30-bit candidate and whether to
  adopt both parent fingerprint and timestamp inputs.
- Define extension versioning, framing, customization, and rejection of
  unsupported suites without changing the existing primary derivation.
- Decide how to report duplicate or conflicting generation records and
  allocate indices after recovery from an older backup.
- Decide whether an inventory or manifest is needed to detect missing rows.
- Define fresh recovery behavior so that recovered historical secrets are
  not silently presented as currently authorized keys.

## Initial validation

Start by validating a complete generation, focusing on historical decryption.
The first prototype should generate S, A, and E with the same stored creation
time, encrypt a message to E, remove the original subkey secrets, recover all
three from the primary words and one extension, and decrypt the message with
an independent implementation.

Require exact fingerprint reproduction and fixed derivation vectors for each
role, including checks that the role contexts produce distinct secrets.
Extend the exercise across several generations, recovering historical
encryption keys while preserving each member's saved expiry and revocations.
Exercise recovery of E alone and revocation of one member independently of
its siblings. Check transcription errors, wrong-parent rows, unsupported
suites, duplicate records, shared timestamp boundaries, and index exhaustion.
Include a regression check that extension checksums depend on the primary
data rather than a complete primary codeword.

Document missing-row behavior explicitly: a valid partial backup must not be
reported as proof that every historical subkey has been recovered.
