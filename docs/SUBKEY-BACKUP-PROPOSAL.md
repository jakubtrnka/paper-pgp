# Deterministic subkey backup proposal

Status: Draft design for exploration. The layouts and derivation labels below
are candidates, not a stable format specification.

Extend the paper backup with independently recorded subkey descriptors. The
existing root secret would derive both the primary key and separate subkey
secrets. Each descriptor would preserve the information needed to reproduce
one subkey with its original OpenPGP fingerprint.

This is a promising extension of the current design. It addresses the main
gap in primary-only recovery: replacing a lost encryption subkey does not
restore access to messages encrypted to that subkey. Signing and
authentication subkeys can use the same mechanism, although replacing those
keys is often sufficient.

The proposal applies to subkeys generated through this scheme. It cannot
retroactively recover independently generated GnuPG subkeys. Public
certificate history would still need a separate backup.

## Derivation from the existing root

Preserve the primary derivation defined in [FORMAT.md](FORMAT.md). Derive
subkeys as separate outputs from the same HKDF pseudorandom key:

```text
PRK = HMAC-SHA256(
    key = ASCII("GPG Key Backup v1"),
    message = stored 20-byte entropy
)

info = ASCII("gpkb-subkey-v1")
       || primary_fingerprint
       || encoded_subkey_descriptor

material = HKDF-Expand(PRK, info, 32)
         = HMAC-SHA256(key = PRK, message = info || 0x01)
```

The final expression is the standard single-block HKDF expansion from
[RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html#section-2.3).
The label separates subkey derivation from the existing primary derivation.
The parent fingerprint explicitly associates derivation with the primary's
identity, including its creation time. Including the descriptor's timestamp
also separates otherwise identical descriptors created at different stored
times.

The final specification must fix the exact byte encoding, field widths, and
domain labels. For the current v4 primary, the fingerprint is 20 raw bytes;
the candidate descriptor below occupies five bytes. Human-readable strings
must not introduce ambiguous concatenations.

Derive from `PRK`, not from the exported Ed25519 primary seed. The exported
primary secret should not become a means of deriving encryption subkeys.

## Profiles and purposes

Use an immutable profile ID that defines the purpose, algorithm, OpenPGP
packet version, key encoding, and any encryption KDF parameters. Those
choices must remain reproducible even if library defaults change.

Initial profiles would cover:

| Purpose | Key material |
| --- | --- |
| Signing `[S]` | A separately derived Ed25519 seed |
| Authentication `[A]` | A separately derived Ed25519 seed |
| Encryption `[E]` | A separately derived X25519 private value |

Ed25519 handles signatures; encryption requires its own algorithm and
encoding. Legacy Curve25519 ECDH and the newer X25519 OpenPGP algorithm have
different packet representations. The initial encryption profile must make
that choice explicitly. See the
[OpenPGP algorithm registry](https://www.rfc-editor.org/rfc/rfc9580.html#section-9.1).

A combined signing/authentication profile could be added deliberately.
Arbitrary purpose combinations involving encryption do not work with these
algorithms. If purposes are represented as a bitmask, values `0`, `1`, and
`2` should denote bit positions, yielding masks `1`, `2`, and `4`.

The derivation profile is permanent. Recovery must not infer it solely from
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

Reuse the primary backup's 1024-second granularity: round the time down
before creating the subkey, put that rounded value into its original key
packet, and reproduce it exactly during recovery. Trimming the timestamp of
an already published key during backup would change its identity.

This preserves the existing unsigned 32-bit OpenPGP timestamp range while
storing only 22 bits per timestamp.

## Candidate extension format

Keep the existing primary record and append a fixed-size row for each subkey:

```text
primary:     19 data words + 3 checksum words
extension:    4 data words + 3 checksum words
extension:    4 data words + 3 checksum words
...
```

One possible descriptor uses all 40 bits without padding:

| Field | Bits | Meaning |
| --- | ---: | --- |
| Profile ID | 8 | Immutable derivation and key representation profile |
| Rotation index | 10 | Index from 0 through 1023 within the profile |
| Creation time shifted right by 10 | 22 | Creation time in units of 1024 seconds |
| **Descriptor total** | **40** | **4 words** |
| RS1024 checksum | 30 | 3 additional words |

Each extension therefore occupies seven words. The complete backup contains
`22 + 7n` words for `n` recorded subkeys: 29 words with one encryption subkey,
or 43 words with one subkey for each of E, A, and S.

The originally suggested six-bit index is workable but permits only 64
generations per purpose. Ten bits provide 1024 per profile. Indices must not
wrap or be silently reused. The format supports repeated independent rows
within its finite profile and index space.

## Checksums and missing records

Compute each extension's RS1024 checksum over the primary's 19 data symbols
followed by that extension's four data symbols, using a specified extension
customization string. The original primary checksum remains unchanged, and
adding a row does not require rewriting previous rows.

Do not include the primary's three checksum words in the prefix. Processing
a complete valid RS1024 record reaches a fixed checksum state; using that
record as the prefix would cancel the dependence on the primary's contents.
This remains a problem even if the extension uses a different customization
string. Using the 190-bit primary body avoids it.

The checksum detects transcription errors and accidental association with
the wrong primary. It provides no cryptographic authentication. Recovery
should validate the primary first, then validate each extension against it.

Independent rows cannot prove that the set is complete. Losing an entire
row leaves the remaining records valid. Every historical encryption row
must be retained, including rows for expired or revoked subkeys. A separate
inventory or saved public certificate can help identify missing records.
Adding a global manifest could detect omissions, but would require updates
when subkeys are added; whether that tradeoff is worthwhile remains open.

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

Index allocation also needs a recovery policy: an old snapshot may not know
the latest index. Restoring an old snapshot must not silently reuse a prior
allocation. Including creation time in derivation helps distinguish keys
created at different stored times, but does not replace allocation tracking.

## Recovery and certificate history

Extend the existing `--certificate` recovery behavior to reconstruct each
requested subkey, verify its public packet against the saved certificate,
and insert the corresponding secret without issuing new signatures. Preserve
the saved bindings, expiry, revocations, and identities.

Recover historical encryption secrets for decryption without automatically
making those subkeys active recipients for new messages. A descriptor
identifies a recoverable key; it does not describe its current status.

Without a saved public certificate, the program can reconstruct the keys
and create fresh bindings, but cannot infer historical expiry or revocations.
Signing subkeys require the appropriate embedded primary-key binding
signature. See the
[OpenPGP subkey binding requirements](https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.1.8).

This extends secret-key recovery while retaining the need to back up the
public certificate. It does not reproduce the complete certificate history
from the words alone.

## Decisions before implementation

- Fix the initial profile IDs, packet encodings, encryption parameters, and
  conversion of derived bytes into algorithm-specific private material.
- Specify the derivation context and descriptor serialization exactly,
  including whether to adopt both parent fingerprint and timestamp inputs.
- Define extension versioning, framing, customization, and rejection of
  unsupported profiles without changing the existing primary derivation.
- Decide how to report duplicate or conflicting records and allocate indices
  after recovery from an older backup.
- Decide whether an inventory or manifest is needed to detect missing rows.
- Define fresh recovery behavior so that recovered historical secrets are
  not silently presented as currently authorized keys.

## Initial validation

Start with the encryption profile because it addresses the most consequential
recovery gap. The first prototype should generate a subkey, encrypt a message,
remove the original subkey secret, recover it from the primary words and one
extension, and decrypt the message with an independent implementation.

Require exact fingerprint reproduction and fixed derivation vectors. Extend
the exercise across several rotations, recovering all historical encryption
keys while preserving saved expiry and revocations. Check transcription
errors, wrong-parent rows, unsupported profiles, duplicate records, timestamp
boundaries, and index exhaustion. Include a regression check that extension
checksums depend on the primary data rather than a complete primary codeword.

Document missing-row behavior explicitly: a valid partial backup must not be
reported as proof that every historical subkey has been recovered.
