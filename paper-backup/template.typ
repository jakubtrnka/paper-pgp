// Shared by main.typ and the CLI's standalone `template` output.
#let backup-document(words, kind: "compact") = {
  assert(kind == "compact" or kind == "raw", message: "Unknown backup variant")
  let is-raw = kind == "raw"
  let count = if is-raw { 44 } else { 35 }
  let first-count = calc.ceil(count / 2)
  let payload-len = if is-raw { 32 } else { 20 }
  let body-len = 18 + payload-len
  let byte-len = body-len + 5
  assert(words.len() == 1024, message: "Expected the pinned 1024-word SLIP-39 wordlist")
  assert(words.first() == "academic" and words.last() == "zero")
  set document(title: "OpenPGP master key paper backup — GPKB v1", date: none)
  set page(
    paper: "a5",
    margin: (x: 12mm, top: 12mm, bottom: 13mm),
    footer: context {
      set text(size: 7pt, fill: luma(90))
      grid(columns: (1fr, auto), [GPKB v1 · Keep all pages together], counter(page).display("1 / 1", both: true))
    },
  )
  set text(font: "Liberation Sans", size: 9pt, lang: "en")
  set par(leading: 0.55em, spacing: 0.65em)
  set heading(numbering: none)
  show heading.where(level: 1): set text(size: 20pt, weight: "bold")
  show heading.where(level: 2): set text(size: 12pt, weight: "bold")
  show raw: set text(font: "Liberation Mono", size: 8pt)

  let eyebrow(body) = text(size: 8pt, tracking: 0.6pt, weight: "bold", body)
  let padded(number, width) = {
    let digits = str(number)
    "0" * (width - digits.len()) + digits
  }
  let field(label) = {
    text(size: 8pt, label)
    v(5mm)
    line(length: 100%, stroke: 0.4pt)
    v(1mm)
  }
  let slots(start, end) = grid(
    columns: (1fr, 1fr),
    column-gutter: 9mm,
    row-gutter: 3mm,
    ..range(start, end + 1).map(n => block(height: 6.5mm)[
      #text(size: 8pt, fill: luma(70))[#padded(n, 2).]
      #v(3mm)
      #line(length: 100%, stroke: 0.4pt)
    ]),
  )
  let hash = "bcc4555340332d169718aed8bf31dd9d5248cb7da6e5d355140ef4f1e601eec3"

  [
    #eyebrow[#if is-raw [RAW / 256-BIT PRIVATE SEED] else [COMPACT / 160-BIT ENTROPY]]
    = OpenPGP master key
    *GPKB version 1 · #count words · Words 01–#padded(first-count, 2)*

    Anyone with these words can recover your certification master secret.
    Store this paper securely. The words are unencrypted.

    #field[Owner / exact User ID]
    #field[Primary fingerprint]
    #v(1mm)
    Write one word on each line, in order. Continue on the next page.
    #v(2mm)
    #slots(1, first-count)

    #pagebreak()
    #eyebrow[PAPER BACKUP / CONTINUED]
    = Words #padded(first-count + 1, 2)–#padded(count, 2)
    Handwrite the remaining words. Leave numbers out when entering the words into recovery software.
    #v(3mm)
    #slots(first-count + 1, count)
    #v(4mm)
    #field[Backup date / identifying note]
    #field[Location of public certificate and private subkey backups]

    *Before relying on the paper:* test a recovery and compare its primary fingerprint with page 1.
    The words restore the master secret only. Private subkeys need separate backups.

    #pagebreak()
    #eyebrow[OFFLINE RECOVERY / WORDS TO BACKUP]
    = Decode the backup
    This is *GPKB v1*, using the SLIP-39 wordlist. It is a distinct format,
    not a SLIP-39 share. No passphrase is needed to recover the stored secret.

    1. Look up each of the #count words in the indexed appendix. Indices start at zero.
       Ignore word case. Do not silently correct words.
    2. Express each index as exactly 10 binary bits, most significant bit first.
       Concatenate them in word order: #(count * 10) bits in total.
    3. #if is-raw [There are no padding bits.] else [Check that the final 6 bits are zero and remove them.]
       Regroup into #byte-len bytes, most significant bit first. Validate all fields below.

    == Serialized bytes
    Ranges are zero-based and exclude their upper bound.
    #table(
      columns: (auto, 1fr), inset: 3pt,
      stroke: (x: none, y: 0.25pt + luma(170)),
      table.header([*Bytes*], [*Required value / meaning*]),
      [`[0,4)`], [ASCII `GPKB` (`47 50 4b 42`)],
      [`[4,5)`], [Version `01`],
      [`[5,13)`], [Wordlist hash prefix: `bc c4 55 53 40 33 2d 16`],
      [`[13,17)`], [Creation timestamp: unsigned big-endian Unix seconds],
      [`[17,18)`], [#if is-raw [Tag `00`: Raw] else [Tag `01`: CompactEntropy]],
      [#raw("[18," + str(body-len) + ")")], [#payload-len bytes of secret payload; preserve leading zeros],
      [#raw("[" + str(body-len) + "," + str(byte-len) + ")")], [First 5 bytes of the checksum digest],
    )
    Reject unknown tags, incorrect lengths, or a tag inconsistent with the word count.
    A compact backup has 35 words; a raw backup has 44 words. The encoded tag determines recovery.

    == Checksum
    Hash the following concatenation with SHA-256:
    #raw("ASCII(\"gpg-keys/backup/v1\") || 0x00\n|| serialized_bytes[0:" + str(body-len) + "]", block: true)
    The first 5 digest bytes must match the final 5 serialized bytes.
    This covers the marker, timestamp, tag, and payload. Padding is checked separately.

    == Pinned wordlist
    SHA-256 of lowercase ASCII words in index order, each followed by LF, including the last:
    #raw(hash.slice(0, 32) + "\n" + hash.slice(32), block: true)

    #pagebreak()
    #eyebrow[OFFLINE RECOVERY / BACKUP TO OPENPGP]
    = Restore the master key
    #if is-raw [
      *Raw:* use the stored 32-byte payload directly as the native Ed25519 private seed.
      *Do not apply HKDF.* This preserves the imported private key.
    ] else [
      *CompactEntropy:* derive 32 bytes with HKDF-SHA256 (RFC 5869):
      #raw("IKM  = stored 20-byte entropy\nsalt = ASCII(\"gpg-keys/master/v1\")\ninfo = ASCII(\"ed25519-certification\")\nPRK  = HMAC-SHA256(key=salt, message=IKM)\nkey_seed = HMAC-SHA256(\n  key=PRK, message=info || 0x01)", block: true)
      The ASCII strings have no trailing NUL. The output is the native Ed25519 private seed.
    ]
    Use the seed as specified by RFC 8032, not an already clamped scalar.

    == OpenPGP parameters
    Construct a version 4 primary-key packet with a compatible OpenPGP library:
    - Creation timestamp: read bytes `[13,17)` as an unsigned big-endian integer
      (`BE32`); seconds since 1970-01-01 00:00:00 UTC. *Reuse this stored time.*
    - Legacy EdDSA algorithm 22; Ed25519 curve OID `1.3.6.1.4.1.11591.15.1`.
      OID encoding with length: `09 2b 06 01 04 01 da 47 0f 01`.
    - Public MPI: `0x40` followed by the 32-byte Ed25519 public key; bit length 263.
      Secret MPI: native seed as a big-endian integer; restore its leading zero bytes.
    - Self-certify the written UTF-8 User ID: positive certification (`0x13`), SHA-256,
      the stored timestamp, certification-only flags (`0x01`), primary User ID, no expiry.
      Preferences: SHA-512, SHA-256; AES-256, AES-128.

    == Fingerprint and certificate
    The version 4 fingerprint is SHA-1 of `0x99`, the 2-byte big-endian length of
    the public-key packet body, then that body (including the timestamp).
    Compare it with page 1. User IDs and export passphrases do not affect it.

    Import into GnuPG or Sequoia and merge the saved public certificate to retain
    subkey bindings, original capabilities, later identities, expiration updates,
    and revocations. Recovering the master does not recreate the full original certificate.

    *Back up private subkeys separately:* the master cannot recreate them or decrypt
    messages encrypted to lost subkeys. The checksum detects damage, not malicious changes.

    #pagebreak()
    #for start-index in range(0, 1024, step: 192) {
      if start-index > 0 { pagebreak() }
      let end-index = calc.min(start-index + 192, 1024)
      eyebrow[WORDLIST / ZERO-BASED INDICES]
      heading(level: 1)[#padded(start-index, 4)–#padded(end-index - 1, 4)]
      if start-index == 0 {
        text(size: 7pt)[
          Unmodified SLIP-0039 wordlist by SatoshiLabs / SLIP contributors.
          #link("https://github.com/satoshilabs/slips/blob/master/slip-0039/wordlist.txt")[Source wordlist]
          · #link("https://creativecommons.org/licenses/by-sa/4.0/")[CC BY-SA 4.0]
          · Provided without warranty.
        ]
        v(2mm)
      }
      grid(
        columns: (1fr, 1fr, 1fr, 1fr),
        column-gutter: 3mm,
        row-gutter: 1mm,
        ..range(start-index, end-index).map(index => text(font: "Liberation Mono", size: 8pt)[
          #padded(index, 4) #words.at(index)
        ]),
      )
    }
  ]
}
