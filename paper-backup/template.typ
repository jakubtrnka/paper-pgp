// Shared by main.typ and the CLI's standalone `template` output.
#let backup-document(words) = {
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
  let slots(start) = grid(
    columns: (1fr, 1fr),
    column-gutter: 9mm,
    row-gutter: 3mm,
    ..range(start, start + 20).map(n => block(height: 6.5mm)[
      #text(size: 8pt, fill: luma(70))[#padded(n, 2).]
      #v(3mm)
      #line(length: 100%, stroke: 0.4pt)
    ]),
  )
  let hash = "bcc4555340332d169718aed8bf31dd9d5248cb7da6e5d355140ef4f1e601eec3"

  [
    #eyebrow[PAPER BACKUP / 256-BIT SEED]
    = OpenPGP master key
    *GPKB version 1 · 40 words · Words 01–20*

    Anyone with these words can recover your certification master secret.
    Store this paper securely. The words are unencrypted.

    #field[Owner / exact User ID]
    #field[Primary fingerprint]
    #v(1mm)
    Write one word on each line, in order. Continue on the next page.
    #v(2mm)
    #slots(1)

    #pagebreak()
    #eyebrow[PAPER BACKUP / CONTINUED]
    = Words 21–40
    Handwrite the remaining words. Leave numbers out when entering the words into recovery software.
    #v(3mm)
    #slots(21)
    #v(4mm)
    #field[Backup date / identifying note]
    #field[Location of public certificate and private subkey backups]

    *Before relying on the paper:* test a recovery and compare its primary fingerprint with the one on page 1.
    The words restore the master secret only. Private subkeys need separate backups.

    #pagebreak()
    #eyebrow[OFFLINE RECOVERY / WORDS TO SEED]
    = Decode the backup
    This is *GPKB v1*, using the SLIP-39 wordlist. It is a distinct format,
    not a SLIP-39 share or a secret-sharing scheme. No passphrase is needed to recover the seed.

    1. Look up each of the 40 words in the indexed appendix. Indices start at zero.
       Ignore word case. Do not silently correct words.
    2. Express each index as exactly 10 binary bits, most significant bit first.
       Concatenate them in word order: 400 bits in total.
    3. Regroup into 50 bytes, most significant bit first, with no padding.
       Validate every field below before using the secret.

    == Serialized bytes
    Ranges are zero-based and exclude their upper bound.
    #table(
      columns: (auto, 1fr), inset: 4pt,
      stroke: (x: none, y: 0.25pt + luma(170)),
      table.header([*Bytes*], [*Required value / meaning*]),
      [`[0,4)`], [ASCII `GPKB` (`47 50 4b 42`)],
      [`[4,5)`], [Version `01`],
      [`[5,13)`], [Wordlist hash prefix: `bc c4 55 53 40 33 2d 16`],
      [`[13,45)`], [The 32-byte backup seed; preserve leading zeros],
      [`[45,50)`], [First 5 bytes of the checksum digest],
    )

    == Checksum
    Hash the following concatenation with SHA-256:
    #raw("ASCII(\"gpg-keys/backup/v1\") || 0x00\n|| serialized_bytes[0:45]", block: true)
    The first 5 digest bytes must match bytes `[45,50)`. This detects accidental damage, not malicious modification.

    == Pinned wordlist
    SHA-256 of the lowercase ASCII words in index order, each followed by LF,
    including the final word:
    #raw(hash.slice(0, 32) + "\n" + hash.slice(32), block: true)

    #pagebreak()
    #eyebrow[OFFLINE RECOVERY / SEED TO OPENPGP]
    = Restore the master key
    The recovered backup seed is not directly the OpenPGP private key.
    Derive its Ed25519 seed using HKDF-SHA256 (RFC 5869):
    #raw("IKM  = 32-byte backup seed\nsalt = ASCII(\"gpg-keys/master/v1\")\ninfo = ASCII(\"ed25519-certification\")\nPRK  = HMAC-SHA256(key=salt, message=IKM)\nkey_seed = HMAC-SHA256(\n  key=PRK, message=info || 0x01)", block: true)
    The ASCII strings have no trailing NUL. Use the 32-byte result as an
    Ed25519 private seed (RFC 8032), not an already clamped scalar.

    == Fixed OpenPGP parameters
    Construct a version 4 primary-key packet with a compatible OpenPGP library:
    - Creation timestamp: `1767225600`, or 2026-01-01 00:00:00 UTC. Keep it fixed.
    - Legacy EdDSA algorithm 22; Ed25519 curve OID `1.3.6.1.4.1.11591.15.1`.
      OID encoding with length: `09 2b 06 01 04 01 da 47 0f 01`.
    - Public MPI: `0x40` followed by the 32-byte Ed25519 public key;
      MPI bit length 263. Secret MPI: derived seed as a big-endian integer;
      restore leading zero bytes when reading it as an Ed25519 seed.
    - Add the exact written UTF-8 User ID with a positive self-certification
      (type `0x13`), SHA-256, the same timestamp, certification-only flags
      (`0x01`), primary-User-ID flag, and no expiry.
    - Preferred hashes: SHA-512, SHA-256; symmetric algorithms: AES-256, AES-128.

    == Verify and merge
    Import the recovered certificate into GnuPG or Sequoia. Compare its primary
    fingerprint with page 1. The identity and export passphrase do not affect
    the primary fingerprint. Merge your saved public certificate to retain
    subkey bindings, later User IDs, expiration changes, and revocations.

    *Keep private subkeys separately:* the master seed cannot reconstruct them
    or decrypt messages encrypted to lost encryption subkeys. The export
    passphrase protects an exported file, not this paper.

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
