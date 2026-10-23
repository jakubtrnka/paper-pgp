// Shared by main.typ and the CLI's standalone `template` output.
#let backup-document(words) = {
  let count = 22
  let first-count = 11
  assert(words.len() == 1024, message: "Expected the pinned 1024-word SLIP-39 wordlist")
  assert(words.first() == "academic" and words.last() == "zero")
  set document(title: "OpenPGP master key paper backup — GPG Key Backup v1", date: none)
  set page(
    paper: "a5",
    margin: (x: 12mm, top: 12mm, bottom: 13mm),
    footer: context {
      set text(size: 7pt, fill: luma(90))
      grid(columns: (1fr, auto), [GPG Key Backup v1 · Keep all pages together], counter(page).display("1 / 1", both: true))
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
    #eyebrow[160-BIT ENTROPY / 22 WORDS]
    = OpenPGP master key
    *GPG Key Backup, version 1 · #count words · Words 01–#padded(first-count, 2)*

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
    This is a *GPG Key Backup* (GPKB), version 1, using the SLIP-39 wordlist and checksum.
    It is a distinct format, not a SLIP-39 share. No passphrase is needed to recover the stored secret.

    1. Look up each of the #count words in the indexed appendix. Indices start at zero.
       Ignore word case. Do not silently correct words.
    2. Verify the checksum (`rs1024` from SLIP-0039). Feed the ASCII codes of `gpkb`
       (103 112 107 98) and then all #count indices, in order, into this function.
       The result must be 1. Any error in up to three words is detected. If it fails,
       trying every alternative word at each position finds a single wrong word.
    #raw("GEN = [0xe0e040, 0x1c1c080, 0x3838100, 0x7070200, 0xe0e0009,\n       0x1c0c2412, 0x38086c24, 0x3090fc48, 0x21b1f890, 0x3f3f120]\nchk = 1\nfor value in values:\n    b = chk >> 20\n    chk = (chk & 0xfffff) << 10 ^ value\n    for i in range(10):\n        chk ^= GEN[i] if (b >> i) & 1 else 0", block: true)
    3. Express each of the first 19 indices as exactly 10 binary bits, most significant
       bit first. Concatenate them in word order: 190 bits. Read the fields below.

    == Bit fields
    Ranges are zero-based and exclude their upper bound.
    #table(
      columns: (auto, 1fr), inset: 3pt,
      stroke: (x: none, y: 0.25pt + luma(170)),
      table.header([*Bits*], [*Required value / meaning*]),
      [`[0,8)`], [Version `01`],
      [`[8,30)`], [Creation time divided by 1024: unsigned big-endian integer],
      [`[30,190)`], [160 bits of entropy (20 bytes); preserve leading zeros],
    )
    Reject a different word count, a failed checksum, or another version.

    == Pinned wordlist
    SHA-256 of lowercase ASCII words in index order, each followed by LF, including the last:
    #raw(hash.slice(0, 32) + "\n" + hash.slice(32), block: true)

    #pagebreak()
    #eyebrow[OFFLINE RECOVERY / BACKUP TO OPENPGP]
    = Restore the master key
    *Entropy to seed:* derive 32 bytes with HKDF-SHA256 (RFC 5869):
    #raw("IKM  = stored 20-byte entropy\nsalt = ASCII(\"GPG Key Backup v1\")\ninfo = ASCII(\"ed25519-certification\")\nPRK  = HMAC-SHA256(key=salt, message=IKM)\nkey_seed = HMAC-SHA256(\n  key=PRK, message=info || 0x01)", block: true)
    The ASCII strings have no trailing NUL. The output is the native Ed25519 private seed.
    Use the seed as specified by RFC 8032, not an already clamped scalar.

    == OpenPGP parameters
    Construct a version 4 primary-key packet with a compatible OpenPGP library:
    - Creation timestamp: the 22-bit field from bits `[8,30)` multiplied by 1024
      (shifted left by 10 bits); seconds since 1970-01-01 00:00:00 UTC. *Reuse this stored time.*
    - Legacy EdDSA algorithm 22; Ed25519 curve OID `1.3.6.1.4.1.11591.15.1`.
      OID encoding with length: `09 2b 06 01 04 01 da 47 0f 01`.
    - Public MPI: `0x40` followed by the 32-byte Ed25519 public key; bit length 263.
      Secret MPI: native seed as a big-endian integer; restore its leading zero bytes.
    - Self-certify the written UTF-8 User ID: positive certification (`0x13`), SHA-256,
      current export time, certification-only flags (`0x01`), primary User ID, no expiry.
      Preferences: SHA-512, SHA-256; AES-256, AES-128.

    == Fingerprint and certificate
    The version 4 fingerprint is SHA-1 of `0x99`, the 2-byte big-endian length of
    the public-key packet body, then that body (including the timestamp).
    Compare it with page 1. User IDs and export passphrases do not affect it.

    Prefer restoring the secret into the saved public certificate: it signs nothing,
    so identities, subkeys, expiry, and revocations stay as saved. Without it,
    recovery certifies the written User ID anew; merging a saved certificate later
    keeps its packets, but fresh signatures can reactivate retired User IDs or replace earlier settings.

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
