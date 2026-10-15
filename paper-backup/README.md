# A5 paper-backup document

`main.typ` reads `../data/slip39.txt` and passes it to the layout in
`template.typ`. The Rust CLI embeds that same layout and appends the wordlist
when exporting a standalone `.typ` file. No Typst Universe packages or network
access are needed to compile the document once Nix dependencies are fetched.

Build the reproducible PDF from the repository root:

```sh
nix build .#paper-backup --out-link result-paper-backup
# result-paper-backup/paper-backup.pdf       (compact: 35 words)
# result-paper-backup/paper-backup-raw.pdf   (raw: 44 words)
```

Each PDF has ten A5 pages (148 × 210 mm): two handwriting pages, two pages of
recovery instructions, and six pages of the full wordlist. The compact template
has 18 + 17 slots; the raw template has 22 + 22. Use the template matching the
backup variant; the encoded tag is authoritative during recovery.
Print at 100% / actual size. Retain all pages with the handwritten backup.
The template itself contains no secret words.

For a convenient local copy (ignored by Git):

```sh
cp result-paper-backup/paper-backup.pdf paper-backup/paper-backup.pdf
cp result-paper-backup/paper-backup-raw.pdf paper-backup/paper-backup-raw.pdf
```

For editing or watching the source, use the pinned tools and Liberation fonts:

```sh
nix develop
typst compile --root . --ignore-system-fonts paper-backup/main.typ paper-backup/paper-backup.pdf
typst compile --root . --ignore-system-fonts --input kind=raw paper-backup/main.typ paper-backup/paper-backup-raw.pdf
typst watch --root . --ignore-system-fonts paper-backup/main.typ paper-backup/paper-backup.pdf
```

Run these from the repository root. The `--root .` is required because the
wordlist is outside the `paper-backup/` directory. The Nix build also ignores
system fonts and pins PDF metadata, so it does not depend on fonts installed
on the host. The development shell supplies the same fonts via Typst's wrapper.

The standalone CLI export can be compiled from any directory:

```sh
nix run . -- template --output /tmp/backup.typ
nix develop --command typst compile --ignore-system-fonts /tmp/backup.typ /tmp/backup.pdf
nix run . -- template --kind raw --output /tmp/backup-raw.typ
nix develop --command typst compile --ignore-system-fonts /tmp/backup-raw.typ /tmp/backup-raw.pdf
```

`nix flake check` compiles repository and standalone sources for both variants
and verifies A5 dimensions on every page, all 35 or 44 handwriting slots,
every indexed word, printed scheme parameters,
and matching extracted text. It also builds and tests the Rust application.

The words recover the primary secret and its creation timestamp; they do not
recover private subkeys. The compact instructions specify HKDF expansion of
20-byte entropy; the raw instructions use the 32-byte native seed directly.
Both specify OpenPGP recovery and the separate backups needed for subkeys and
public certificate updates. Full details are in [FORMAT.md](../FORMAT.md).

The unmodified wordlist is attributed in the PDF and remains under CC BY-SA
4.0; see `../data/LICENSE.slip39`.
