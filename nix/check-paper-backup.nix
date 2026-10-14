{
  runCommand,
  typst,
  liberation_ttf,
  poppler-utils,
  python3,
  gpg-keys,
  paper-backup,
}:
runCommand "check-paper-backup"
  {
    nativeBuildInputs = [
      typst
      poppler-utils
      python3
    ];
    SOURCE_DATE_EPOCH = "1767225600";
  }
  ''
    # Prove the CLI export is standalone and agrees with the repo's document.
    ${gpg-keys}/bin/gpg-keys template --output standalone.typ
    typst compile --ignore-system-fonts \
      --font-path ${liberation_ttf}/share/fonts standalone.typ standalone.pdf
    python ${./check-paper-backup.py} \
      ${paper-backup}/paper-backup.pdf \
      ${../data/slip39.txt} ${../src/backup.rs} ${../src/master.rs}
    python ${./check-paper-backup.py} \
      standalone.pdf \
      ${../data/slip39.txt} ${../src/backup.rs} ${../src/master.rs}
    pdftotext -layout ${paper-backup}/paper-backup.pdf reference.txt
    pdftotext -layout standalone.pdf standalone.txt
    cmp reference.txt standalone.txt
    touch "$out"
  ''
