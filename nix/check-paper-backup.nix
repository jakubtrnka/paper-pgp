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
    # Compile both standalone CLI variants and compare them with the repo builds.
    for kind in compact raw; do
      if [ "$kind" = raw ]; then
        reference=${paper-backup}/paper-backup-raw.pdf
      else
        reference=${paper-backup}/paper-backup.pdf
      fi
      ${gpg-keys}/bin/gpg-keys template --kind "$kind" --output "$kind.typ"
      typst compile --ignore-system-fonts \
        --font-path ${liberation_ttf}/share/fonts "$kind.typ" "$kind.pdf"
      python ${./check-paper-backup.py} \
        "$reference" ${../data/slip39.txt} ${../src/backup.rs} ${../src/master.rs} "$kind"
      python ${./check-paper-backup.py} \
        "$kind.pdf" ${../data/slip39.txt} ${../src/backup.rs} ${../src/master.rs} "$kind"
      pdftotext -layout "$reference" reference.txt
      pdftotext -layout "$kind.pdf" standalone.txt
      cmp reference.txt standalone.txt
    done
    touch "$out"
  ''
