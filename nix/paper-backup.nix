{
  lib,
  stdenvNoCC,
  typst,
  liberation_ttf,
}:
stdenvNoCC.mkDerivation {
  pname = "gpg-keys-paper-backup";
  version = "1";

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../paper-backup/main.typ
      ../paper-backup/template.typ
      ../data/slip39.txt
    ];
  };

  nativeBuildInputs = [ typst ];
  dontConfigure = true;
  # Pin the fonts and PDF date as well as the compiler via flake.lock.
  SOURCE_DATE_EPOCH = "1767225600";

  buildPhase = ''
    runHook preBuild
    typst compile --root . --ignore-system-fonts \
      --font-path ${liberation_ttf}/share/fonts \
      paper-backup/main.typ paper-backup.pdf
    typst compile --root . --ignore-system-fonts \
      --font-path ${liberation_ttf}/share/fonts --input kind=raw \
      paper-backup/main.typ paper-backup-raw.pdf
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    install -Dm644 paper-backup.pdf "$out/paper-backup.pdf"
    install -Dm644 paper-backup-raw.pdf "$out/paper-backup-raw.pdf"
    runHook postInstall
  '';

  meta = {
    description = "A5 paper backup with recovery instructions and the full SLIP-39 wordlist";
    platforms = lib.platforms.all;
  };
}
