{
  lib,
  rustPlatform,
  pkg-config,
  openssl,
}:
let
  manifest = builtins.fromTOML (builtins.readFile ../Cargo.toml);
in
rustPlatform.buildRustPackage {
  pname = manifest.package.name;
  version = manifest.package.version;

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../Cargo.toml
      ../Cargo.lock
      ../LICENSE
      ../src
      ../tests
      ../data/slip39.txt
      ../paper-backup/template.typ
    ];
  };

  cargoLock.lockFile = ../Cargo.lock;
  nativeBuildInputs = [
    pkg-config
    rustPlatform.bindgenHook
  ];
  buildInputs = [ openssl ];

  # Cargo's regular suite runs in the build sandbox. The GnuPG agent test is
  # explicitly invoked in the development shell, since it needs local sockets.
  doCheck = true;

  meta = {
    description = "Recoverable OpenPGP master keys with compact and raw paper backups";
    license = lib.licenses.mit;
    mainProgram = "gpg-keys";
    platforms = lib.platforms.unix;
  };
}
