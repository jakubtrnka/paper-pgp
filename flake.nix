{
  description = "Paper-backed OpenPGP master keys and an A5 Typst backup document";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      pkgsFor = system: import nixpkgs { inherit system; };
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        rec {
          gpg-keys = pkgs.callPackage ./nix/package.nix { };
          paper-backup = pkgs.callPackage ./nix/paper-backup.nix { };
          default = gpg-keys;
        }
      );

      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.gpg-keys}/bin/gpg-keys";
          meta.description = "Generate and recover paper-backed OpenPGP master keys";
        };
      });

      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = pkgs.mkShell {
            inputsFrom = [ self.packages.${system}.gpg-keys ];
            packages = with pkgs; [
              cargo
              rustc
              rustfmt
              clippy
              rust-analyzer
              gnupg
              (typst.wrapper { fonts = [ liberation_ttf ]; })
              poppler-utils
              python3
              nixfmt
            ];
          };
        }
      );

      checks = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
          packages = self.packages.${system};
        in
        {
          inherit (packages) gpg-keys paper-backup;
          paper-backup-content = pkgs.callPackage ./nix/check-paper-backup.nix {
            inherit (packages) gpg-keys paper-backup;
          };
        }
      );

      formatter = forAllSystems (system: (pkgsFor system).nixfmt);
    };
}
