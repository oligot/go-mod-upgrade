{ sources ? import ./nix/sources.nix
, pkgs ? import sources.nixpkgs { }
}:

pkgs.mkShell {

  buildInputs = [
    pkgs.niv
    pkgs.nil
    pkgs.go_1_23
    pkgs.golangci-lint
    pkgs.goreleaser
  ];

}
