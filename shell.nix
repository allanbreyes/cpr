{ pkgs ? import <nixpkgs> {}}:

pkgs.mkShell {
  nativeBuildInputs = with pkgs; [
    cargo
    gcc
    rustc
  ];
  buildInputs = with pkgs; [
    cargo-watch
    clippy
    rust-analyzer
    rustfmt

    # Tooling
    go-task
    wget
  ];

  RUST_BACKTRACE = 1;
  RUST_SRC_PATH = "${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";
}
