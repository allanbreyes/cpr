{ pkgs ? import <nixpkgs> {}}:

pkgs.mkShell {
  buildInputs = with pkgs; [
    # Rust
    cargo
    clippy
    rust-analyzer
    rustc
    rustfmt

    # Tooling
    go-task
  ];

  RUST_BACKTRACE = 1;
}
