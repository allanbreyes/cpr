{ pkgs ? import <nixpkgs> {}}:

let
  frameworks = pkgs.darwin.apple_sdk.frameworks;
in pkgs.mkShell {
  nativeBuildInputs = with pkgs; [
    cargo
    gcc
    rustc
  ];
  buildInputs = with pkgs; [
    cargo-watch
    clippy
    openssl
    pkg-config
    rust-analyzer
    rustfmt
  ] ++ lib.optional stdenv.isDarwin [
    libiconv
    frameworks.Security
    frameworks.CoreFoundation
    frameworks.CoreServices
  ];

  shellHook = (
    if pkgs.stdenv.isDarwin then
      ''
        export NIX_LDFLAGS="-F${frameworks.CoreFoundation}/Library/Frameworks -framework CoreFoundation -F${frameworks.Security}/Library/Frameworks -framework Security $NIX_LDFLAGS";
      ''
    else
      ""
  );

  RUST_BACKTRACE = 1;
  RUST_SRC_PATH = "${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";
}
