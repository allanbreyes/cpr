# ❤️‍🩹 cpr 🔓

Solutions for [**C**rypto**P**als][cryptopals] in [**R**ust][rust].

## Setup

* Use [nix][nix] and run `nix-shell`
* Run `cp hooks/pre-commit .git/hooks/`
* (Optional) run `rm src/bin/??.rs && echo > src/utils.rs` to remove solutions

## Usage

* Run (fast) tests: `cargo test`
* Run the test watcher: `cargo watch -x test`
* Run an individual challenge: `cargo solve <number>`
* Scaffold a new challenge: `cargo scaffold <number>`

[cryptopals]: https://www.cryptopals.com/
[nix]: https://nixos.org/
[rust]: https://www.rust-lang.org/