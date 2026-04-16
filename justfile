[private]
default:
    @just --justfile {{ justfile() }} --list --list-heading $'Project commands:\n'

[group('ci')]
lint:
    cargo fmt --all -- --check
    cargo clippy --workspace --tests --examples --benches --bins -q -- -D warnings
    cargo clippy --workspace --tests --examples --benches --bins -q --all-features -- -D warnings
    RUSTDOCFLAGS='-D warnings' cargo doc --workspace -q --no-deps --document-private-items

[group('ci')]
check-pr: lint all-tests

[group('test')]
rust-tests:
    cargo test --release --workspace --all-features

[group('test')]
e2e-test:
    @bash run-setup.sh e2e-test || { echo -e "\033[1;41m===== TEST FAILED =====\033[0m" ; exit 1; }

[group('test')]
all-tests: rust-tests e2e-test

[group('local-setup')]
run-setup:
    @bash run-setup.sh setup

[group('deploy')]
run-dev-client *args:
    cargo run --release --bin taceo-zkpassport-dev-client {{ args }}
