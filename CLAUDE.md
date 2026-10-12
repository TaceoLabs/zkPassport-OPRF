# zkPassport OPRF

Workspace crates: `authentication` (shared request/error types), `client`, `dev-client`, `node` (OPRF node), `test-utils` (fixtures, proof-verifier testcontainer).

## Checks (as in CI)

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo test --workspace --all-features` (needs Docker for testcontainers, do this with sandbox disabled)

## Design notes

- The `TraceLayer` in `node/src/api.rs` wraps only the API routes (`/registration`, `/rotation`) by design. The OPRF router already has one upstream, so don't add one there.
