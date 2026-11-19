# Changelog

## [0.2.0](https://github.com/TaceoLabs/zkPassport-OPRF/compare/taceo-zkpassport-dev-client-v0.1.0...taceo-zkpassport-dev-client-v0.2.0)

### ⛰️ Features


- *(node)* Add impl for requests v2 - ([8702c9a](https://github.com/TaceoLabs/zkPassport-OPRF/commit/8702c9a3b1afe35b2d2bdb02d9ca4f7bb31b395b))
- *(node)* Added axum routes for non-oprf calls and some new-types - ([a0eed03](https://github.com/TaceoLabs/zkPassport-OPRF/commit/a0eed037eab53fb3b38e9f020fd342be9714654b))
- *(node)* Adds stubs for the proxy - ([d531423](https://github.com/TaceoLabs/zkPassport-OPRF/commit/d531423158fa585a3f99a470e40800bce2d4bff8))

### 🚜 Refactor


- *(dev-client)* Replace upstream dev-client with smoke and stress commands - ([63e3e92](https://github.com/TaceoLabs/zkPassport-OPRF/commit/63e3e929b57e2ebdf33bf2286d047aa62f73ce0e))
- *(node)* [**breaking**] Remove health check service - ([c71dd4a](https://github.com/TaceoLabs/zkPassport-OPRF/commit/c71dd4accf2a10759132f7ecea04658ad404a1e9))
- *(node)* Add v2 service and move face-match to v1. Adds an oracle proxy - ([284b746](https://github.com/TaceoLabs/zkPassport-OPRF/commit/284b7466fcdbf696c2e8d3d93c2768da65fe0abc))
- Timeout of oracle proxy is no longer retryable - ([fd95dba](https://github.com/TaceoLabs/zkPassport-OPRF/commit/fd95dba78e59079970b921a029cfa53519c70b0a))
- Remove client crate - ([4aa34ba](https://github.com/TaceoLabs/zkPassport-OPRF/commit/4aa34ba926cfa728c2bce1349ac2aa85e0751759))

### 📚 Documentation


- Correct dev-client, e2e and HTTP API descriptions - ([9078c2d](https://github.com/TaceoLabs/zkPassport-OPRF/commit/9078c2d63faf4277534c4fa64bfb1974d7a37f43))

### 🧪 Testing


- *(node)* Add e2e test against the local setup - ([a98e04d](https://github.com/TaceoLabs/zkPassport-OPRF/commit/a98e04d14dffb57d31136cfc33599602ca2e8181))
- *(test-utils)* Return the OPRF public key from NodeClient - ([319f171](https://github.com/TaceoLabs/zkPassport-OPRF/commit/319f17130ca2a247d659a290a935d6ca819d24e2))

### 🌀 Other


- Lints for Cargo.toml - ([960740e](https://github.com/TaceoLabs/zkPassport-OPRF/commit/960740ec7384564d3e2b5ef6e7808c857712bc01))


## [0.1.0]

### ⛰️ Features


- *(node)* Retry load information instead of crashing early - ([da64f1e](https://github.com/TaceoLabs/zkPassport-OPRF/commit/da64f1e10e8c002d5d9335333eba4a0524ebfd86))
- *(test-utils)* Add shared test-utils crate with fixtures and container harness - ([1570da4](https://github.com/TaceoLabs/zkPassport-OPRF/commit/1570da4d7b7218ea6696922e4504174b72f06c84))
- Removed mock oracle and added proof-verifier to setup - ([6b6ea23](https://github.com/TaceoLabs/zkPassport-OPRF/commit/6b6ea23123691b759ce9c8d0eeca6fc081e61b6d))

### 🚜 Refactor


- *(clippy)* Moved lints to Cargo.toml and enforced default taceo prod lints - ([ef6a07a](https://github.com/TaceoLabs/zkPassport-OPRF/commit/ef6a07a7abad5416aecc2cbbfeb134eecb1ce762))
- Refactor!(node): remove cancellation token in start and bump taceo:oprf 0.17.1 - ([b649afa](https://github.com/TaceoLabs/zkPassport-OPRF/commit/b649afa4797132a3ad15a3359344a81ab27f98d5))
- [**breaking**] Bump to taceo-oprf 0.15.2 and cleanup - ([6cb41bf](https://github.com/TaceoLabs/zkPassport-OPRF/commit/6cb41bffda389c7669e1b17abe72be5fa9d26146))
- [**breaking**] Bump latest version + rename to zkPassport ([#29](https://github.com/TaceoLabs/zkPassport-OPRF/pull/29)) - ([9494294](https://github.com/TaceoLabs/zkPassport-OPRF/commit/9494294b645fe13e3fad484ec37bad594f637d4e))

### 🏗️ Build


- *(deps)* Bump to latest taceo versions - ([7c15250](https://github.com/TaceoLabs/zkPassport-OPRF/commit/7c152507084120cd6b6199006dca801ca950efd6))
- *(test)* Add oracle docker container for tests ([#38](https://github.com/TaceoLabs/zkPassport-OPRF/pull/38)) - ([49f88f9](https://github.com/TaceoLabs/zkPassport-OPRF/commit/49f88f9348b13050e30cd6817597597ff6eb19e3))
- Update verifier oracle ([#82](https://github.com/TaceoLabs/zkPassport-OPRF/pull/82)) - ([933508f](https://github.com/TaceoLabs/zkPassport-OPRF/commit/933508f11b5876397e1e73b48c7aa8ee3c069fc4))
- Bump alloy and OPRF versions ([#40](https://github.com/TaceoLabs/zkPassport-OPRF/pull/40)) - ([892b18a](https://github.com/TaceoLabs/zkPassport-OPRF/commit/892b18a166f0c3755dd3fb4aec93c6b5bc6e730e))

### 📚 Documentation


- Updated stale docs - ([33e7b14](https://github.com/TaceoLabs/zkPassport-OPRF/commit/33e7b1460da716811052397cb7154e526eadff41))
- Added docs for project ([#33](https://github.com/TaceoLabs/zkPassport-OPRF/pull/33)) - ([a32eae8](https://github.com/TaceoLabs/zkPassport-OPRF/commit/a32eae8abf704149f66fade96c29e91d3d56eee3))

### 🌀 Other


- Added license - ([189c62a](https://github.com/TaceoLabs/zkPassport-OPRF/commit/189c62a3d51cd105c30c71d0386ed95949b6ed0f))
- Split healthcheck and oracle url ([#47](https://github.com/TaceoLabs/zkPassport-OPRF/pull/47)) - ([a093442](https://github.com/TaceoLabs/zkPassport-OPRF/commit/a09344244a2c0c0b7b5987d1e3e848ba7192c254))
- Initial commit - ([b9f87c2](https://github.com/TaceoLabs/zkPassport-OPRF/commit/b9f87c21301b43a800d0c692c8b7e253a810869c))

