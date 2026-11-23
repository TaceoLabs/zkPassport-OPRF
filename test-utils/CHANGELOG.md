# Changelog

## [0.2.0](https://github.com/TaceoLabs/zkPassport-OPRF/compare/taceo-zkpassport-oprf-test-utils-v0.1.0...taceo-zkpassport-oprf-test-utils-v0.2.0)

### ⛰️ Features


- *(dev-client)* Check that smoke identify returns the identifier key - ([3a2d11e](https://github.com/TaceoLabs/zkPassport-OPRF/commit/3a2d11efd13f7b815b6711e93b8946c193ea06b6))
- *(node)* Add impl for requests v2 - ([8702c9a](https://github.com/TaceoLabs/zkPassport-OPRF/commit/8702c9a3b1afe35b2d2bdb02d9ca4f7bb31b395b))
- *(node)* Added axum routes for non-oprf calls and some new-types - ([a0eed03](https://github.com/TaceoLabs/zkPassport-OPRF/commit/a0eed037eab53fb3b38e9f020fd342be9714654b))
- *(node)* Adds stubs for the proxy - ([d531423](https://github.com/TaceoLabs/zkPassport-OPRF/commit/d531423158fa585a3f99a470e40800bce2d4bff8))
- [**breaking**] Fix the identifier OPRF key ID to U160::MAX - ([243f60d](https://github.com/TaceoLabs/zkPassport-OPRF/commit/243f60d0df28540aca90c62f3652f2866b0b17c9))

### 🐛 Bug Fixes


- *(test-utils)* Normalize node URLs and add HTTP timeout - ([cc8b06b](https://github.com/TaceoLabs/zkPassport-OPRF/commit/cc8b06bd440b399ce4e1b307bde08dc8251be1ea))

### 🚜 Refactor


- *(dev-client)* Replace upstream dev-client with smoke and stress commands - ([63e3e92](https://github.com/TaceoLabs/zkPassport-OPRF/commit/63e3e929b57e2ebdf33bf2286d047aa62f73ce0e))
- *(node)* [**breaking**] Rename register auth module to identify - ([ef62909](https://github.com/TaceoLabs/zkPassport-OPRF/commit/ef629094608c8fceeddece009fb00b085496660f))
- *(node)* [**breaking**] Remove health check service - ([c71dd4a](https://github.com/TaceoLabs/zkPassport-OPRF/commit/c71dd4accf2a10759132f7ecea04658ad404a1e9))
- *(node)* Add v2 service and move face-match to v1. Adds an oracle proxy - ([284b746](https://github.com/TaceoLabs/zkPassport-OPRF/commit/284b7466fcdbf696c2e8d3d93c2768da65fe0abc))
- *(test-utils)* Embed fixtures at compile time - ([61a3839](https://github.com/TaceoLabs/zkPassport-OPRF/commit/61a38396c74346b0b4dc0a7131d9a2460bfb35ac))
- Timeout of oracle proxy is no longer retryable - ([fd95dba](https://github.com/TaceoLabs/zkPassport-OPRF/commit/fd95dba78e59079970b921a029cfa53519c70b0a))
- Remove client crate - ([4aa34ba](https://github.com/TaceoLabs/zkPassport-OPRF/commit/4aa34ba926cfa728c2bce1349ac2aa85e0751759))

### 📚 Documentation


- Correct dev-client, e2e and HTTP API descriptions - ([9078c2d](https://github.com/TaceoLabs/zkPassport-OPRF/commit/9078c2d63faf4277534c4fa64bfb1974d7a37f43))

### 🧪 Testing


- *(node)* Add e2e test against the local setup - ([a98e04d](https://github.com/TaceoLabs/zkPassport-OPRF/commit/a98e04d14dffb57d31136cfc33599602ca2e8181))
- *(test-utils)* Return the OPRF public key from NodeClient - ([319f171](https://github.com/TaceoLabs/zkPassport-OPRF/commit/319f17130ca2a247d659a290a935d6ca819d24e2))
- *(test-utils)* Add NodeClient for v2 requests - ([f68e519](https://github.com/TaceoLabs/zkPassport-OPRF/commit/f68e519fb1836af5c66c612886cab9f18e134c12))
- *(test-utils)* Add v2 fixtures - ([82f0462](https://github.com/TaceoLabs/zkPassport-OPRF/commit/82f046255c2ccbbaad6bfdcbce502c81fe28b2a5))
- Refactor dev-client to test specific parts - ([169ed2b](https://github.com/TaceoLabs/zkPassport-OPRF/commit/169ed2b64507fefc0d13493211e95a5d1ddfa0e0))
- Add unit tests and integration test suite ([#206](https://github.com/TaceoLabs/zkPassport-OPRF/pull/206)) - ([45e4666](https://github.com/TaceoLabs/zkPassport-OPRF/commit/45e4666efe90bce98a71c595513c85677129d99c))
- Remove proof-verifier testcontainer after the last test - ([387d38a](https://github.com/TaceoLabs/zkPassport-OPRF/commit/387d38a5f6eb57aadcd5ba69165cc85c81b1cf96))

### 🌀 Other


- *(test-utils)* Remove unused proof-verifier testcontainer - ([3c91573](https://github.com/TaceoLabs/zkPassport-OPRF/commit/3c915732e5842e1ee4d9ec3502818f877f3190b9))
- Lints for Cargo.toml - ([960740e](https://github.com/TaceoLabs/zkPassport-OPRF/commit/960740ec7384564d3e2b5ef6e7808c857712bc01))
- Update verifier tag ([#199](https://github.com/TaceoLabs/zkPassport-OPRF/pull/199)) - ([d7c53f1](https://github.com/TaceoLabs/zkPassport-OPRF/commit/d7c53f1c9de75fbef86e9b87f3f7c78e989dc6fb))


## [0.1.0]

### ⛰️ Features


- *(node)* Retry load information instead of crashing early - ([da64f1e](https://github.com/TaceoLabs/zkPassport-OPRF/commit/da64f1e10e8c002d5d9335333eba4a0524ebfd86))
- *(test-utils)* Add shared test-utils crate with fixtures and container harness - ([1570da4](https://github.com/TaceoLabs/zkPassport-OPRF/commit/1570da4d7b7218ea6696922e4504174b72f06c84))
- Removed mock oracle and added proof-verifier to setup - ([6b6ea23](https://github.com/TaceoLabs/zkPassport-OPRF/commit/6b6ea23123691b759ce9c8d0eeca6fc081e61b6d))

### 🚜 Refactor


- [**breaking**] Bump to taceo-oprf 0.15.2 and cleanup - ([6cb41bf](https://github.com/TaceoLabs/zkPassport-OPRF/commit/6cb41bffda389c7669e1b17abe72be5fa9d26146))
- [**breaking**] Bump latest version + rename to zkPassport ([#29](https://github.com/TaceoLabs/zkPassport-OPRF/pull/29)) - ([9494294](https://github.com/TaceoLabs/zkPassport-OPRF/commit/9494294b645fe13e3fad484ec37bad594f637d4e))

### 🏗️ Build


- Bump alloy and OPRF versions ([#40](https://github.com/TaceoLabs/zkPassport-OPRF/pull/40)) - ([892b18a](https://github.com/TaceoLabs/zkPassport-OPRF/commit/892b18a166f0c3755dd3fb4aec93c6b5bc6e730e))

### 📚 Documentation


- Updated stale docs - ([33e7b14](https://github.com/TaceoLabs/zkPassport-OPRF/commit/33e7b1460da716811052397cb7154e526eadff41))
- Added docs for project ([#33](https://github.com/TaceoLabs/zkPassport-OPRF/pull/33)) - ([a32eae8](https://github.com/TaceoLabs/zkPassport-OPRF/commit/a32eae8abf704149f66fade96c29e91d3d56eee3))

### 🧪 Testing


- Update proof verifier tag - ([ec4e82a](https://github.com/TaceoLabs/zkPassport-OPRF/commit/ec4e82a0e52242a189756d94d8ebe3194109b845))

### 🌀 Other


- Bump verifier image - ([825702a](https://github.com/TaceoLabs/zkPassport-OPRF/commit/825702a516c47e5d3fa34a7df1fd769db73adc37))
- Update verifier tag ([#118](https://github.com/TaceoLabs/zkPassport-OPRF/pull/118)) - ([ad755de](https://github.com/TaceoLabs/zkPassport-OPRF/commit/ad755de5aa58597f087bf6e36fd441918deb0703))
- Update fixtures ([#109](https://github.com/TaceoLabs/zkPassport-OPRF/pull/109)) - ([a596b6d](https://github.com/TaceoLabs/zkPassport-OPRF/commit/a596b6de10ac95a95db07e488b2528afb2c0632f))
- Some typos - ([9629415](https://github.com/TaceoLabs/zkPassport-OPRF/commit/96294153a6fb58e7bf36260fbee34af0265781b3))
- Added license - ([189c62a](https://github.com/TaceoLabs/zkPassport-OPRF/commit/189c62a3d51cd105c30c71d0386ed95949b6ed0f))
- Initial commit - ([b9f87c2](https://github.com/TaceoLabs/zkPassport-OPRF/commit/b9f87c21301b43a800d0c692c8b7e253a810869c))

