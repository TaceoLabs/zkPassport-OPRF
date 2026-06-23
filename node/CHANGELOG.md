# Changelog

## [Unreleased]

## [1.0.0]

### ⛰️ Features


- *(node)* Correctly handle BAD REQUEST - ([c6f5873](https://github.com/TaceoLabs/zkPassport-OPRF/commit/c6f58736ae62d1b3bf35eef4dd6f9c67ca05c423))
- *(test-utils)* Add shared test-utils crate with fixtures and container harness - ([1570da4](https://github.com/TaceoLabs/zkPassport-OPRF/commit/1570da4d7b7218ea6696922e4504174b72f06c84))
- Removed mock oracle and added proof-verifier to setup - ([6b6ea23](https://github.com/TaceoLabs/zkPassport-OPRF/commit/6b6ea23123691b759ce9c8d0eeca6fc081e61b6d))

### 🐛 Bug Fixes


- *(node)* Correctly log bad request at warn level - ([8369c82](https://github.com/TaceoLabs/zkPassport-OPRF/commit/8369c821c99e17daeb420f3531ca04dc3adba4c0))

### 🚜 Refactor


- *(node)* [**breaking**] Remove dead error code variant - ([a41950e](https://github.com/TaceoLabs/zkPassport-OPRF/commit/a41950e6178ba0f1903ac4e94f739052066d5410))
- *(node)* Use status code as source of truth for result - ([f10d25e](https://github.com/TaceoLabs/zkPassport-OPRF/commit/f10d25e3fbb55ec444ef76a29b300f459ddb77d5))
- *(node)* Add new error variants for auth module - ([9c6e5c4](https://github.com/TaceoLabs/zkPassport-OPRF/commit/9c6e5c4ac3dab6a1626f79205421b6aae383f9f1))
- *(node)* Use dedicated health check task - ([190c456](https://github.com/TaceoLabs/zkPassport-OPRF/commit/190c456c0a44940212cfc9c8186ff58a5dd9fdca))
- *(node)* Updated error reporting when oracle fails - ([f957122](https://github.com/TaceoLabs/zkPassport-OPRF/commit/f957122dea3666e166aea73a97f370693bd9ec2a))
- *(node)* Better logging in error case - ([ffbebf3](https://github.com/TaceoLabs/zkPassport-OPRF/commit/ffbebf3db03653a80c0974d6a78781b70eca68e4))
- *(node)* Use jemallocator as global_allocator - ([955a623](https://github.com/TaceoLabs/zkPassport-OPRF/commit/955a623e06b2599d69c90b005b126367aa56f24e))
- [**breaking**] Bump to taceo-oprf 0.15.2 and cleanup - ([6cb41bf](https://github.com/TaceoLabs/zkPassport-OPRF/commit/6cb41bffda389c7669e1b17abe72be5fa9d26146))
- Added prod clippy lints - ([2fe8fe3](https://github.com/TaceoLabs/zkPassport-OPRF/commit/2fe8fe3fc1ee33fbf69470103eed1f1e6da0390c))
- [**breaking**] Bump latest version + rename to zkPassport ([#29](https://github.com/TaceoLabs/zkPassport-OPRF/pull/29)) - ([9494294](https://github.com/TaceoLabs/zkPassport-OPRF/commit/9494294b645fe13e3fad484ec37bad594f637d4e))

### 🏗️ Build


- *(deps)* Bump nodes-common and taceo:oprf - ([12436ad](https://github.com/TaceoLabs/zkPassport-OPRF/commit/12436ad1c352332e7c7d30124198049473200f01))
- *(node)* Set release tracing level to max debug - ([1710e80](https://github.com/TaceoLabs/zkPassport-OPRF/commit/1710e804037e00f6f4d2255c4f83190341391e32))
- Bump alloy and OPRF versions ([#40](https://github.com/TaceoLabs/zkPassport-OPRF/pull/40)) - ([892b18a](https://github.com/TaceoLabs/zkPassport-OPRF/commit/892b18a166f0c3755dd3fb4aec93c6b5bc6e730e))

### 📚 Documentation


- Updated stale docs - ([d1b34af](https://github.com/TaceoLabs/zkPassport-OPRF/commit/d1b34af53e6d42e0b37ceed23b89d288ace9e5fe))
- Added docs for project ([#33](https://github.com/TaceoLabs/zkPassport-OPRF/pull/33)) - ([a32eae8](https://github.com/TaceoLabs/zkPassport-OPRF/commit/a32eae8abf704149f66fade96c29e91d3d56eee3))

### 🧪 Testing


- Add mock oracle for testing - ([6cb16f4](https://github.com/TaceoLabs/zkPassport-OPRF/commit/6cb16f4b9bc975fd66b73c1ebf900f0707d52cd5))

### ⚙️ Miscellaneous Tasks


- Set version to 1.0.0 - ([4d99a0e](https://github.com/TaceoLabs/zkPassport-OPRF/commit/4d99a0e46e3597a4ab8ab99e49d36d02b786139f))
- Set to rc-5 to find latest release - ([568c623](https://github.com/TaceoLabs/zkPassport-OPRF/commit/568c623edd9a374d26db9a09da25392737cc1b0c))
- Release flow for node - ([415e36d](https://github.com/TaceoLabs/zkPassport-OPRF/commit/415e36d09919099c4df2d90e39650b44f5e73a1c))
- Some typos - ([9629415](https://github.com/TaceoLabs/zkPassport-OPRF/commit/96294153a6fb58e7bf36260fbee34af0265781b3))
- Removed dead return type - ([18cc912](https://github.com/TaceoLabs/zkPassport-OPRF/commit/18cc9127cfc9e11e3671cb9e5139ba5a9df9cac5))
- Added license - ([189c62a](https://github.com/TaceoLabs/zkPassport-OPRF/commit/189c62a3d51cd105c30c71d0386ed95949b6ed0f))
- Add instrument to authenticate ([#75](https://github.com/TaceoLabs/zkPassport-OPRF/pull/75)) - ([0752ebd](https://github.com/TaceoLabs/zkPassport-OPRF/commit/0752ebda1bc6b8da9fcf105ca0018aa09d7444f0))
- Split healthcheck and oracle url ([#47](https://github.com/TaceoLabs/zkPassport-OPRF/pull/47)) - ([a093442](https://github.com/TaceoLabs/zkPassport-OPRF/commit/a09344244a2c0c0b7b5987d1e3e848ba7192c254))
- Enable cors on nodes - ([b95a6e8](https://github.com/TaceoLabs/zkPassport-OPRF/commit/b95a6e8c733fab2ac68ec8669d51fa87c885c1b7))

