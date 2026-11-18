[![CI](https://github.com/TaceoLabs/zkPassport-OPRF/actions/workflows/ci.yml/badge.svg)](https://github.com/TaceoLabs/zkPassport-OPRF/actions/workflows/ci.yml) [![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](/LICENSE) [![Rust](https://img.shields.io/badge/rust-1.94.1%2B-orange.svg)](https://www.rust-lang.org)

# TACEO:OPRF for zkPassport

A customized deployment of the [TACEO:OPRF service](https://github.com/TaceoLabs/oprf-service) that adds **zkPassport proof-based authentication** to the OPRF request flow. Passport holders prove their identity via zero-knowledge proofs, which are verified by an oracle before the OPRF evaluation proceeds.

This is a monorepo containing:

* `authentication`: A library crate that defines the authentication types, error codes, and oracle-error mapping used by the zkPassport OPRF flow.
* `client`: A library crate implementing the client-side logic for performing a distributed, verifiable OPRF evaluation with zkPassport authentication.
* `contracts`: Foundry project containing the smart contracts (inherited from the upstream OPRF service).
* `dev-client`: A binary crate that runs the end-to-end test, smoke tests and a stress test against local or deployed nodes using fixture data.
* `node`: A binary + library crate implementing the zkPassport OPRF node — the main service binary that handles OPRF requests with face-match authentication.

## Dev Dependencies

* [just](https://github.com/casey/just)
* Docker Compose (for running `anvil` and `postgres` containers)
* anvil and forge — install with [foundryup](https://getfoundry.sh/introduction/installation/)
* Rust 1.94.1+ (edition 2024)

## Setup

### Forge

Install smart-contract dependencies:

```sh
cd contracts && forge install
```

## Test & Run

Run the full Rust test suite:

```sh
just rust-tests
```

Run the end-to-end test (starts local infra, deploys contracts, runs nodes, and exercises the full flow):

```sh
just e2e-test
```

Or run everything (unit + e2e):

```sh
just all-tests
```

### Local Setup

To start a local multi-node setup for interactive development:

```sh
just run-setup
```

This will:
1. Start `anvil` and `postgres` Docker containers
2. Deploy the `OprfKeyRegistry` smart contract and register participants
3. Start a verification oracle (proof-verifier) and 3 OPRF service nodes
4. Start 3 OPRF key-gen instances (via Docker)
5. Initialize the registration OPRF key (id 1) and a customer OPRF key (id 2)

Log files for all processes are written to the `logs/` directory. Press `Ctrl+C` to tear down.

`just e2e-test` starts the setup, runs the end-to-end test (`node/tests/e2e.rs`, once per fresh node database) and then `stress identify`.

## Testing deployed systems

The `dev-client` runs the fixtures against nodes given with `--nodes <url>,<url>,<url>` (`OPRF_DEV_CLIENT_NODES`) and the customer key with `--oprf-key-id`. It also works against the local setup.

| Environment | Command |
|---|---|
| `dev` (`devmode=true`, the fixtures verify) | `just run-dev-client smoke`, repeatable |
| `dev`, load test | `just run-dev-client stress identify --concurrency 10 --requests 100`, `stress nullifier` |
| other (`devmode=false`) | `just run-dev-client smoke --prod`: checks that the nodes are up and the verifier rejects the fixture proofs, writes nothing |

The fixtures allow one rotation per node database, which only the end-to-end test performs. Afterwards `smoke` and `stress nullifier` fail on that database, so never run the end-to-end test against a shared environment.

## Configuration

The OPRF node is configured via environment variables using a hierarchical prefix scheme:

* **OPRF node:** `TACEO_OPRF_NODE__*` (e.g., `TACEO_OPRF_NODE__BIND_ADDR`, `TACEO_OPRF_NODE__SERVICE__OPRF__ENVIRONMENT`)

OPRF key-gen instances are provided by the upstream [oprf-service](https://github.com/TaceoLabs/oprf-service) Docker images and configured via `TACEO_OPRF_KEY_GEN__*` environment variables.

See `run-setup.sh` for a complete example of all required environment variables.

### Oracle

All oracle requests go through one proxy built from a base URL. Endpoint paths are appended to it:

* `<base>/verify-oprf-auth`: face-match verification (v1)
* `<base>/oprf/v2/identify`, `register`, `query` and `rotate`: proof verification of the four v2 steps

In the `dev` environment, `?devmode=true` is added to every endpoint. Connection errors and HTTP 408, 429, 502, 503 and 504 are retried with exponential backoff.

| Variable | Required | Description |
|----------|----------|-------------|
| `TACEO_OPRF_NODE__SERVICE__ORACLE_BASE_URL` | yes | Base URL of the oracle (e.g. `http://127.0.0.1:8080`) |

## Databases

OPRF key shares are stored in a PostgreSQL schema managed by the upstream `taceo-oprf` secret manager. A separate schema stores passport registrations and is initialized and migrated (from `node/migrations`) when the node starts. Both schemas can use the same PostgreSQL database. The node needs write access to the registrations schema.

**Required environment variables:**

* `TACEO_OPRF_NODE__OPRF_KEYS_POSTGRES__CONNECTION_STRING` — PostgreSQL connection string for OPRF keys
* `TACEO_OPRF_NODE__OPRF_KEYS_POSTGRES__SCHEMA` — schema for OPRF keys
* `TACEO_OPRF_NODE__USERS_POSTGRES__CONNECTION_STRING` — PostgreSQL connection string for passport registrations
* `TACEO_OPRF_NODE__USERS_POSTGRES__SCHEMA` — schema for passport registrations

**Security considerations:**

* The connection string contains credentials and should be treated as a secret
* Use SSL/TLS connections in production (`?sslmode=require`)
* Ensure the database is not publicly accessible

## HTTP API

The node forwards the proofs of a request to the oracle and changes its database only if the oracle accepts them.

* `POST /api/registration`: stores the commitment for a passport identifier `I`. Body: `{"I": <point>, "commitment": <field element>, "proofs": [<proof>, ...]}`. Returns 409 if `I` is registered with another commitment.
* `POST /api/rotation`: replaces the commitment stored for `I`. Body: `{"I": <point>, "new_commitment": <field element>, "proofs": [<proof>, ...]}`. Returns 404 for an unknown identifier and 409 if the commitment was stored for `I` before.

Repeating a request that succeeded succeeds again. Both endpoints return 400 if the oracle rejects the proofs and 503 if the oracle is not reachable.

## Architecture

This project builds on the [TACEO:OPRF service](https://github.com/TaceoLabs/oprf-service). For a detailed description of the underlying OPRF scheme, see the [design document](https://github.com/TaceoLabs/oprf-service/blob/main/docs/oprf.pdf).

The zkPassport-specific addition is an **authentication layer**: before an OPRF evaluation is performed, the requesting client must supply zero-knowledge proofs (generated by [zkPassport](https://zkpassport.id)) that are forwarded to an oracle for verification. Only after the oracle confirms the proofs does the OPRF node proceed with the evaluation.

## License

This project is licensed under either of

* [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
* [MIT License](http://opensource.org/licenses/MIT)

at your option.
