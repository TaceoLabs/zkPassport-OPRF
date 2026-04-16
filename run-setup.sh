#!/usr/bin/env bash

set -eu

NOCOLOR='\033[0m'
RED='\033[0;31m'
GREEN='\033[0;32m'

PK=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

wait_for_health() {
    local port=$1
    local name=$2
    local timeout=${3:-60}
    local start_time=$(date +%s)
    echo "waiting for $name on port $port to be healthy..."

    while true; do
        http_code=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$port/health" || echo "000")
        if [[ "$http_code" == "200" ]]; then
            echo "$name is healthy!"
            break
        fi
        now=$(date +%s)
        if (( now - start_time >= timeout )); then
            echo -e "${RED}error: $name did not become healthy after $timeout seconds${NOCOLOR}" >&2
            exit 1
        fi
        sleep 1
    done
}

wait_for_oprf_pub() {
    local port=$1
    local timeout=${3:-60}
    local start_time=$(date +%s)
    local oprf_key_id=$2
    echo "waiting for orpf key id $oprf_key_id on port $port to be ready..."

    while true; do
        http_code=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$port/oprf_pub/$oprf_key_id" || echo "000")
        if [[ "$http_code" == "200" ]]; then
            echo "Found oprf key id $oprf_key_id"
            break
        fi
        now=$(date +%s)
        if (( now - start_time >= timeout )); then
            echo -e "${RED}error: oprf key id $oprf_key_id was not found after $timeout seconds${NOCOLOR}" >&2
            exit 1
        fi
        sleep 1
    done
}

deploy_contracts() {
    # deploy OprfKeyRegistry for 3 nodes and register anvil wallets 7,8,9 as participants
    (cd contracts && TACEO_ADMIN_ADDRESS=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 THRESHOLD=2 NUM_PEERS=3 forge script script/deploy/OprfKeyRegistryWithDeps.s.sol --broadcast --fork-url http://127.0.0.1:8545 --private-key $PK)
    # this should stay constant unless the contract changes, is also hardcoded in contracts/script/config/local.json
    oprf_key_registry=$(jq -r '.transactions[] | select(.contractName == "ERC1967Proxy") | .contractAddress' ./contracts/broadcast/OprfKeyRegistryWithDeps.s.sol/31337/run-latest.json)
    (cd contracts && TACEO_ADMIN_ADDRESS=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 OPRF_KEY_REGISTRY_PROXY=$oprf_key_registry PARTICIPANT_ADDRESSES=0x14dC79964da2C08b23698B3D3cc7Ca32193d9955,0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f,0xa0Ee7A142d267C1f36714E4a8F75612F20a79720 forge script script/RegisterParticipants.s.sol --broadcast --fork-url http://127.0.0.1:8545 --private-key $PK)
    echo "OprfKeyRegistry: $oprf_key_registry"
}

start_node() {
    local i="$1"
    local port=$((10000 + i))
    local db_conn="postgres://postgres:postgres@localhost:5432/postgres"
    RUST_LOG="taceo=trace,warn" \
    TACEO_OPRF_NODE__BIND_ADDR=127.0.0.1:$port \
    TACEO_OPRF_NODE__SERVICE__ORACLE_URL="http://127.0.0.1:3000" \
    TACEO_OPRF_NODE__SERVICE__OPRF__ENVIRONMENT=dev \
    TACEO_OPRF_NODE__SERVICE__OPRF__OPRF_KEY_REGISTRY_CONTRACT=$oprf_key_registry \
    TACEO_OPRF_NODE__SERVICE__OPRF__VERSION_REQ=">=0.0.0" \
    TACEO_OPRF_NODE__SERVICE__OPRF__WS_MAX_MESSAGE_SIZE=262144 \
    TACEO_OPRF_NODE__SERVICE__RPC__HTTP_URLS=http://127.0.0.1:8545 \
    TACEO_OPRF_NODE__SERVICE__RPC__WS_URL=ws://127.0.0.1:8545 \
    TACEO_OPRF_NODE__SERVICE__RPC__CHAIN_ID=31337 \
    TACEO_OPRF_NODE__POSTGRES__CONNECTION_STRING=$db_conn \
    TACEO_OPRF_NODE__POSTGRES__SCHEMA=oprf$i \
    ./target/release/taceo-zkpassport-oprf-node > logs/node$i.log 2>&1 &
    pid=$!
    echo "started oprf-node $i with PID $pid"
}

teardown() {
    docker compose -f ./deploy/local/docker-compose.yml down || true
    killall -9 taceo-zkpassport-oprf-node 2>/dev/null || true
    killall -9 taceo-zkpassport-oprf-mock-oracle 2>/dev/null || true
    killall -9 anvil 2>/dev/null || true
}

start_mock_oracle() {
    MOCK_ORACLE_BIND_ADDR=0.0.0.0:3000 \
    ./target/release/taceo-zkpassport-oprf-mock-oracle > logs/mock-oracle.log 2>&1 &
    pid=$!
    echo "started mock-oracle with PID $pid"
}

wait_for_mock_oracle() {
    local port=$1
    local timeout=${2:-30}
    local start_time=$(date +%s)
    echo "waiting for mock-oracle on port $port to be healthy..."

    while true; do
        http_code=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$port/" || echo "000")
        if [[ "$http_code" == "200" ]]; then
            echo "mock-oracle is healthy!"
            break
        fi
        now=$(date +%s)
        if (( now - start_time >= timeout )); then
            echo -e "${RED}error: mock-oracle did not become healthy after $timeout seconds${NOCOLOR}" >&2
            exit 1
        fi
        sleep 1
    done
}

setup() {
    rm -rf logs
    mkdir -p logs
    teardown
    trap teardown EXIT SIGINT SIGTERM

    docker compose -f ./deploy/local/docker-compose.yml up -d postgres anvil
    # wait for anvil to be healthy before proceeding
    while true; do
        response=$(curl -X POST --data '{"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":1}' -H "Content-Type: application/json" http://localhost:8545 || echo "bla")
        if [[ "$response" == *"anvil"* ]]; then
            echo "Anvil is healthy!"
            break
        fi
        echo "Waiting for Anvil to be healthy..."
        sleep 1
    done

    echo -e "${GREEN}deploying contracts..${NOCOLOR}"
    deploy_contracts

    echo -e "${GREEN}starting OPRF key-gen nodes..${NOCOLOR}"
    TACEO_OPRF_KEY_GEN__SERVICE__OPRF_KEY_REGISTRY_CONTRACT=$oprf_key_registry \
    docker compose -f ./deploy/local/docker-compose.yml up -d oprf-key-gen0 oprf-key-gen1 oprf-key-gen2

    docker compose -f ./deploy/local/docker-compose.yml logs -f --no-log-prefix oprf-key-gen0 > logs/key-gen0.log 2>&1 &
    docker compose -f ./deploy/local/docker-compose.yml logs -f --no-log-prefix oprf-key-gen1 > logs/key-gen1.log 2>&1 &
    docker compose -f ./deploy/local/docker-compose.yml logs -f --no-log-prefix oprf-key-gen2 > logs/key-gen2.log 2>&1 &
    wait_for_health 20000 "oprf-key-gen0" 300
    wait_for_health 20001 "oprf-key-gen1" 300
    wait_for_health 20002 "oprf-key-gen2" 300

    echo -e "${GREEN}starting OPRF nodes..${NOCOLOR}"
    echo -e "${GREEN}starting mock-oracle..${NOCOLOR}"
    start_mock_oracle
    wait_for_mock_oracle 3000 30
    start_node 0
    start_node 1
    start_node 2
    wait_for_health 10000 "taceo-zkpassport-oprf-node0" 300
    wait_for_health 10001 "taceo-zkpassport-oprf-node1" 300
    wait_for_health 10002 "taceo-zkpassport-oprf-node2" 300

    echo -e "${GREEN}init an OPRF key..${NOCOLOR}"
    (cd contracts && OPRF_KEY_REGISTRY_PROXY=$oprf_key_registry OPRF_KEY_ID=1 forge script script/InitKeyGen.s.sol --broadcast --fork-url http://127.0.0.1:8545 --private-key $PK)

    wait_for_oprf_pub 10000 1 300
    wait_for_oprf_pub 10001 1 300
    wait_for_oprf_pub 10002 1 300
}

client() {
    ./target/release/taceo-zkpassport-dev-client "$@"
}

main() {
    if [ $# -lt 1 ]; then
        echo "usage: $0 <command>"
        exit 1
    fi

    if [[ $1 = "setup" ]]; then
        cargo build --workspace --release
        echo -e "${GREEN}running setup..${NOCOLOR}"
        setup
        echo -e "${GREEN}press Ctrl+C to stop${NOCOLOR}"
        wait
    elif [[ $1 = "e2e-test" ]]; then
        cargo build --workspace --release
        echo -e "${GREEN}running test..${NOCOLOR}"
        setup
        client --nodes http://127.0.0.1:10000,http://127.0.0.1:10001,http://127.0.0.1:10002 --oprf-key-registry-contract $oprf_key_registry --max-wait-time 10min reshare-test 
        client --nodes http://127.0.0.1:10000,http://127.0.0.1:10001,http://127.0.0.1:10002 --oprf-key-registry-contract $oprf_key_registry --max-wait-time 10min delete-test 
        client --nodes http://127.0.0.1:10000,http://127.0.0.1:10001,http://127.0.0.1:10002 --oprf-key-registry-contract $oprf_key_registry --max-wait-time 10min stress-test-oprf 
        client --nodes http://127.0.0.1:10000,http://127.0.0.1:10001,http://127.0.0.1:10002 --oprf-key-registry-contract $oprf_key_registry --max-wait-time 10min stress-test-key-gen 
    else
        echo "unknown command: '$1' - supported are setup and e2e-test"
        exit 1
    fi

}

main "$@"
