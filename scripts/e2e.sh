#!/usr/bin/env bash
set -euo pipefail
: "${LYQUID_ADDRESS:?Set the fresh deployment address}"
: "${PRIVATE_KEY:?Set the local devnet deployer key}"
[[ $# == 8 ]] || { echo 'Usage: bash scripts/e2e.sh RPC1 ID1 RPC2 ID2 RPC3 ID3 RPC4 ID4' >&2; exit 2; }
rpc=("$1" "$3" "$5" "$7")
account=0x1111111111111111111111111111111111111111
read_node() {
    local node=$1
    shift
    cast call --rpc-url "${rpc[node]}" "$LYQUID_ADDRESS" "$@"
}
send() {
    cast send --rpc-url "${rpc[0]}" --private-key "$PRIVATE_KEY" "$LYQUID_ADDRESS" "$@" >/dev/null
}
expect() {
    [[ $1 == "$2" ]] || { printf 'Expected <%s>, got <%s>\n' "$2" "$1" >&2; exit 1; }
}
number() { printf '%s\n' "${1%% *}"; }

# Wait for a sequenced write to become visible on the queried node.
wait_for_number() {
    local expected=$1 node=$2 signature=$3
    shift 3
    local deadline=$((SECONDS + 60)) output final_line
    while true; do
        if output=$(read_node "$node" "$signature" "$@" 2>&1); then
            final_line=$(printf '%s\n' "$output" | tail -n 1)
            if [[ $(number "$final_line") == "$expected" ]]; then
                return 0
            fi
        fi
        if (( SECONDS >= deadline )); then
            printf 'Node %s did not report %s for %s. Last response: %s\n' \
                "$((node + 1))" "$expected" "$signature" "$output" >&2
            return 1
        fi
        sleep 1
    done
}

send 'configure_indexers(bytes32[],uint64)' "[$2,$4,$6,$8]" 4
for i in {0..11}; do
    send 'ingest(address,uint64,uint8)' "$account" "$((11+i))" "$((i%2))"
done
for node in {0..3}; do
    read_node "$node" 'build_index()(uint64)' >/dev/null
    wait_for_number 12 "$node" 'index_cursor()(uint64)'
done
for window in {0..2}; do
    output=$(read_node 0 'local_window_root(uint64)(bytes32,uint64)' "$window")
    expect "$(number "${output#*$'\n'}")" 4
    send 'seal_window(uint64,bytes32,uint64)' "$window" "${output%%$'\n'*}" 4
done

for node in {0..3}; do
    wait_for_number 3 "$node" 'commitment_head()(bytes32,uint64)'
done

output=$(read_node 0 'historical_balance(address,uint64)(uint64,uint64,uint64)' "$account" 0)
mapfile -t history <<< "$output"
expect "$(number "${history[0]}")" 24
expect "$(number "${history[1]}")" 26
expect "$(number "${history[2]}")" 4

balance='verified_balance(address)(bool,uint64,uint64,uint64,uint32,uint32,string)'
check_balance() {
    local output
    output=$(read_node 0 "$balance" "$account")
    local -a answer
    mapfile -t answer <<< "$output"
    expect "${answer[0]}" "$1"
    expect "$(number "${answer[1]}")" 96
    expect "$(number "${answer[2]}")" 102
    expect "$(number "${answer[3]}")" 12
    expect "$(number "${answer[4]}")" "$2"
    expect "$(number "${answer[5]}")" 4
    if [[ $1 == false ]]; then
        [[ "${answer[6]}" =~ ^\"?Node-[[:alnum:]]+\"?$ ]]
    fi
    printf '%s\n' "$output"
}
check_balance true 4
read_node 1 'set_tamper(uint64)(bool)' 500 >/dev/null
trap 'read_node 1 "set_tamper(uint64)(bool)" 0 >/dev/null || true' EXIT
check_balance false 3

# ABI words: root, count, index, array offset, array length, then two siblings.
proof=$(read_node 0 'prove_event(uint64)' 5)
[[ "$proof" =~ ^0x[0-9a-fA-F]{448}$ ]]
path="[0x${proof:322:64},0x${proof:386:64}]"
verify='verify_event(uint64,address,uint64,uint8,bytes32[])(bool)'
expect "$(read_node 0 "$verify" 5 "$account" 16 1 "$path")" true
expect "$(read_node 0 "$verify" 5 "$account" 17 1 "$path")" false

head=$(read_node 0 'commitment_head()')
send 'dispute(uint64,bytes32)' 2 "0x$(printf '%064d' 0)"
wait_for_number 1 0 'dispute_count(uint64)(uint64)' 2
expect "$(number "$(read_node 0 'dispute_count(uint64)(uint64)' 1)")" 0
expect "$(read_node 0 'commitment_head()')" "$head"
echo 'PASS: historical totals, UPC divergence, anchored proof and dispute'
