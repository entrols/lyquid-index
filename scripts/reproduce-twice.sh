#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.shakenup/bin:$HOME/.cargo/bin:$PATH"
runner_dir=$(cd -- "$(dirname -- "$0")" && pwd)
cd -- "$runner_dir/.."

for tool in shaker cast curl python3; do
  command -v "$tool" >/dev/null
done
# Default key for the first account on the local Anvil devnet.
export PRIVATE_KEY="${PRIVATE_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"

ports=(10087 11087 12087 13087)
args=()
for port in "${ports[@]}"; do
  id=$(curl -fsS --max-time 5 -H 'Content-Type: application/json' -d '{}' \
    "http://127.0.0.1:$port/lyquor.node.v1.NodeService/GetNodeInfo" |
    python3 -c 'import base64,json,sys; d=json.load(sys.stdin); s=(d.get("nodeId") or d["node_id"])["value"][5:].upper(); print("0x"+base64.b32decode(s+"="*(-len(s)%8))[:32].hex())')
  args+=("ws://127.0.0.1:$port/ws" "$id")
done

wait_for_contract() {
  local port endpoint deadline response
  printf 'Waiting for the new contract on all four nodes...\n'
  for port in "${ports[@]}"; do
    endpoint="ws://127.0.0.1:$port/ws"
    deadline=$((SECONDS + 60))
    until response=$(cast call --rpc-url "$endpoint" --rpc-timeout 5 \
      "$LYQUID_ADDRESS" 'commitment_head()(bytes32,uint64)' 2>&1); do
      if (( SECONDS >= deadline )); then
        printf 'Contract unavailable on %s after 60 seconds: %s\n' "$endpoint" "$response" >&2
        return 1
      fi
      sleep 1
    done
    printf 'Ready: %s\n' "$endpoint"
  done
}

log_dir=$(mktemp -d docs/reproduction-twice.XXXXXX)
printf 'Log directory: %s/%s\n' "$PWD" "$log_dir"
first_address=""

for run in 1 2; do
  printf '\n=== Run %s of 2 ===\n' "$run"
  deployment=$(shaker deploy --endpoint ws://127.0.0.1:10087/ws \
    --private-key "$PRIVATE_KEY" --debug --output json \
    --reference http://127.0.0.1:10087/lyquids:lyquid-index Cargo.toml \
    2> >(tee "$log_dir/deploy-$run.log" >&2))
  printf '%s\n' "$deployment" > "$log_dir/deploy-$run.json"
  LYQUID_ADDRESS=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["contract"])' <<< "$deployment")
  export LYQUID_ADDRESS
  if [[ $run == 1 ]]; then
    first_address=$LYQUID_ADDRESS
  elif [[ ${LYQUID_ADDRESS,,} == "${first_address,,}" ]]; then
    printf 'Second deployment returned the same address. Stopping before writing test data.\n' >&2
    exit 1
  fi
  printf 'Contract: %s\n' "$LYQUID_ADDRESS"
  wait_for_contract
  bash "$runner_dir/e2e.sh" "${args[@]}" 2>&1 | tee "$log_dir/e2e-$run.log"
done

diff -u "$log_dir/e2e-1.log" "$log_dir/e2e-2.log" |
  tee "$log_dir/comparison.log"
printf '\nPASS: both runs used different contracts and produced identical end-to-end output.\n'
