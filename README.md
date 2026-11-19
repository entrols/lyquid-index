# LyquidIndex — Verifiable Historical Indexing on Lyquor

CS5298 Blockchain and Web3.0 Security — Final Project, Direction 3 (Verifiable Indexer)

Author: **Jia Wenrui** · Student ID: **60851180**

---

## What this is

`LyquidIndex` is an original Lyquid application that gives stablecoin / RWA issuers a
historical account-flow index whose answers can be *independently falsified*:

1. **Layered commitment** — the consensus (`network`) layer stores only the canonical
   event log, one Merkle commitment per `window_size` events, and a hash chain over
   those commitments. Everything else (aggregates, leaves, audit paths, divergence log)
   lives in per-node `instance` state and is recomputable on demand.
   The canonical log grows per event and adds one commitment per full window.

2. **UPC recomputation** — `verified_balance` fans a query out to every registered
   indexer over UPC. Each node replays the sealed event prefix and reports the figures plus its local
   root. The initiator counts only replies matching the consensus window and root,
   and returns figures only when more than half the configured nodes agree.

3. **FCO-pinned disputes** — because FCO fixes one global order, "the commitment for
   window W" is a uniquely addressable object. `dispute(W, claimed_root)` pins an
   accusation to that coordinate; the head of the commitment chain is never rewritten.

## Directory layout

```
Cargo.toml            lyquid 0.8.4 (feature "ldk"), serde/serde_json; dev-dep lyquid-test
build.rs              exports __stack_pointer for the wasm guest
rust-toolchain.toml   channel 1.99.0, target wasm32-unknown-unknown
.cargo/config.toml    default build target = wasm32
src/lib.rs            the Lyquid: 5 network + 15 instance methods, UPC 3-stage query
src/merkle.rs         domain-separated blake3 Merkle tree + seal() + chain_next()
docs/e2e-result.txt   transcript of the four-node devnet experiment (raw evidence)
```

## The design decision worth reading first

`src/merkle.rs::seal` binds the leaf count into the published commitment:

```
seal(tree_top, leaf_count) = blake3(0x04 || leaf_count || tree_top)
```

With promote-odd collapsing the tree *shape* depends on the leaf count. A commitment
that stores only the tree top lets a prover hand over a shorter path plus a smaller
`leaf_count` and still pass verification: for a 6-leaf window, indices 0–3 are
indistinguishable between the 5-leaf and 6-leaf width sequences. Folding the count into
the hash makes any disagreement about the count change the commitment, and a forged
count is then rejected for *every* index. This was found by a failing test, confirmed
with a per-index probe, and fixed at the hash level.

## How to run

### Build

```bash
cargo build --release          # produces target/wasm32-unknown-unknown/release/lyquid_index.wasm
```

### Guest unit tests

```bash
shaker test Cargo.toml         # wasm guest runtime
```

Note: guest tests must go through `shaker test`. A test binary built directly with
`cargo test --no-run` lacks the heap-boundary exports (`__heap_base` / `__heap_end`
at 0x20000000) the guest loader requires.

### Native algorithm checks

`src/merkle.rs` has no Lyquor dependency except `B256`; it was verified natively in a
separate harness (19 assertions) covering empty/single windows, domain separation,
all-leaf proofs for sizes 1–16, manual promote-odd construction, tamper detection
(sibling / index / leaf count / root), chain order sensitivity, reordering, and
extra-event inclusion.

### Devnet end-to-end

```bash
# four nodes, shared anvil; no Docker required
bash <ldk>/scripts/localnet.sh multi

# deploy
shaker deploy --endpoint ws://127.0.0.1:10087/ws \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  --debug --output json \
  --reference http://127.0.0.1:10087/lyquids:lyquid-index Cargo.toml
```

From a shell with Foundry `cast` installed, supply each node's RPC URL and its
32-byte hex ID (with `0x` prefix). Use a fresh deployment for each run. The key
must belong to the funded local deployer.

```bash
export LYQUID_ADDRESS=<deployed-address>
export PRIVATE_KEY=<funded-local-deployer-key>
bash scripts/e2e.sh "$RPC1" "$NODE1" "$RPC2" "$NODE2" "$RPC3" "$NODE3" "$RPC4" "$NODE4"
```

A passing run prints `PASS` after checking historical totals, 4/4 agreement,
3/4 agreement with one modified response, inclusion proof acceptance and
rejection, and a dispute that preserves the commitment head. The previous
run in `docs/e2e-result.txt` used a different fixture.

`get_balance` reads the live local aggregate. `historical_balance` replays through
a selected sealed window. `verified_balance` replays through the latest sealed
window, returning zero totals when there is no strict majority. Check
`agreeing > total / 2` before consuming totals. `agreed` means unanimity.
Only complete windows with canonical roots can be sealed.

### Calling convention (important)

Mutable **instance** methods (`set_tamper`) must be invoked with `cast call`
(eth_call), **not** `cast send`. A sequenced transaction commits network state only;
the per-node instance write is applied by the node that serves the call. `cast send`
returns a successful receipt and silently drops the write. Network methods
(`configure_indexers`, `ingest`, `seal_window`, `dispute`) do go through `cast send`.

Node IDs are RFC4648 lowercase base32 (`Node-` prefix, 35 bytes = 32 id + 2 checksum +
1 version byte); `configure_indexers` takes them as `bytes32[]`, i.e. the first 32
bytes of the base32 decoding.

## Recorded results from the earlier four-node localnet run

| Check | Result |
| --- | --- |
| Native algorithm assertions | 19 / 19 |
| Guest unit tests (`shaker test`) | 6 / 6 |
| Honest query: `agreed`, `agreeing/total` | true, 4 / 4 |
| Query after tampering node 2 only | `agreed=false`, 3 / 4, divergent = node 2 |
| `self_check` (audit-path re-verification) | 12 checked, 0 failures |
| `dispute(2, wrong_root)` | `dispute_count(2) = 1`; control window 1 stays 0 |
| UPC round-trip latency | 68–183 ms for 4 nodes |

## Known limitations

- Majority voting assumes an honest majority; the indexer set is a governance property.
- Divergence is demonstrated via a per-node fault-injection knob, not organic drift.
- Aggregates and roots are compared; an uncovered individual leaf could still differ.
- The recorded test used four loopback nodes. Wide-area latency and restart recovery remain unmeasured.
- Historical queries replay the full sealed prefix. The Merkle proof authenticates an individual event. Aggregate correctness still relies on recomputation and the UPC quorum.
