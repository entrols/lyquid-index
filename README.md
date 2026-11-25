# LyquidIndex — Verifiable Historical Indexing on Lyquor

CS5298 Blockchain and Web3.0 Security — Final Project, Direction 3 (Verifiable Indexer)

Group: **Final Project Group 10**
Author: **Jia Wenrui** · Student ID: **60851180**
Author: **Li Muen** · Student ID: **60659117**

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

4. **Bounded historical features** — `verified_flow_features` asks every indexer to
   recompute an account's inflow, outflow, event count, active-window count, and peak
   per-window outflow across a requested sealed range. The answer is bound to the
   commitment-chain root at the range endpoint, so it cannot be reused for another
   historical prefix.

## Directory layout

```
Cargo.toml            lyquid 0.8.4 (feature "ldk"), serde/serde_json; dev-dep lyquid-test
build.rs              exports __stack_pointer for the wasm guest
rust-toolchain.toml   channel 1.99.0, target wasm32-unknown-unknown
.cargo/config.toml    default build target = wasm32
src/lib.rs            the Lyquid: 5 network + 18 instance methods, UPC 3-stage queries
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

For the automated two-run reproduction, start the four-node native devnet
(`bash <ldk>/scripts/localnet.sh multi`) in a separate terminal. With
`shaker`, `cast`, `curl`, and Python 3 available, run:

```bash
bash scripts/reproduce-twice.sh
```

The runner discovers the four local nodes, deploys a fresh contract for each
run, and waits for each node to serve the new contract before sending test
transactions. The end-to-end script waits for index and checkpoint updates
before asserting values. Each run writes its deployment and test logs to a
new `docs/reproduction-twice.*` directory. The final check requires separate
contract addresses and identical end-to-end output. It uses the public default
Anvil devnet key unless `PRIVATE_KEY` is set.

For a single manual run, use the steps below. Wait until each node can call
`commitment_head()` on the fresh contract before starting the script.


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

A passing run prints `PASS` after checking a bounded historical feature vector with
4/4 agreement, 3/4 agreement after one modified feature response, historical totals,
balance divergence, inclusion proof acceptance and rejection, and a dispute that
preserves the commitment head. The previous
run in `docs/e2e-result.txt` used a different fixture.

`get_balance` reads the live local aggregate. `historical_balance` replays through
a selected sealed window. `verified_balance` replays through the latest sealed
window, returning zero totals when there is no strict majority. Check
`agreeing > total / 2` before consuming totals. `agreed` means unanimity.
Only complete windows with canonical roots can be sealed.

`flow_features(account, first_window, last_window)` reads a node's private
per-account/per-window index over an inclusive sealed range.
`verified_flow_features` returns the same five figures only if a strict UPC majority
reports the requested range and the consensus chain root at `last_window`; it reports
zero figures with no majority. This demonstrates a composable historical input rather
than a spot oracle value.

### Calling convention (important)

Mutable **instance** methods (`set_tamper`, `set_feature_tamper`) must be invoked with `cast call`
(eth_call), **not** `cast send`. A sequenced transaction commits network state only;
the per-node instance write is applied by the node that serves the call. `cast send`
returns a successful receipt and silently drops the write. Network methods
(`configure_indexers`, `ingest`, `seal_window`, `dispute`) do go through `cast send`.

Node IDs are RFC4648 lowercase base32 (`Node-` prefix, 35 bytes = 32 id + 2 checksum +
1 version byte); `configure_indexers` takes them as `bytes32[]`, i.e. the first 32
bytes of the base32 decoding.

## Recorded results for the historical range release

| Check | Result |
| --- | --- |
| Guest unit tests | 9 passed, 0 failed |
| Fresh four-node deployments | Two distinct contracts, identical end-to-end test output |
| Range [0, 2] | 96 in, 102 out, 12 events, 3 active windows, peak outflow 42 |
| Range quorum under a simulated peak outflow fault | 3 / 4, node 2 identified, majority peak remains 42 |
| Individual proof and dispute recording | Original amount accepted, changed amount rejected, commitment head unchanged |

The [first run](docs/interval-reproduction/e2e-1.log), [second run](docs/interval-reproduction/e2e-2.log)
and [guest tests](docs/interval-guest-test.log) are from this release. Earlier baseline runs are
retained in `docs/e2e-result.txt` and `docs/latest-e2e.log`.

## Known limitations

- Majority voting assumes an honest majority; the indexer set is a governance property.
- Divergence is demonstrated via a per-node fault-injection knob, not organic drift.
- Aggregates and roots are compared; an uncovered individual leaf could still differ.
- The recorded test used four loopback nodes. Wide-area latency and restart recovery remain unmeasured.
- Historical balance queries replay the full sealed prefix; bounded feature queries use
  private per-window aggregates. The Merkle proof authenticates an individual event.
  Aggregate correctness still relies on recomputation and the UPC quorum.
