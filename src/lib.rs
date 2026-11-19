//! # LyquidIndex — a verifiable, commitment-anchored index for Lyquor
//!
//! `LyquidIndex` turns an append-only event log into a *verifiable* secondary index: the
//! canonical events and one Merkle commitment per fixed-size window live in `network`
//! state, while the derived aggregates and the Merkle leaves live in per-node `instance`
//! state. Nobody has to trust a single operator, because any node (or any client holding
//! the event log) can recompute the index and check it against the committed root chain.
//!
//! ## Why this split
//!
//! * `network` (sequenced, consensus) keeps only what must be agreed by everyone: the
//!   event log, the per-window roots, and the hash-chained commitment head. The log
//!   grows per event, and commitments grow per window.
//! * `instance` (per-node, off-chain) keeps everything else: account aggregates, the
//!   Merkle leaf arrays and the audit paths. This is what lets the Lyquid index data that
//!   would be far too large to keep in sequenced state.
//!
//! ## The three Lyquor-specific mechanisms used
//!
//! 1. **Two-layer commitment.** `build_index` derives per-window Merkle roots off-chain;
//!    `seal_window` records them on-chain and chains them (`chain_root`), so dropping,
//!    reordering or rewriting a window stays detectable forever afterwards.
//! 2. **UPC multi-node re-computation.** `verified_balance` broadcasts a UPC to every
//!    registered indexer. Each indexer replays the sealed history and returns
//!    its aggregate plus its own view of the newest window root. The initiator folds
//!    the answers by majority rule and reports the exact set of divergent nodes.
//! 3. **FCO-anchored dispute.** Because FCO gives the network one global order, a reported
//!    divergence can be pinned to a specific window id plus the commitment recorded for
//!    that window — `dispute` stores that pin, so the accusation is decidable rather than
//!    a he-said-she-said argument about whose log is authoritative.
//!
//! ## Test-only fault injection
//!
//! `set_tamper` deliberately corrupts *only this node's* answers. It is documented as a
//! demo hook for the divergence-detection experiment and never touches network state.

use lyquid::lyquor_primitives::B256;
use lyquid::prelude::*;
use serde::{Deserialize, Serialize};

mod merkle;

use merkle::{chain_next, hash_leaf, proof as merkle_proof, verify as merkle_verify};

// Number of events committed per window when the deployer does not override it.
pub const DEFAULT_WINDOW_SIZE: u64 = 4;

// One canonical event in the index source log.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventRecord {
    // Account the event belongs to.
    pub account: Address,
    // Amount moved (satoshi-like integer units).
    pub amount: u64,
    // Event kind: 0 = inflow, 1 = outflow.
    pub kind: u8,
}

// Derived per-account aggregate held only in instance state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountAgg {
    // Sum of inflow events.
    pub inflow: u64,
    // Sum of outflow events.
    pub outflow: u64,
    // Number of events seen.
    pub count: u64,
    // Sequence number of the last event folded in.
    pub last_seq: u64,
}

// On-chain commitment for one window.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct WindowCommit {
    // Merkle root over the window's event leaves.
    pub merkle_root: B256,
    // Number of leaves in the window (needed to verify promote-odd paths).
    pub leaf_count: u64,
    // Hash-chain head *after* folding this window in.
    pub chain_root: B256,
    // Caller that sealed the window.
    pub sealed_by: Address,
}

// The UPC answer envelope. It is used for two roles with the same wire type, because the
// UPC response handler must decode exactly the type the request handler produced and must
// return exactly the type the initiator decodes.
//
// * as a *node answer*: one indexer's own figures, `total = 1`, `agreed` unset;
// * as a *verdict*: the majority fold computed by the initiator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexAnswer {
    // Node that produced this answer (or the initiator, for a verdict).
    pub responder: NodeID,
    // Inflow total reported by this node.
    pub inflow: u64,
    // Outflow total reported by this node.
    pub outflow: u64,
    // Number of events this node indexed.
    pub count: u64,
    // This node's view of the newest window root.
    pub window_root: B256,
    // Which window `window_root` refers to.
    pub window_id: u64,
    // Whether this node flagged its own answer as deliberately corrupted.
    pub tampered: bool,
    // Set on a verdict: whether every responder agreed.
    pub agreed: bool,
    // Set on a verdict: responders matching the majority.
    pub agreeing: u32,
    // Set on a verdict: responders observed.
    pub total: u32,
    // Set on a verdict: comma-separated divergent node ids.
    pub divergent: String,
    // Set on a verdict: comma-separated self-flagged tampered node ids.
    pub flagged: String,
}

impl Default for IndexAnswer {
    fn default() -> Self {
        Self {
            responder: NodeID::from([0u8; 32]),
            inflow: 0,
            outflow: 0,
            count: 0,
            window_root: B256::ZERO,
            window_id: 0,
            tampered: false,
            agreed: false,
            agreeing: 0,
            total: 0,
            divergent: String::new(),
            flagged: String::new(),
        }
    }
}

// Accumulator kept inside the UPC continuation cache across response callbacks.
#[derive(Debug, Clone)]
pub struct Tally {
    expected: u32,
    answers: Vec<IndexAnswer>,
    failed: Vec<NodeID>,
    commitment: Option<(u64, B256)>,
}

impl Tally {
    // Creates a tally that completes after `expected` answers.
    pub fn new(expected: u32) -> Self {
        Self {
            expected,
            answers: Vec::new(),
            failed: Vec::new(),
            commitment: None,
        }
    }

    fn ready(&self) -> bool {
        self.expected > 0 && self.answers.len() + self.failed.len() >= self.expected as usize
    }

    // Folds the observations into a majority-rule verdict.
    fn verdict(&self) -> IndexAnswer {
        let key = |a: &IndexAnswer| (a.window_id, a.window_root, a.inflow, a.outflow, a.count);
        let mut votes = std::collections::BTreeMap::new();
        for answer in &self.answers {
            if self.commitment == Some((answer.window_id, answer.window_root)) {
                *votes.entry(key(answer)).or_insert(0u32) += 1;
            }
        }
        let winner = votes.into_iter().max_by_key(|(_, count)| *count);
        let agreeing = winner.as_ref().map_or(0, |(_, count)| *count);
        let majority = winner.filter(|(_, count)| *count > self.expected / 2);
        let mut divergent: Vec<_> = self.failed.iter().map(ToString::to_string).collect();
        let mut flagged = Vec::new();
        for answer in &self.answers {
            if majority.as_ref().map(|(winner, _)| *winner) != Some(key(answer)) {
                divergent.push(answer.responder.to_string());
            }
            if answer.tampered {
                flagged.push(answer.responder.to_string());
            }
        }
        divergent.sort();
        flagged.sort();
        let (window_id, window_root, inflow, outflow, count) =
            majority.map(|(winner, _)| winner).unwrap_or_default();

        IndexAnswer {
            window_id,
            window_root,
            inflow,
            outflow,
            count,
            agreeing,
            agreed: agreeing == self.expected && self.expected > 0,
            tampered: !flagged.is_empty(),
            total: self.expected,
            divergent: divergent.join(","),
            flagged: flagged.join(","),
            ..IndexAnswer::default()
        }
    }
}

state! {
    // ---- Sequenced (consensus) state: small, must be identical on every node. ----
    network initializer: Address = Address::ZERO;
    network window_size: u64 = 4;
    network events: Vec<EventRecord> = Vec::new();
    network commits: HashMap<u64, WindowCommit> = new_hashmap();
    network latest_window: u64 = 0;
    network chain_root: B256 = B256::ZERO;
    network indexers: Vec<NodeID> = Vec::new();
    network disputes: HashMap<u64, u64> = new_hashmap();

    // ---- Off-chain (per-node) state: the actual index. ----
    instance cursor: u64 = 0;
    instance agg: HashMap<Address, AccountAgg> = new_hashmap();
    instance leaves: HashMap<u64, Vec<B256>> = new_hashmap();
    instance built_windows: u64 = 0;
    instance mismatches: Vec<String> = Vec::new();
    instance tamper_amount: u64 = 0;
}

// ---------------------------------------------------------------------------
// Sequenced entry points
// ---------------------------------------------------------------------------

// Sets the operator address at deploy time.
#[method::network(export = eth)]
fn constructor(ctx: &mut _) {
    *ctx.network.initializer = ctx.caller;
}

// Registers the node set that UPC queries fan out to, plus the window size.
#[method::network(export = eth)]
fn configure_indexers(ctx: &mut _, node_ids: Vec<NodeID>, window_size: u64) -> LyquidResult<bool> {
    if ctx.caller != *ctx.network.initializer {
        return Err(LyquidError::LyquidRuntime(
            "only the initializer may configure indexers".into(),
        ));
    }
    if node_ids.is_empty() {
        return Err(LyquidError::LyquidRuntime(
            "indexer set cannot be empty".into(),
        ));
    }
    if window_size == 0 {
        return Err(LyquidError::LyquidRuntime(
            "window size must be positive".into(),
        ));
    }
    if !ctx.network.events.is_empty() && window_size != *ctx.network.window_size {
        return Err(LyquidError::LyquidRuntime(
            "window size is fixed after ingestion".into(),
        ));
    }
    let unique: std::collections::HashSet<_> = node_ids.iter().collect();
    if unique.len() != node_ids.len() {
        return Err(LyquidError::LyquidRuntime("duplicate indexer".into()));
    }
    *ctx.network.indexers = node_ids;
    *ctx.network.window_size = window_size;
    Ok(true)
}

// Appends one canonical event and schedules an off-chain index rebuild after the commit.
#[method::network(export = eth)]
fn ingest(ctx: &mut _, account: Address, amount: u64, kind: u8) -> LyquidResult<u64> {
    if kind > 1 {
        return Err(LyquidError::LyquidRuntime(
            "kind must be 0 (inflow) or 1 (outflow)".into(),
        ));
    }
    if amount == 0 {
        return Err(LyquidError::LyquidRuntime("amount must be positive".into()));
    }
    let seq = ctx.network.events.len() as u64;
    ctx.network.events.push(EventRecord {
        account,
        amount,
        kind,
    });
    // Every hosting node refreshes its own off-chain index once this slot commits.
    trigger!(build_index(), TriggerMode::Commit);
    Ok(seq)
}

// Seals one window: stores its Merkle root and folds it into the commitment chain.
#[method::network(export = eth)]
fn seal_window(
    ctx: &mut _,
    window_id: u64,
    window_root: B256,
    leaf_count: u64,
) -> LyquidResult<bool> {
    if ctx.caller != *ctx.network.initializer {
        return Err(LyquidError::LyquidRuntime(
            "only the initializer may seal windows".into(),
        ));
    }
    if window_id != *ctx.network.latest_window {
        return Err(LyquidError::LyquidRuntime(format!(
            "window {} is out of order, expected {}",
            window_id, *ctx.network.latest_window
        )));
    }
    let size = *ctx.network.window_size;
    if leaf_count != size || window_id >= ctx.network.events.len() as u64 / size {
        return Err(LyquidError::LyquidRuntime(
            "only complete windows can be sealed".into(),
        ));
    }
    let start = window_id * size;
    let leaves: Vec<_> = (start..start + size)
        .map(|seq| leaf_of(seq, &ctx.network.events[seq as usize]))
        .collect();
    if merkle::root(&leaves) != window_root {
        return Err(LyquidError::LyquidRuntime(
            "root does not match canonical events".into(),
        ));
    }

    let previous = *ctx.network.chain_root;
    let next = chain_next(previous, window_id, window_root, leaf_count);
    ctx.network.commits.insert(
        window_id,
        WindowCommit {
            merkle_root: window_root,
            leaf_count,
            chain_root: next,
            sealed_by: ctx.caller,
        },
    );
    *ctx.network.chain_root = next;
    *ctx.network.latest_window = window_id + 1;

    trigger!(build_index(), TriggerMode::Commit);
    log!(window_sealed, &(window_id, window_root, next));
    Ok(true)
}

// Records a dispute against one already-committed window.
//
// Because FCO fixes a single global order, the disputed window id identifies an exact,
// universally agreed position, so the accusation is decidable instead of being a matter of
// "whose log is right".
#[method::network(export = eth)]
fn dispute(ctx: &mut _, window_id: u64, claimed_root: B256) -> LyquidResult<bool> {
    let Some(committed) = ctx.network.commits.get(&window_id).copied() else {
        return Err(LyquidError::LyquidRuntime(format!(
            "window {} is not committed",
            window_id
        )));
    };
    if committed.merkle_root == claimed_root {
        return Err(LyquidError::LyquidRuntime(
            "claimed root matches the commitment; nothing to dispute".into(),
        ));
    }
    let entry = ctx.network.disputes.entry(window_id).or_insert(0);
    *entry += 1;
    log!(
        window_disputed,
        &(window_id, claimed_root, committed.merkle_root)
    );
    Ok(true)
}

// ---------------------------------------------------------------------------
// Off-chain (instance) index construction, proofs and lookups
// ---------------------------------------------------------------------------

// Rebuilds this node's index from the canonical event log.
//
// Idempotent: it only folds events at or after `cursor`, so repeated invocations stay cheap.
#[method::instance(export = eth)]
fn build_index(ctx: &mut _) -> LyquidResult<u64> {
    let event_count = ctx.network.events.len() as u64;
    let window_size = {
        let size = *ctx.network.window_size;
        if size == 0 { DEFAULT_WINDOW_SIZE } else { size }
    };

    let mut cursor = *ctx.instance.cursor.read();
    let mut built = *ctx.instance.built_windows.read();
    {
        let mut agg = ctx.instance.agg.write();
        let mut leaves = ctx.instance.leaves.write();

        while cursor < event_count {
            let seq = cursor;
            let event = ctx.network.events[seq as usize];
            let window_id = seq / window_size;

            let leaf = leaf_of(seq, &event);
            leaves.entry(window_id).or_default().push(leaf);

            let entry = agg.entry(event.account).or_default();
            if event.kind == 0 {
                entry.inflow = entry.inflow.saturating_add(event.amount);
            } else {
                entry.outflow = entry.outflow.saturating_add(event.amount);
            }
            entry.count += 1;
            entry.last_seq = seq;

            cursor += 1;
        }
    }

    // Re-derive every closed window root and compare it against the on-chain commitment.
    let closed = *ctx.network.latest_window;
    built = built.min(closed);
    while built < closed {
        let local_root = {
            let leaves = ctx.instance.leaves.read();
            let window_leaves = leaves.get(&built).cloned().unwrap_or_default();
            merkle::root(&window_leaves)
        };
        if let Some(commit) = ctx.network.commits.get(&built).copied() {
            if commit.merkle_root != local_root {
                let message = format!(
                    "window {} local {} != committed {}",
                    built, local_root, commit.merkle_root
                );
                lyquid::println!("LyquidIndex: {message}");
                ctx.instance.mismatches.write().push(message);
            }
        }
        built += 1;
    }

    *ctx.instance.cursor.write() = cursor;
    *ctx.instance.built_windows.write() = built;
    Ok(built)
}

// Returns this node's aggregate for one account.
#[method::instance(export = eth)]
fn get_balance(ctx: &_, account: Address) -> LyquidResult<(u64, u64, u64)> {
    let agg = ctx.instance.agg.read();
    let entry = agg.get(&account).copied().unwrap_or_default();
    Ok((entry.inflow, entry.outflow, entry.count))
}

// Returns this node's Merkle root for one window.
#[method::instance(export = eth)]
fn local_window_root(ctx: &_, window_id: u64) -> LyquidResult<(B256, u64)> {
    let leaves = ctx.instance.leaves.read();
    let window = leaves.get(&window_id).cloned().unwrap_or_default();
    Ok((merkle::root(&window), window.len() as u64))
}

// Returns account totals through the end of a selected committed window.
#[method::instance(export = eth)]
fn historical_balance(ctx: &_, account: Address, window_id: u64) -> LyquidResult<(u64, u64, u64)> {
    if !ctx.network.commits.contains_key(&window_id) {
        return Err(LyquidError::LyquidRuntime("window is not committed".into()));
    }
    let end = sealed_end(
        *ctx.network.window_size,
        window_id,
        ctx.network.events.len(),
    )
    .ok_or_else(|| LyquidError::LyquidRuntime("sealed window is incomplete".into()))?;
    Ok(fold_account(&ctx.network.events[..end], account))
}

// Checks supplied event data and its path against the consensus commitment.
#[method::instance(export = eth)]
fn verify_event(
    ctx: &_,
    seq: u64,
    account: Address,
    amount: u64,
    kind: u8,
    path: Vec<B256>,
) -> LyquidResult<bool> {
    let size = *ctx.network.window_size;
    let Some(commit) = ctx.network.commits.get(&(seq / size)) else {
        return Ok(false);
    };
    let event = EventRecord {
        account,
        amount,
        kind,
    };
    Ok(merkle_verify(
        commit.merkle_root,
        leaf_of(seq, &event),
        seq % size,
        commit.leaf_count,
        &path,
    ))
}

// Returns the on-chain commitment for one window.
#[method::instance(export = eth)]
fn get_commit(ctx: &_, window_id: u64) -> LyquidResult<(B256, u64, B256)> {
    let commit = ctx
        .network
        .commits
        .get(&window_id)
        .copied()
        .unwrap_or_default();
    Ok((commit.merkle_root, commit.leaf_count, commit.chain_root))
}

// Returns the commitment head: current chain root and the next window id to seal.
#[method::instance(export = eth)]
fn commitment_head(ctx: &_) -> LyquidResult<(B256, u64)> {
    Ok((*ctx.network.chain_root, *ctx.network.latest_window))
}

// Builds an inclusion proof for event `seq` from this node's own leaves.
#[method::instance(export = eth)]
fn prove_event(ctx: &_, seq: u64) -> LyquidResult<(B256, u64, u64, Vec<B256>)> {
    let window_size = {
        let size = *ctx.network.window_size;
        if size == 0 { DEFAULT_WINDOW_SIZE } else { size }
    };
    let window_id = seq / window_size;
    let leaves = ctx.instance.leaves.read();
    let window = leaves.get(&window_id).cloned().unwrap_or_default();
    let index = (seq % window_size) as usize;
    if window.is_empty() || index >= window.len() {
        return Err(LyquidError::LyquidRuntime(format!(
            "event {} is not indexed on this node yet",
            seq
        )));
    }
    let root = merkle::root(&window);
    let path = merkle_proof(&window, index)
        .ok_or_else(|| LyquidError::LyquidRuntime("no audit path for this event".into()))?;
    Ok((root, window.len() as u64, index as u64, path))
}

// Re-verifies every local window with the audit-path machinery.
//
// This is the same check an external auditor runs, so it doubles as a self-test.
#[method::instance(export = eth)]
fn self_check(ctx: &_) -> LyquidResult<(u64, u64)> {
    let leaves = ctx.instance.leaves.read();
    let mut checked = 0u64;
    let mut failures = 0u64;
    let mut window_ids: Vec<u64> = leaves.keys().copied().collect();
    window_ids.sort_unstable();
    for window_id in window_ids {
        let window = leaves.get(&window_id).cloned().unwrap_or_default();
        let root = merkle::root(&window);
        for index in 0..window.len() {
            let Some(path) = merkle_proof(&window, index) else {
                failures += 1;
                continue;
            };
            checked += 1;
            if !merkle_verify(
                root,
                window[index],
                index as u64,
                window.len() as u64,
                &path,
            ) {
                failures += 1;
            }
        }
    }
    Ok((checked, failures))
}

// Returns the local divergence log (committed roots that did not match local leaves).
#[method::instance(export = eth)]
fn get_mismatches(ctx: &_) -> LyquidResult<Vec<String>> {
    Ok(ctx.instance.mismatches.read().clone())
}

// Demo-only fault injection: makes this node over-report one account's inflow.
//
// Only instance state is touched, so exactly one node diverges - which is precisely the
// setup the UPC consensus path has to detect.
//
// NOTE: mutable instance methods must be invoked with `cast call` (eth_call), not `cast send`.
// A sequenced transaction only commits network state; the per-node instance write is applied by
// the node that serves the call.
#[method::instance(export = eth)]
fn set_tamper(ctx: &mut _, amount: u64) -> LyquidResult<bool> {
    *ctx.instance.tamper_amount.write() = amount;
    lyquid::println!(
        "LyquidIndex: node {} armed tamper of {}",
        ctx.node_id,
        amount
    );
    Ok(true)
}

// Diagnostic read-back of the per-node fault-injection knob.
#[method::instance(export = eth)]
fn tamper_state(ctx: &_) -> LyquidResult<u64> {
    Ok(*ctx.instance.tamper_amount.read())
}

// Diagnostic read-back of how far this node's index has been built.
#[method::instance(export = eth)]
fn index_cursor(ctx: &_) -> LyquidResult<u64> {
    Ok(*ctx.instance.cursor.read())
}

// ---------------------------------------------------------------------------
// UPC: independent re-computation on every indexer
// ---------------------------------------------------------------------------

// UPC callee selection: fan out to every registered indexer.
//
// The continuation cache is seeded here so the aggregate handler knows how many answers to
// wait for before concluding.
#[method::instance(upc(prepare))]
fn q_balance(ctx: &_) -> LyquidResult<Vec<NodeID>> {
    let targets: Vec<NodeID> = ctx.network.indexers.clone();
    if targets.is_empty() {
        return Err(LyquidError::LyquidRuntime(
            "no indexers configured for UPC queries".into(),
        ));
    }
    let window_id = ctx
        .network
        .latest_window
        .checked_sub(1)
        .ok_or_else(|| LyquidError::LyquidRuntime("no sealed window".into()))?;
    let commit = ctx
        .network
        .commits
        .get(&window_id)
        .ok_or_else(|| LyquidError::LyquidRuntime("missing window commitment".into()))?;
    let mut tally = Tally::new(targets.len() as u32);
    tally.commitment = Some((window_id, commit.merkle_root));
    ctx.cache.set(tally);
    Ok(targets)
}

// UPC request handler: replay the sealed prefix and check this node's index progress.
#[method::instance(upc(request))]
fn q_balance(ctx: &mut _, account: Address) -> LyquidResult<IndexAnswer> {
    let window_id = ctx
        .network
        .latest_window
        .checked_sub(1)
        .ok_or_else(|| LyquidError::LyquidRuntime("no sealed window".into()))?;
    let end = sealed_end(
        *ctx.network.window_size,
        window_id,
        ctx.network.events.len(),
    )
    .ok_or_else(|| LyquidError::LyquidRuntime("sealed window is incomplete".into()))?;
    if *ctx.instance.cursor.read() < end as u64 {
        return Err(LyquidError::LyquidRuntime(
            "local index is behind the sealed window".into(),
        ));
    }
    let (inflow, outflow, count) = fold_account(&ctx.network.events[..end], account);
    let tamper = *ctx.instance.tamper_amount.read();
    let window = ctx
        .instance
        .leaves
        .read()
        .get(&window_id)
        .cloned()
        .unwrap_or_default();

    Ok(IndexAnswer {
        responder: ctx.node_id,
        inflow: inflow.saturating_add(tamper),
        outflow,
        count,
        window_root: merkle::root(&window),
        window_id,
        tampered: tamper != 0,
        agreed: false,
        agreeing: 1,
        total: 1,
        divergent: String::new(),
        flagged: String::new(),
    })
}

// UPC aggregate: folds one answer into the majority tally.
//
// Returns `None` while answers are still missing and `Some(verdict)` as soon as the
// expected number of answers has arrived; that verdict is what the initiator receives.
#[method::instance(upc(response))]
fn q_balance(ctx: &_, response: LyquidResult<IndexAnswer>) -> LyquidResult<Option<IndexAnswer>> {
    let tally = ctx.cache.get_mut_or_init(|| Tally::new(0));
    if tally
        .answers
        .iter()
        .any(|answer| answer.responder == ctx.from)
        || tally.failed.contains(&ctx.from)
    {
        return Ok(None);
    }
    match response {
        Ok(mut answer) => {
            answer.responder = ctx.from;
            tally.answers.push(answer);
        }
        Err(err) => {
            lyquid::println!("LyquidIndex: UPC responder {} failed: {err}", ctx.from);
            tally.failed.push(ctx.from);
        }
    }
    if tally.ready() {
        return Ok(Some(tally.verdict()));
    }
    Ok(None)
}

// Client-facing verified balance: UPC fan-out plus majority verdict.
//
// Returns `(agreed, inflow, outflow, count, agreeing, total, divergent_nodes)`.
#[method::instance(export = eth)]
fn verified_balance(
    ctx: &mut _,
    account: Address,
) -> LyquidResult<(bool, u64, u64, u64, u32, u32, String)> {
    let lyquid_id = ctx.lyquid_id;
    let verdict = upc!((lyquid_id).q_balance(account: Address = account) -> (c: IndexAnswer))?;
    lyquid::println!(
        "LyquidIndex: verdict agreed={} inflow={} outflow={} count={} {}/{} divergent=[{}] flagged=[{}]",
        verdict.c.agreed,
        verdict.c.inflow,
        verdict.c.outflow,
        verdict.c.count,
        verdict.c.agreeing,
        verdict.c.total,
        verdict.c.divergent,
        verdict.c.flagged
    );
    Ok((
        verdict.c.agreed,
        verdict.c.inflow,
        verdict.c.outflow,
        verdict.c.count,
        verdict.c.agreeing,
        verdict.c.total,
        verdict.c.divergent,
    ))
}

// Returns how many disputes have been recorded for one window.
#[method::instance(export = eth)]
fn dispute_count(ctx: &_, window_id: u64) -> LyquidResult<u64> {
    Ok(ctx.network.disputes.get(&window_id).copied().unwrap_or(0))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sealed_end(size: u64, window_id: u64, len: usize) -> Option<usize> {
    let end = window_id.checked_add(1)?.checked_mul(size)?;
    (end <= len as u64).then_some(end as usize)
}

fn fold_account(events: &[EventRecord], account: Address) -> (u64, u64, u64) {
    let mut inflow = 0u64;
    let mut outflow = 0u64;
    let mut count = 0u64;
    for event in events.iter().filter(|event| event.account == account) {
        if event.kind == 0 {
            inflow = inflow.saturating_add(event.amount);
        } else {
            outflow = outflow.saturating_add(event.amount);
        }
        count += 1;
    }
    (inflow, outflow, count)
}

// Deterministic leaf encoding: `seq || account || amount || kind`.
fn leaf_of(seq: u64, event: &EventRecord) -> B256 {
    let mut bytes = Vec::with_capacity(8 + 20 + 8 + 1);
    bytes.extend_from_slice(&seq.to_be_bytes());
    bytes.extend_from_slice(event.account.as_slice());
    bytes.extend_from_slice(&event.amount.to_be_bytes());
    bytes.push(event.kind);
    hash_leaf(&bytes)
}

#[cfg(test)]
mod tests {
    use super::merkle::{chain_next, hash_leaf, proof, root, verify};
    use super::*;

    fn sample_leaves(count: usize) -> Vec<B256> {
        (0..count)
            .map(|i| hash_leaf(&(i as u64).to_be_bytes()))
            .collect()
    }

    #[lyquid_test::test]
    fn empty_window_has_zero_root() {
        assert_eq!(root(&[]), B256::ZERO);
    }

    #[lyquid_test::test]
    fn every_leaf_proves_against_its_root_for_sizes_one_to_nine() {
        for count in 1usize..=9 {
            let leaves = sample_leaves(count);
            let tree_root = root(&leaves);
            for index in 0..count {
                let path = proof(&leaves, index).expect("proof exists");
                assert!(
                    verify(tree_root, leaves[index], index as u64, count as u64, &path),
                    "size {count} index {index} failed"
                );
            }
        }
    }

    #[lyquid_test::test]
    fn wrong_sibling_breaks_the_proof() {
        let leaves = sample_leaves(6);
        let tree_root = root(&leaves);
        let mut path = proof(&leaves, 2).expect("proof exists");
        assert!(verify(tree_root, leaves[2], 2, 6, &path));
        path[0] = hash_leaf(b"tampered");
        assert!(!verify(tree_root, leaves[2], 2, 6, &path));
    }

    #[lyquid_test::test]
    fn commitment_chain_is_order_sensitive() {
        let a = hash_leaf(b"a");
        let b = hash_leaf(b"b");
        let forward = chain_next(chain_next(B256::ZERO, 0, a, 1), 1, b, 1);
        let swapped = chain_next(chain_next(B256::ZERO, 1, b, 1), 0, a, 1);
        assert_ne!(forward, swapped);
    }

    #[lyquid_test::test]
    fn index_folds_events_into_windows_deterministically() {
        let account = Address::repeat_byte(0x11);
        let mut agg = AccountAgg::default();
        for seq in 0..6u64 {
            let event = EventRecord {
                account,
                amount: 10,
                kind: (seq % 2) as u8,
            };
            let leaf = leaf_of(seq, &event);
            assert_ne!(leaf, B256::ZERO);
            if event.kind == 0 {
                agg.inflow += event.amount;
            } else {
                agg.outflow += event.amount;
            }
            agg.count += 1;
            agg.last_seq = seq;
        }
        assert_eq!(agg.inflow, 30);
        assert_eq!(agg.outflow, 30);
        assert_eq!(agg.count, 6);
        assert_eq!(agg.last_seq, 5);
    }

    #[lyquid_test::test]
    fn verdict_excludes_wrong_commitments_and_requires_strict_majority() {
        let canonical = hash_leaf(b"canonical");
        let mut tally = Tally::new(4);
        tally.commitment = Some((2, canonical));
        for responder in [1, 2] {
            tally.answers.push(IndexAnswer {
                responder: NodeID::from([responder; 32]),
                window_root: canonical,
                window_id: 2,
                inflow: 42,
                ..IndexAnswer::default()
            });
        }
        tally.answers.push(IndexAnswer {
            responder: NodeID::from([3; 32]),
            window_root: canonical,
            window_id: 1,
            inflow: 42,
            ..IndexAnswer::default()
        });
        tally.failed.push(NodeID::from([4; 32]));
        assert!(tally.ready());
        let verdict = tally.verdict();
        assert!(!verdict.agreed);
        assert_eq!(verdict.agreeing, 2);
        assert_eq!(verdict.total, 4);
        assert_eq!(verdict.inflow, 0);
    }

    #[lyquid_test::test]
    fn verdict_reports_divergent_and_flagged_nodes() {
        let good_a = NodeID::from([0x01; 32]);
        let good_b = NodeID::from([0x03; 32]);
        let bad = NodeID::from([0x02; 32]);
        let mut tally = Tally::new(3);
        tally.commitment = Some((0, B256::ZERO));
        for responder in [good_a, good_b] {
            tally.answers.push(IndexAnswer {
                responder,
                inflow: 100,
                outflow: 40,
                count: 3,
                ..IndexAnswer::default()
            });
        }
        tally.answers.push(IndexAnswer {
            responder: bad,
            inflow: 999,
            outflow: 40,
            count: 3,
            tampered: true,
            ..IndexAnswer::default()
        });
        let verdict = tally.verdict();
        // 2-of-3 is a real majority, so the honest figure wins and the liar is named.
        assert!(!verdict.agreed);
        assert_eq!(verdict.inflow, 100);
        assert_eq!(verdict.agreeing, 2);
        assert_eq!(verdict.total, 3);
        assert!(verdict.divergent.contains(&bad.to_string()));
        assert!(verdict.flagged.contains(&bad.to_string()));
        assert!(!verdict.divergent.contains(&good_a.to_string()));
    }
}
