//! Deterministic Merkle commitment utilities used by `LyquidIndex`.
//!
//! Leaves are domain-separated (`0x00`) and internal nodes are domain-separated (`0x01`),
//! so a leaf hash can never be confused with an internal node hash.
//!
//! The tree promotes a lone trailing node to the next level unchanged (no duplicate-pair
//! padding), which keeps proofs short for power-of-two windows and stays deterministic for
//! every window size.
//!
//! Because promote-odd makes the *shape* of the tree depend on the leaf count, the number of
//! leaves is folded into the published commitment itself (`ROOT_PREFIX` + `leaf_count`). Without
//! that binding a verifier could be handed a shorter path plus a smaller `leaf_count` and accept
//! a truncated window; see `seal`.

use lyquid::lyquor_primitives::{B256, blake3};

/// Domain-separation prefix for a leaf.
const LEAF_PREFIX: u8 = 0x00;
/// Domain-separation prefix for an internal node.
const NODE_PREFIX: u8 = 0x01;
/// Domain-separation prefix for a sealed (published) window commitment.
const ROOT_PREFIX: u8 = 0x04;

/// Hashes one serialized event record into a leaf.
pub fn hash_leaf(bytes: &[u8]) -> B256 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[LEAF_PREFIX]);
    hasher.update(bytes);
    B256::from(*hasher.finalize().as_bytes())
}

/// Hashes two child nodes into their parent.
pub fn hash_node(left: B256, right: B256) -> B256 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[NODE_PREFIX]);
    hasher.update(left.as_slice());
    hasher.update(right.as_slice());
    B256::from(*hasher.finalize().as_bytes())
}

/// Binds the tree top to the window size, producing the on-chain commitment.
///
/// This is what stops a prover from claiming a smaller window: the leaf count is inside the
/// hash, so any disagreement about it changes the commitment.
pub fn seal(tree_top: B256, leaf_count: u64) -> B256 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[ROOT_PREFIX]);
    hasher.update(&leaf_count.to_be_bytes());
    hasher.update(tree_top.as_slice());
    B256::from(*hasher.finalize().as_bytes())
}

/// Tree top before the size binding is applied.
fn tree_top(leaves: &[B256]) -> B256 {
    if leaves.is_empty() {
        return B256::ZERO;
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        level = next_level(&level);
    }
    level[0]
}

/// Computes the window commitment of the given leaves.
///
/// Returns `B256::ZERO` for an empty leaf set so an empty window still has a stable,
/// well-defined commitment.
pub fn root(leaves: &[B256]) -> B256 {
    if leaves.is_empty() {
        return B256::ZERO;
    }
    seal(tree_top(leaves), leaves.len() as u64)
}

/// Builds the audit path for `index`, or `None` when `index` is out of range.
pub fn proof(leaves: &[B256], index: usize) -> Option<Vec<B256>> {
    if index >= leaves.len() {
        return None;
    }
    let mut path = Vec::new();
    let mut level = leaves.to_vec();
    let mut idx = index;
    while level.len() > 1 {
        if idx % 2 == 1 {
            path.push(level[idx - 1]);
        } else if idx + 1 < level.len() {
            path.push(level[idx + 1]);
        }
        level = next_level(&level);
        idx /= 2;
    }
    Some(path)
}

/// Verifies an audit path against a window commitment.
///
/// `leaf_count` must be the number of leaves in the committed window: with the promote-odd
/// scheme the verifier needs the level widths to know when a level had a lone trailing node.
/// It is also bound into `merkle_root` by [`seal`], so a wrong count is always rejected.
pub fn verify(merkle_root: B256, leaf: B256, index: u64, leaf_count: u64, path: &[B256]) -> bool {
    if leaf_count == 0 || index >= leaf_count {
        return false;
    }
    let mut node = leaf;
    let mut idx = index;
    let mut len = leaf_count;
    let mut cursor = 0usize;
    while len > 1 {
        if idx % 2 == 1 {
            let Some(sibling) = path.get(cursor) else {
                return false;
            };
            node = hash_node(*sibling, node);
            cursor += 1;
        } else if idx + 1 < len {
            let Some(sibling) = path.get(cursor) else {
                return false;
            };
            node = hash_node(node, *sibling);
            cursor += 1;
        }
        idx /= 2;
        len = len.div_ceil(2);
    }
    cursor == path.len() && seal(node, leaf_count) == merkle_root
}

/// Collapses one level of the tree, promoting a lone trailing node unchanged.
fn next_level(level: &[B256]) -> Vec<B256> {
    let mut out = Vec::with_capacity(level.len().div_ceil(2));
    let mut i = 0usize;
    while i + 1 < level.len() {
        out.push(hash_node(level[i], level[i + 1]));
        i += 2;
    }
    if i < level.len() {
        out.push(level[i]);
    }
    out
}

/// Chains one checkpoint into the running commitment chain.
///
/// This is what makes the *sequence* of windows tamper-evident, not just each window
/// individually: reordering or dropping a checkpoint breaks every later chain root.
pub fn chain_next(
    previous_chain: B256,
    window_id: u64,
    merkle_root: B256,
    leaf_count: u64,
) -> B256 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[0x02]);
    hasher.update(previous_chain.as_slice());
    hasher.update(&window_id.to_be_bytes());
    hasher.update(merkle_root.as_slice());
    hasher.update(&leaf_count.to_be_bytes());
    B256::from(*hasher.finalize().as_bytes())
}
