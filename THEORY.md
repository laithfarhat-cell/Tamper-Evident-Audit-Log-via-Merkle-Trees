# What the proofs establish

The tree construction and proof ordering follow [RFC 6962 §2.1](https://www.rfc-editor.org/rfc/rfc6962#section-2.1). The audit-event format, API, and Ed25519 checkpoints are application-specific, not Certificate Transparency wire formats.

## Merkle Tree Hash

Let `H` be SHA-256 and `||` be concatenation. For an ordered sequence of byte strings `D`, define:

- `MTH([]) = H("")`.
- `MTH([d]) = H(0x00 || d)`.
- `MTH(D[0:n]) = H(0x01 || MTH(D[0:k]) || MTH(D[k:n]))` for `n > 1`.

`k = 2^floor(log2(n−1))` is the largest power of two strictly below `n`. In integers this is `1 << ((n - 1).bit_length() - 1)`; no floating-point rounding, duplicate leaves, or padding. For `n=7`, split `4+3`, then `3=2+1`; for `n=8`, split `4+4`.

Without a domain prefix, an internal node `H(L || R)` would also be the hash of a single leaf with value `L || R`: structural ambiguity, no SHA-256 break required. With prefixes, these two inputs differ at byte zero. A match would require finding a second preimage or collision, rather than merely retyping an internal preimage as a leaf. Ordered children bind positions; the signed size also binds the tree shape. A one-byte edit changes the hashed input and is expected to drastically change its digest, but binding relies on collision/second-preimage resistance, not the avalanche property alone.

## Inclusion

At each split descend into the side containing the requested zero-based index and record the sibling subtree root. Emit siblings bottom-up. The verifier derives each sibling direction and the exact path length from `(index, size)` rather than trusting the supplied direction, starts with `H(0x00 || entry_bytes)`, rehashes up, and compares to the pinned root. This binds the bytes and index at that checkpoint, not the truth of the event or the identity of its claimed actor.

## Consistency

`PROOF(m, D) = SUBPROOF(m, D, true)` for `0 < m <= n`. At `m=n`, return nothing when `complete=true` (reuse the trusted first root), or emit `MTH(D)` otherwise. At split `k`:

- If `m <= k`, recurse into the left subtree with the flag unchanged, then append the new right subtree hash. The old root is entirely on the left.
- If `m > k`, recurse into the right subtree with `m-k` and flag `false`, then append the common left subtree hash. This left subtree is combined with **both** reconstructed right roots.

The verifier uses the same split geometry but reconstructs the two roots from the proof stream, checks exact consumption, and compares both results to signed roots. Under the hash assumption this shows the first `m` leaves remain in the same order with the same bytes. It does not show which events were added. An empty tree is a prefix of any tree (the new root must still be authenticated), and equal sizes require the same root and an empty proof. The CLI requires `m < n` to advance a pin.

## Complexity and persistence

Proof sizes and verification hash counts are `O(log n)` (inclusion also hashes the input record in `O(entry_bytes)`). Each proof visits a single spine. Sibling ranges are complete aligned subtrees except at the right fringe; a fringe root costs at most `O(log n)` cached subtree reads, and only one such sibling is needed. SQLite B-tree lookup costs are separate from hash counts. Each append folds `O(log n)` frontier hashes and persists the leaf plus completed binary-carry subtrees; fewer than `2n` complete nodes exist for `n > 0`. Checkpoints are `O(n)`. The full sweep rehashes every payload, checks every stored node, and verifies every historical STH; folding the frontier for every prefix takes `O(n log n)` hash operations in addition to reading payloads, checking signatures, and querying SQLite. It operates in a single read snapshot.

## Signed checkpoints and the database-admin threat model

The signed preimage is exactly `uint64_be(tree_size) || uint64_be(timestamp_ms) || root_hash[32]`, with no JSON or delimiter bytes. Ed25519 signs it with a dedicated per-log key. Auditors verify with an independently obtained 32-byte raw public key. A DB-only attacker cannot authenticate a different root, size, or timestamp just by rewriting rows and recomputing hashes. Writes check the previous signed tip and cached frontier inside the transaction before extending it; this is not a full historical sweep.

Signatures do **not** stop deletion, denial of service, stale replay, or restoration of an intact signed prefix. A coherent rollback can pass a local sweep, and a running signer that sees only the rolled-back DB can sign a divergent branch. Retain pins outside the server, reject regressions and inconsistent successors, and compare checkpoints across auditors or use an independent witness to detect split views. For deployments that must *prevent* the signer from extending a rollback, isolate a monotonic checkpoint store/witness outside the database administrator's control and enforce it before publishing. No such witness is included. Key compromise defeats checkpoint authenticity; protect the key and do not reuse it across logs. A signed timestamp is not external evidence of time or freshness. SQLite is a single logical writer, not a distributed consensus system.
