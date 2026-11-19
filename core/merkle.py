"""RFC 6962 hashing and proofs. Proof hashes are raw 32-byte digests."""

from dataclasses import dataclass
from hashlib import sha256
from hmac import compare_digest

EMPTY_ROOT = sha256(b"").digest()


def leaf_hash(data: bytes) -> bytes:
    return sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return sha256(b"\x01" + left + right).digest()


def split(n: int) -> int:
    return 1 << ((n - 1).bit_length() - 1)


@dataclass(frozen=True)
class Sibling:
    hash: bytes
    direction: str


class MerkleTree:
    """Read-only proof view over a snapshot of aligned complete subtree hashes.

    `node(start, width)` returns a complete subtree of power-of-two width.
    """

    def __init__(self, size, node):
        self.size = size
        self.node = node

    def root(self, size=None, *, start=0):
        n = self.size if size is None else size
        if not 0 <= start <= start + n <= self.size:
            raise ValueError("invalid range")
        if n == 0:
            return EMPTY_ROOT
        if not n & (n - 1) and start % n == 0:
            return self.node(start, n)
        k = split(n)
        return node_hash(self.root(k, start=start), self.root(n - k, start=start + k))

    def generate_inclusion_proof(self, index, tree_size=None):
        n = self.size if tree_size is None else tree_size
        if not 0 <= index < n <= self.size:
            raise ValueError("invalid leaf index or tree size")

        def path(i, start, width):
            if width == 1:
                return []
            k = split(width)
            if i < k:
                return path(i, start, k) + [
                    Sibling(self.root(width - k, start=start + k), "right")
                ]
            return path(i - k, start + k, width - k) + [
                Sibling(self.root(k, start=start), "left")
            ]

        return path(index, 0, n)

    def generate_consistency_proof(self, first_size, second_size=None):
        m, n = first_size, self.size if second_size is None else second_size
        if not 0 <= m <= n <= self.size:
            raise ValueError("invalid checkpoint sizes")

        def subproof(m, start, n, complete):
            if m == n:
                return [] if complete else [self.root(n, start=start)]
            k = split(n)
            if m <= k:
                return subproof(m, start, k, complete) + [
                    self.root(n - k, start=start + k)
                ]
            return subproof(m - k, start + k, n - k, False) + [
                self.root(k, start=start)
            ]

        return subproof(m, 0, n, True) if m else []


def is_digest(value):
    return isinstance(value, bytes) and len(value) == 32


def verify_inclusion(data, index, tree_size, proof, root):
    if not (0 <= index < tree_size < 2**64 and is_digest(root) and len(proof) <= 64):
        return False
    directions = []
    while tree_size > 1:
        k = split(tree_size)
        if index < k:
            directions.append("right")
            tree_size = k
        else:
            directions.append("left")
            index -= k
            tree_size -= k
    if len(proof) != len(directions):
        return False
    acc = leaf_hash(data)
    for sibling, direction in zip(proof, reversed(directions)):
        if sibling.direction != direction or not is_digest(sibling.hash):
            return False
        acc = (
            node_hash(sibling.hash, acc)
            if direction == "left"
            else node_hash(acc, sibling.hash)
        )
    return compare_digest(acc, root)


def verify_consistency(first_size, second_size, first_root, second_root, proof):
    if not (
        0 <= first_size <= second_size < 2**64
        and is_digest(first_root)
        and is_digest(second_root)
        and len(proof) <= 65
    ):
        return False
    if first_size == second_size:
        return (
            not proof
            and first_root == second_root
            and (first_size != 0 or first_root == EMPTY_ROOT)
        )
    if first_size == 0:
        return not proof and first_root == EMPTY_ROOT
    hashes = iter(proof)

    def take():
        digest = next(hashes)
        if not is_digest(digest):
            raise ValueError("invalid digest")
        return digest

    def rebuild(m, n, complete):
        if m == n:
            digest = first_root if complete else take()
            return digest, digest
        k = split(n)
        if m <= k:
            old, new = rebuild(m, k, complete)
            return old, node_hash(new, take())
        old, new = rebuild(m - k, n - k, False)
        left = take()
        return node_hash(left, old), node_hash(left, new)

    try:
        old, new = rebuild(first_size, second_size, True)
    except (StopIteration, ValueError):
        return False
    sentinel = object()
    return (
        next(hashes, sentinel) is sentinel and old == first_root and new == second_root
    )
