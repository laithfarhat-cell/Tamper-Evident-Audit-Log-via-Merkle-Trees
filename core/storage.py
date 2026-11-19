"""Transactional SQLite log and independently verifiable signed checkpoints."""

import json
import os
import sqlite3
import struct
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from core.merkle import (
    EMPTY_ROOT,
    MerkleTree,
    is_digest,
    leaf_hash,
    node_hash,
    verify_consistency,
    verify_inclusion,
)


class IntegrityError(RuntimeError):
    pass


def canonical_json(event):
    return json.dumps(
        event, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


@dataclass(frozen=True)
class SignedTreeHead:
    tree_size: int
    timestamp: int
    root_hash: bytes
    signature: bytes

    def to_dict(self):
        return dict(
            tree_size=self.tree_size,
            timestamp=self.timestamp,
            root_hash=self.root_hash.hex(),
            signature=self.signature.hex(),
        )

    @classmethod
    def from_dict(cls, value):
        return cls(
            value["tree_size"],
            value["timestamp"],
            bytes.fromhex(value["root_hash"]),
            bytes.fromhex(value["signature"]),
        )


def sth_message(size, timestamp, root):
    return struct.pack(">QQ", size, timestamp) + root


def verify_sth(sth, key):
    if not (
        type(sth.tree_size) is int
        and type(sth.timestamp) is int
        and 0 <= sth.tree_size < 2**64
        and 0 <= sth.timestamp < 2**64
        and is_digest(sth.root_hash)
        and isinstance(sth.signature, bytes)
        and len(sth.signature) == 64
        and (sth.tree_size != 0 or sth.root_hash == EMPTY_ROOT)
    ):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(
            sth.signature, sth_message(sth.tree_size, sth.timestamp, sth.root_hash)
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def create_key(path):
    """Explicit provisioning; never silently replace a lost signing key."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = Ed25519PrivateKey.generate().private_bytes_raw()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


SCHEMA = """
CREATE TABLE IF NOT EXISTS entries (idx INTEGER PRIMARY KEY CHECK(idx >= 0), payload BLOB NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS nodes (start INTEGER NOT NULL, width INTEGER NOT NULL,
    hash BLOB NOT NULL CHECK(length(hash)=32), PRIMARY KEY(start,width)) STRICT, WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS checkpoints (size INTEGER PRIMARY KEY CHECK(size >= 0),
    timestamp INTEGER NOT NULL, root BLOB NOT NULL CHECK(length(root)=32),
    signature BLOB NOT NULL CHECK(length(signature)=64)) STRICT;
"""


class AuditLog:
    def __init__(self, db_path, key_path):
        self.key = Ed25519PrivateKey.from_private_bytes(Path(key_path).read_bytes())
        self.public_key = self.key.public_key().public_bytes_raw()
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.transaction(begin=False) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript(SCHEMA)
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT 1 FROM checkpoints LIMIT 1").fetchone()
            if row is None:
                if any(
                    db.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone()
                    for table in ("entries", "nodes")
                ):
                    raise IntegrityError("missing checkpoints")
                self._sign(db, 0, EMPTY_ROOT)
            else:
                self._head(db, 0)
                self._snapshot(db)

    @contextmanager
    def transaction(self, write=False, *, begin=True):
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        try:
            db.execute("PRAGMA trusted_schema=OFF")
            db.execute("PRAGMA synchronous=FULL")
            if begin:
                # Initialization needs WAL configuration before opening a transaction.
                db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def _sign(self, db, size, root, minimum_timestamp=0):
        timestamp = max(minimum_timestamp, time.time_ns() // 1_000_000)
        signature = self.key.sign(sth_message(size, timestamp, root))
        db.execute(
            "INSERT INTO checkpoints VALUES (?,?,?,?)",
            (size, timestamp, root, signature),
        )
        return SignedTreeHead(size, timestamp, root, signature)

    def _head(self, db, size=None):
        if size is None:
            row = db.execute(
                "SELECT * FROM checkpoints ORDER BY size DESC LIMIT 1"
            ).fetchone()
        else:
            row = db.execute(
                "SELECT * FROM checkpoints WHERE size=?", (size,)
            ).fetchone()
        if row is None:
            raise IntegrityError("missing checkpoint")
        sth = SignedTreeHead(*row)
        if not verify_sth(sth, self.public_key):
            raise IntegrityError("invalid checkpoint signature")
        return sth

    def _snapshot(self, db):
        sth = self._head(db)
        tip = db.execute("SELECT MAX(idx) FROM entries").fetchone()[0]
        if (0 if tip is None else tip + 1) != sth.tree_size:
            raise IntegrityError("entry tip does not match signed checkpoint")

        def node(start, width):
            row = db.execute(
                "SELECT hash FROM nodes WHERE start=? AND width=?", (start, width)
            ).fetchone()
            if row is None or not is_digest(row[0]):
                raise IntegrityError("missing or invalid subtree hash")
            return row[0]

        tree = MerkleTree(sth.tree_size, node)
        if tree.root() != sth.root_hash:
            raise IntegrityError("cached frontier does not match signed checkpoint")
        return sth, tree

    def append(self, event):
        with self.transaction(write=True) as db:
            previous, tree = self._snapshot(db)
            index = previous.tree_size
            timestamp = max(previous.timestamp, time.time_ns() // 1_000_000)
            payload = canonical_json(
                dict(event, sequence_id=index, timestamp=timestamp)
            )
            digest = leaf_hash(payload)
            db.execute("INSERT INTO entries VALUES (?,?)", (index, payload))
            start, width, root = index, 1, digest
            db.execute("INSERT INTO nodes VALUES (?,?,?)", (start, width, root))
            # Fold the old authenticated frontier from right to left. Persist
            # only aligned complete subtrees formed by the binary carry.
            for bit in range(index.bit_length()):
                span = 1 << bit
                if index & span:
                    root = node_hash(tree.node(start - span, span), root)
                    start -= span
                    if width == span:
                        width *= 2
                        db.execute(
                            "INSERT INTO nodes VALUES (?,?,?)", (start, width, root)
                        )
            sth = self._sign(db, index + 1, root, timestamp)
            return dict(
                leaf_index=index,
                leaf_hash=digest.hex(),
                entry=json.loads(payload),
                sth=sth.to_dict(),
            )

    def head(self):
        with self.transaction() as db:
            return self._snapshot(db)[0]

    def inclusion(self, index, size=None):
        with self.transaction() as db:
            latest, tree = self._snapshot(db)
            size = latest.tree_size if size is None else size
            path = tree.generate_inclusion_proof(index, size)
            row = db.execute(
                "SELECT payload FROM entries WHERE idx=?", (index,)
            ).fetchone()
            if row is None:
                raise IntegrityError("missing entry")
            sth = self._head(db, size)
            if not verify_inclusion(row[0], index, size, path, sth.root_hash):
                raise IntegrityError("entry or path does not match signed checkpoint")
            return dict(
                leaf_index=index,
                entry=json.loads(row[0]),
                sth=sth.to_dict(),
                proof=[dict(hash=p.hash.hex(), direction=p.direction) for p in path],
            )

    def consistency(self, first, second):
        with self.transaction() as db:
            _, tree = self._snapshot(db)
            proof = tree.generate_consistency_proof(first, second)
            old, new = self._head(db, first), self._head(db, second)
            if not verify_consistency(
                first, second, old.root_hash, new.root_hash, proof
            ):
                raise IntegrityError("path does not match signed checkpoints")
            return dict(
                first_sth=old.to_dict(),
                second_sth=new.to_dict(),
                proof=[h.hex() for h in proof],
            )

    def verify_all(self):
        """Rebuild from raw bytes, compare every node and verify every signed prefix."""
        with self.transaction() as db:
            latest, _ = self._snapshot(db)
            heads = iter(db.execute("SELECT * FROM checkpoints ORDER BY size"))
            frontier = []
            node_count = 0
            timestamp = 0

            def check_head(size, root):
                nonlocal timestamp
                row = next(heads, None)
                if (
                    row is None
                    or row[0] != size
                    or row[2] != root
                    or row[1] < timestamp
                    or not verify_sth(SignedTreeHead(*row), self.public_key)
                ):
                    raise IntegrityError(f"invalid checkpoint at size {size}")
                timestamp = row[1]

            def check_node(start, width, digest):
                nonlocal node_count
                row = db.execute(
                    "SELECT hash FROM nodes WHERE start=? AND width=?", (start, width)
                ).fetchone()
                if row is None or row[0] != digest:
                    raise IntegrityError(f"node mismatch at ({start}, {width})")
                node_count += 1

            check_head(0, EMPTY_ROOT)
            count = 0
            for idx, payload in db.execute(
                "SELECT idx,payload FROM entries ORDER BY idx"
            ):
                if idx != count:
                    raise IntegrityError(f"missing entry at index {count}")
                start, width, digest = idx, 1, leaf_hash(payload)
                check_node(start, width, digest)
                while frontier and frontier[-1][1] == width:
                    start, _, left = frontier.pop()
                    width *= 2
                    digest = node_hash(left, digest)
                    check_node(start, width, digest)
                frontier.append((start, width, digest))
                for _, _, left in reversed(frontier[:-1]):
                    digest = node_hash(left, digest)
                count += 1
                check_head(count, digest)
            if (
                count != latest.tree_size
                or next(heads, None) is not None
                or db.execute("SELECT count(*) FROM nodes").fetchone()[0] != node_count
            ):
                raise IntegrityError("unexpected row count")
            return dict(ok=True, entries=count, nodes=node_count, sth=latest.to_dict())
