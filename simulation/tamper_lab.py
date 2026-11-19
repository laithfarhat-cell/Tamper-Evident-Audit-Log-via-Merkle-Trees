"""Four SQLite tampering demos, each inside its own temporary directory."""

import sqlite3
from pathlib import Path
from tempfile import TemporaryDirectory

from rich.console import Console

from core.merkle import (
    Sibling,
    leaf_hash,
    node_hash,
    verify_consistency,
    verify_inclusion,
)
from core.storage import AuditLog, IntegrityError, create_key


def run():
    outcomes = {}
    for attack in (
        "payload",
        "truncation",
        "reordering",
        "internal node impersonation",
    ):
        with TemporaryDirectory() as directory:
            db, key = Path(directory) / "log.db", Path(directory) / "signing.key"
            create_key(key)
            log = AuditLog(db, key)
            for i in range(4):
                log.append(
                    dict(
                        actor="alice",
                        action="read",
                        resource=f"asset-{i}",
                        source_ip="192.0.2.1",
                        metadata={},
                    )
                )
            pinned = log.head()
            proof = [
                Sibling(bytes.fromhex(p["hash"]), p["direction"])
                for p in log.inclusion(0)["proof"]
            ]
            with sqlite3.connect(db) as conn:
                rows = [
                    row[0]
                    for row in conn.execute("SELECT payload FROM entries ORDER BY idx")
                ]
                if attack == "payload":
                    conn.execute(
                        "UPDATE entries SET payload=? WHERE idx=0",
                        (rows[0].replace(b"alice", b"Alice"),),
                    )
                elif attack == "truncation":
                    conn.execute("DELETE FROM entries WHERE idx=3")
                    conn.execute("DELETE FROM checkpoints WHERE size=4")
                    conn.execute("DELETE FROM nodes WHERE start+width>3")
                elif attack == "reordering":
                    conn.executemany(
                        "UPDATE entries SET payload=? WHERE idx=?",
                        [(rows[1], 0), (rows[0], 1)],
                    )
                else:
                    conn.execute(
                        "UPDATE entries SET payload=? WHERE idx=0",
                        (leaf_hash(rows[0]) + leaf_hash(rows[1]),),
                    )
                    conn.commit()
                if attack != "truncation":
                    raw = conn.execute(
                        "SELECT payload FROM entries WHERE idx=0"
                    ).fetchone()[0]
                    rejected = not verify_inclusion(
                        raw, 0, pinned.tree_size, proof, pinned.root_hash
                    )
                    if attack == "internal node impersonation":
                        rejected &= not verify_inclusion(
                            raw, 0, 1, [], node_hash(raw[:32], raw[32:])
                        )
                else:
                    rejected = True
            if attack == "truncation":
                # A coherent rollback can pass the local sweep. An auditor
                # comparing with the independently retained size 4 rejects it.
                assert log.verify_all()["entries"] == 3
                candidate = log.head()
                rejected = not verify_consistency(
                    pinned.tree_size,
                    candidate.tree_size,
                    pinned.root_hash,
                    candidate.root_hash,
                    [],
                )
            else:
                try:
                    log.verify_all()
                except IntegrityError:
                    pass
                else:
                    rejected = False
            outcomes[attack] = rejected
    return outcomes


def main():
    outcomes = run()
    console = Console()
    for attack, rejected in outcomes.items():
        console.print(f"{attack}: {'DETECTED' if rejected else 'MISSED'}")
    return 0 if all(outcomes.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
