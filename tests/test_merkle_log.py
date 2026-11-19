import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from hashlib import sha256

import pytest
from fastapi.testclient import TestClient

from cli.auditor import check_consistency, check_inclusion, main
from core.merkle import (
    EMPTY_ROOT,
    MerkleTree,
    Sibling,
    leaf_hash,
    node_hash,
    verify_consistency,
    verify_inclusion,
)
from core.storage import (
    AuditLog,
    IntegrityError,
    SignedTreeHead,
    canonical_json,
    create_key,
    verify_sth,
)
from server.api import create_app
from simulation.tamper_lab import run

EVENT = dict(
    actor="alice",
    action="read",
    resource="/example",
    source_ip="192.0.2.9",
    metadata={},
)
LEAVES = [str(i).encode() for i in range(256)]


def reference(leaves):
    if not leaves:
        return sha256(b"").digest()
    if len(leaves) == 1:
        return sha256(b"\x00" + leaves[0]).digest()
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    return sha256(b"\x01" + reference(leaves[:k]) + reference(leaves[k:])).digest()


@pytest.fixture(scope="module")
def tree():
    hashes = {
        (i, w): reference(LEAVES[i : i + w])
        for w in (1 << j for j in range(9))
        for i in range(0, len(LEAVES), w)
    }
    return MerkleTree(len(LEAVES), lambda i, w: hashes[i, w])


@pytest.mark.parametrize("size", [0, 1, 2, 3, 7, 8, 255, 256])
def test_inclusion(tree, size):
    root = reference(LEAVES[:size])
    assert tree.root(size) == root
    for i in range(size):
        proof = tree.generate_inclusion_proof(i, size)
        assert len(proof) <= (size - 1).bit_length()
        assert verify_inclusion(LEAVES[i], i, size, proof, root)
        assert not verify_inclusion(b"other", i, size, proof, root)
        assert not verify_inclusion(
            LEAVES[i], i, size, proof + [Sibling(root, "left")], root
        )
        if proof:
            direction = "left" if proof[0].direction == "right" else "right"
            assert not verify_inclusion(
                LEAVES[i],
                i,
                size,
                [Sibling(proof[0].hash, direction), *proof[1:]],
                root,
            )
            assert not verify_inclusion(LEAVES[i], i, size, proof[1:], root)
    with pytest.raises(ValueError):
        tree.generate_inclusion_proof(size, size)


def test_consistency_all_pairs(tree):
    roots = [reference(LEAVES[:size]) for size in range(257)]
    for n, root in enumerate(roots):
        for m in range(n + 1):
            proof = tree.generate_consistency_proof(m, n)
            assert len(proof) <= max(0, n - 1).bit_length() + 1
            assert verify_consistency(m, n, roots[m], root, proof)
            assert not verify_consistency(m, n, roots[m], root, proof + [None])
            if m:
                assert not verify_consistency(m, n, EMPTY_ROOT, root, proof)
            if proof:
                assert not verify_consistency(m, n, roots[m], root, proof[:-1])
                assert not verify_consistency(
                    m, n, roots[m], root, [EMPTY_ROOT, *proof[1:]]
                )
    assert not verify_consistency(7, 3, roots[7], roots[3], [])
    with pytest.raises(ValueError):
        tree.generate_consistency_proof(7, 3)


def test_domains_and_serialization():
    left, right = leaf_hash(b"a"), leaf_hash(b"b")
    assert leaf_hash(left + right) != node_hash(left, right)
    assert (
        canonical_json({"z": "é", "a": {"d": 4, "b": 2}})
        == b'{"a":{"b":2,"d":4},"z":"\\u00e9"}'
    )
    with pytest.raises(ValueError):
        canonical_json({"bad": float("nan")})


@pytest.fixture
def log(tmp_path):
    key = tmp_path / "key"
    create_key(key)
    return AuditLog(tmp_path / "audit.db", key)


def test_sth_and_concurrent_appends(log, tmp_path):
    with ThreadPoolExecutor(max_workers=8) as pool:
        receipts = list(
            pool.map(lambda i: log.append(dict(EVENT, resource=str(i))), range(32))
        )
    receipts.sort(key=lambda r: r["leaf_index"])
    entries = [canonical_json(r["entry"]) for r in receipts]
    for i, receipt in enumerate(receipts):
        sth = SignedTreeHead.from_dict(receipt["sth"])
        assert receipt["leaf_index"] == i and sth.tree_size == i + 1
        assert receipt["leaf_hash"] == leaf_hash(entries[i]).hex()
        assert sth.root_hash == reference(entries[: i + 1])
        assert verify_sth(sth, log.public_key)
        for tampered in (
            replace(sth, tree_size=i + 2),
            replace(sth, timestamp=sth.timestamp + 1),
            replace(sth, root_hash=EMPTY_ROOT),
            replace(sth, signature=bytes(64)),
        ):
            assert not verify_sth(tampered, log.public_key)
        assert not verify_sth(sth, bytes(32))
    with pytest.raises(FileExistsError):
        create_key(tmp_path / "key")
    assert AuditLog(log.path, tmp_path / "key").verify_all()["entries"] == 32


def test_failed_append_rolls_back(log):
    log.append(EVENT)
    before = log.head()
    with pytest.raises(ValueError):
        log.append(dict(EVENT, metadata={"bad": float("nan")}))
    assert log.head() == before
    assert log.verify_all()["entries"] == 1


def test_cache_corruption_refuses_to_sign(log):
    log.append(EVENT)
    with sqlite3.connect(log.path) as db:
        db.execute("UPDATE nodes SET hash=?", (bytes(32),))
    with pytest.raises(IntegrityError):
        log.append(EVENT)


def test_lab():
    assert all(run().values())


def test_api_and_offline(log, tmp_path, capsys):
    with TestClient(create_app(log.path, tmp_path / "key", "test-token")) as client:
        auth = {"Authorization": "Bearer test-token"}
        assert client.post("/api/v1/logs", json=EVENT).status_code == 401
        assert (
            client.post(
                "/api/v1/logs", json=dict(EVENT, source_ip="invalid"), headers=auth
            ).status_code
            == 422
        )
        assert client.post("/api/v1/logs", json=EVENT, headers=auth).status_code == 201
        pinned = client.get("/api/v1/sth").json()
        assert client.post("/api/v1/logs", json=EVENT, headers=auth).status_code == 201
        bundle = client.get("/api/v1/proof/inclusion/0?tree_size=1").json()
        proof = client.get("/api/v1/proof/consistency?first=1&second=2").json()
        assert client.get("/api/v1/proof/inclusion/3").status_code == 400
        assert (
            client.get("/api/v1/proof/consistency?first=2&second=1").status_code == 400
        )
        assert client.get("/api/v1/audit/verify-all").status_code == 401
        assert (
            client.get("/api/v1/audit/verify-all", headers=auth).json()["entries"] == 2
        )
        key = bytes.fromhex(pinned["public_key"])
        check_inclusion(bundle, pinned["sth"], key)
        assert check_consistency(proof, pinned["sth"], key).tree_size == 2
        with pytest.raises(ValueError):
            check_inclusion(
                bundle, pinned["sth"], key, dict(bundle["entry"], actor="mallory")
            )
        with pytest.raises(ValueError):
            check_consistency(
                dict(proof, second_sth=pinned["sth"], proof=[]), pinned["sth"], key
            )
        (tmp_path / "pub").write_text(key.hex())
        for name, value in [("inc", bundle), ("pin", pinned), ("con", proof)]:
            (tmp_path / name).write_text(json.dumps(value))
        common = ["--checkpoint", str(tmp_path / "pin"), "--key", str(tmp_path / "pub")]
        assert main(["tree", str(tmp_path / "inc"), *common]) == 0
        assert "Verified" in capsys.readouterr().out
        assert (
            main(
                [
                    "verify-consistency",
                    str(tmp_path / "con"),
                    *common,
                    "--candidate-out",
                    str(tmp_path / "next"),
                ]
            )
            == 0
        )
        assert json.loads((tmp_path / "next").read_bytes())["tree_size"] == 2
        with sqlite3.connect(log.path) as db:
            db.execute("UPDATE entries SET payload=? WHERE idx=0", (b"{}",))
        assert client.get("/api/v1/proof/inclusion/0").status_code == 409
        assert client.get("/api/v1/audit/verify-all", headers=auth).status_code == 409


def test_rfc_path_order_for_unbalanced_tree(tree):
    def h(start, end):
        return reference(LEAVES[start:end])

    assert tree.generate_inclusion_proof(5, 7) == [
        Sibling(h(4, 5), "left"),
        Sibling(h(6, 7), "right"),
        Sibling(h(0, 4), "left"),
    ]
    assert tree.generate_consistency_proof(5, 7) == [h(4, 5), h(5, 6), h(6, 7), h(0, 4)]
    assert tree.generate_consistency_proof(4, 7) == [h(4, 7)]
