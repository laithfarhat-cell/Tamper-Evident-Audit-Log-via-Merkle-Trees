"""Online artifact retrieval and offline verification with an independently pinned key."""

import argparse
import json
import os
from dataclasses import replace
from pathlib import Path
from urllib.request import HTTPRedirectHandler, Request, build_opener

from rich.console import Console
from rich.tree import Tree

from core.merkle import (
    Sibling,
    leaf_hash,
    node_hash,
    verify_consistency,
    verify_inclusion,
)
from core.storage import SignedTreeHead, canonical_json, create_key, verify_sth

console = Console()


def load(path):
    return json.loads(Path(path).read_bytes())


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request(base, route, data=None):
    headers = {"Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
        if token := os.getenv("AUDIT_TOKEN"):
            headers["Authorization"] = f"Bearer {token}"
    with build_opener(NoRedirect()).open(
        Request(base.rstrip("/") + "/api/v1/" + route, data, headers), timeout=15
    ) as response:
        raw = response.read(8_388_609)
        if len(raw) > 8_388_608:
            raise ValueError("response exceeds 8 MiB")
        return json.loads(raw)


def signed(value, key):
    sth = SignedTreeHead.from_dict(value)
    if not verify_sth(sth, key):
        raise ValueError("invalid checkpoint signature")
    return sth


def check_inclusion(bundle, checkpoint, key, entry=None):
    sth = signed(checkpoint, key)
    if SignedTreeHead.from_dict(bundle["sth"]) != sth:
        raise ValueError("proof does not target pinned checkpoint")
    data = canonical_json(bundle["entry"] if entry is None else entry)
    proof = [Sibling(bytes.fromhex(p["hash"]), p["direction"]) for p in bundle["proof"]]
    index = bundle["leaf_index"]
    if type(index) is not int or not verify_inclusion(
        data, index, sth.tree_size, proof, sth.root_hash
    ):
        raise ValueError("invalid inclusion proof")
    return data, proof


def check_consistency(bundle, checkpoint, key):
    old, new = signed(checkpoint, key), signed(bundle["second_sth"], key)
    if SignedTreeHead.from_dict(bundle["first_sth"]) != old:
        raise ValueError("proof does not start at pinned checkpoint")
    if new.tree_size <= old.tree_size or new.timestamp < old.timestamp:
        raise ValueError("candidate is not a newer, strictly larger checkpoint")
    if not verify_consistency(
        old.tree_size,
        new.tree_size,
        old.root_hash,
        new.root_hash,
        [bytes.fromhex(h) for h in bundle["proof"]],
    ):
        raise ValueError("invalid consistency proof")
    return new


class AsciiTree(Tree):
    def __rich_console__(self, console, options):
        yield from super().__rich_console__(console, replace(options, encoding="ascii"))


def visualize(data, proof):
    acc = leaf_hash(data)
    parts = []
    for sibling in proof:
        acc = (
            node_hash(sibling.hash, acc)
            if sibling.direction == "left"
            else node_hash(acc, sibling.hash)
        )
        parts.append((acc, sibling))
    tip = tree = AsciiTree(f"root {acc.hex()[:16]}")
    for level in range(len(parts) - 1, -1, -1):
        sibling = parts[level][1]
        child = parts[level - 1][0] if level else leaf_hash(data)
        label = f"{'subtree' if level else 'leaf'} {child.hex()[:16]}"
        other = f"sibling {sibling.hash.hex()[:16]}"
        if sibling.direction == "left":
            tip.add("L " + other)
            tip = tip.add("R " + label)
        else:
            parent = tip
            tip = parent.add("L " + label)
            parent.add("R " + other)
    console.print(tree)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init-key").add_argument("path", type=Path)
    sub.add_parser("public-key").add_argument("path", type=Path)
    sub.add_parser("submit").add_argument("event")
    sub.add_parser("sth")
    inc = sub.add_parser("inclusion")
    inc.add_argument("index", type=int)
    inc.add_argument("--size", type=int)
    con = sub.add_parser("consistency")
    con.add_argument("first", type=int)
    con.add_argument("second", type=int)
    for name in ("verify-inclusion", "verify-consistency", "tree"):
        cmd = sub.add_parser(name)
        cmd.add_argument("bundle")
        cmd.add_argument(
            "--checkpoint", required=True, help="pinned STH or /sth response JSON"
        )
        cmd.add_argument(
            "--key", required=True, help="file containing trusted public key hex"
        )
        if name != "verify-consistency":
            cmd.add_argument(
                "--entry", help="locally saved entry JSON (instead of bundle entry)"
            )
        else:
            cmd.add_argument(
                "--candidate-out",
                help="write the verified successor checkpoint to a new file",
            )
    args = parser.parse_args(argv)
    try:
        match args.command:
            case "init-key":
                create_key(args.path)
                return 0
            case "public-key":
                from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                    Ed25519PrivateKey,
                )

                print(
                    Ed25519PrivateKey.from_private_bytes(args.path.read_bytes())
                    .public_key()
                    .public_bytes_raw()
                    .hex()
                )
                return 0
            case "submit":
                result = request(args.url, "logs", canonical_json(load(args.event)))
            case "sth":
                result = request(args.url, "sth")
            case "inclusion":
                suffix = "" if args.size is None else f"?tree_size={args.size}"
                result = request(args.url, f"proof/inclusion/{args.index}{suffix}")
            case "consistency":
                result = request(
                    args.url,
                    f"proof/consistency?first={args.first}&second={args.second}",
                )
            case _:
                value = load(args.checkpoint)
                checkpoint = value.get("sth", value)
                key = bytes.fromhex(Path(args.key).read_text())
                bundle = load(args.bundle)
                if args.command == "verify-consistency":
                    candidate = check_consistency(bundle, checkpoint, key)
                    if args.candidate_out:
                        with Path(args.candidate_out).open("x") as stream:
                            json.dump(candidate.to_dict(), stream, indent=2)
                else:
                    data, proof = check_inclusion(
                        bundle,
                        checkpoint,
                        key,
                        load(args.entry) if args.entry else None,
                    )
                    if args.command == "tree":
                        visualize(data, proof)
                console.print("[green]Verified[/green]")
                return 0
        print(json.dumps(result, indent=2))
        return 0
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        OverflowError,
        RecursionError,
    ) as exc:
        Console(stderr=True).print(f"Error: {exc}", markup=False, highlight=False)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
