# Tamper-Evident Audit Log

[![Tests](https://github.com/laithfarhat-cell/Tamper-Evident-Audit-Log-via-Merkle-Trees/actions/workflows/tests.yml/badge.svg)](https://github.com/laithfarhat-cell/Tamper-Evident-Audit-Log-via-Merkle-Trees/actions/workflows/tests.yml)
![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue)
![RFC 6962](https://img.shields.io/badge/Merkle-RFC%206962-green)
![Ed25519](https://img.shields.io/badge/signatures-Ed25519-purple)

Append structured security events to SQLite, publish signed Merkle checkpoints, and verify historical inclusion and append-only growth offline. The proof algorithms follow RFC 6962; this is not a CT protocol endpoint. See [THEORY.md](THEORY.md) for the wire encoding, complexity, and trust model.

```text
              root H(01 || N01 || L2)    size = 3
              /                     \
     N01 H(01 || L0 || L1)           L2
         /             \
        L0             L1              Li = H(00 || canonical_event_i)
```

## Run locally

Requires Python 3.11+ and SQLite 3.37+ (`STRICT` tables). In one terminal:

```sh
python -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
audit-log init-key keys/signing.key          # once; refuses to overwrite
export AUDIT_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
printf 'Use this token in the client terminal: %s\n' "$AUDIT_TOKEN"
uvicorn server.api:app --host 127.0.0.1 --port 8000
```

In the client terminal activate the same environment and set `AUDIT_TOKEN` to the server token. Obtain the public key through a trusted path, for example on the signer host:

```sh
audit-log public-key keys/signing.key > trusted-public.hex
```

Transfer **only** `trusted-public.hex` to the auditor via an authenticated channel. Do not implicitly trust the key returned by a proof server.

## API walkthrough

Start with a fresh log for the sizes below. The server assigns zero-based `sequence_id` and an integer Unix-milliseconds `timestamp`. `metadata` defaults to `{}`. The receipt contains the canonicalizable `entry`, `leaf_index`, `leaf_hash`, and signed `sth`. Keys, signatures, and digests are hex. Inclusion siblings are ordered from leaf to root; `direction` tells where the sibling sits. Consistency hashes follow RFC 6962 ordering.

```sh
base=http://127.0.0.1:8000/api/v1
cat > event.json <<'JSON'
{"actor":"alice","action":"read","resource":"invoice/42","source_ip":"192.0.2.12","metadata":{"ticket":"AUD-42"}}
JSON
curl -fsS -H "Authorization: Bearer $AUDIT_TOKEN" -H 'Content-Type: application/json' \
  --data-binary @event.json "$base/logs" > receipt.json
curl -fsS "$base/sth" > pinned.json
curl -fsS "$base/proof/inclusion/0?tree_size=1" > inclusion.json
curl -fsS -H "Authorization: Bearer $AUDIT_TOKEN" -H 'Content-Type: application/json' \
  --data-binary @event.json "$base/logs"
curl -fsS "$base/proof/consistency?first=1&second=2" > consistency.json
curl -fsS -H "Authorization: Bearer $AUDIT_TOKEN" "$base/audit/verify-all"
```

Omit `tree_size` for the latest head. Empty and equal-size consistency requests return empty proofs; impossible ranges return `400`. A detected storage integrity violation returns `409`; unavailable SQLite storage returns `503`. Interactive API schema: `/docs`.

## Auditor CLI

| Command | Purpose |
|---|---|
| `audit-log init-key PATH` / `audit-log public-key PATH` | Provision a private key / export its trusted public key |
| `audit-log [--url URL] submit EVENT.json` | Append using the `AUDIT_TOKEN` environment variable |
| `audit-log [--url URL] sth` | Retrieve latest STH and advertised key |
| `audit-log [--url URL] inclusion INDEX [--size N]` | Fetch historical proof bundle |
| `audit-log [--url URL] consistency M N` | Fetch the consistency bundle |
| `audit-log verify-inclusion BUNDLE --checkpoint PIN --key KEY [--entry ENTRY]` | Verify offline against the exact pinned STH; optionally check a separately saved entry |
| `audit-log verify-consistency BUNDLE --checkpoint PIN --key KEY [--candidate-out NEW]` | Verify strict growth from a pinned STH; optionally write the verified candidate to a new file |
| `audit-log tree BUNDLE --checkpoint PIN --key KEY [--entry ENTRY]` | Verify and render an ASCII path with sibling hashes |

```sh
audit-log verify-inclusion inclusion.json --checkpoint pinned.json --key trusted-public.hex
audit-log tree inclusion.json --checkpoint pinned.json --key trusted-public.hex
audit-log verify-consistency consistency.json --checkpoint pinned.json \
  --key trusted-public.hex --candidate-out next-pin.json
```

An initial pin is only as current as your bootstrap source; bootstrap through a trusted channel and retain it independently. Only advance to an authenticated, consistent successor. Without `--entry`, inclusion verifies the **supplied** event; compare it with the event you intended to audit. Verification failures exit nonzero.

## Docker and operations

```sh
export AUDIT_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
docker compose --profile tools run --build --rm provision-key   # once per key volume
docker compose up --build -d audit-log
```

Compose binds to host loopback, runs as a non-root user, and mounts the signing volume read-only in the server. It is a local baseline, not a hardened internet-facing deployment. `AUDIT_DB` and `AUDIT_KEY` override the paths outside Compose. Put a TLS/authenticating proxy in front for remote access, enforce request size and rate limits, restrict access to sensitive logs, and schedule sweeps rather than polling them. **Read endpoints are unauthenticated by the app and inclusion responses disclose event payloads.** The bearer token gates writes and sweeps; it does not authenticate the `actor` field. Back up the database using a SQLite-consistent snapshot and protect key backups separately. Do not remove the named volumes to restart the service. Keep independent checkpoint pins and monitor for rollback or equivocation. This service does not provide witness quorum, key rotation, retention, or exactly-once retries.

## Verification and tamper lab

```sh
python -m pytest -q
python -m simulation.tamper_lab
```

The lab uses disposable databases and checks payload edits, coherent truncation, reordering, and internal-node impersonation. The truncation example passes the local sweep but cannot pass as an extension of the auditor's retained checkpoint. That distinction is essential: cryptographic proofs expose inconsistency relative to a trusted pin; they do not keep SQLite files from being deleted or modified.
