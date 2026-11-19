"""HTTP transport. The signing key must be provisioned before startup."""

import os
import secrets
import sqlite3
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Path, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, JsonValue

from core.storage import AuditLog, IntegrityError

MAX_INDEX = 2**63 - 1
Text = Annotated[str, Field(min_length=1, max_length=512)]


class Event(BaseModel):
    model_config = ConfigDict(extra="forbid")
    actor: Text
    action: Text
    resource: Text
    source_ip: IPvAnyAddress
    metadata: dict[str, JsonValue] = Field(default_factory=dict)


def create_app(db_path=None, key_path=None, token=None):
    @asynccontextmanager
    async def lifespan(app):
        app.state.log = AuditLog(
            db_path or os.getenv("AUDIT_DB", "data/audit_log.db"),
            key_path or os.getenv("AUDIT_KEY", "keys/signing.key"),
        )
        app.state.token = token if token is not None else os.getenv("AUDIT_TOKEN")
        yield

    app = FastAPI(title="Merkle Audit Log", version="1.0", lifespan=lifespan)

    def log(request: Request):
        return request.app.state.log

    def authorize(
        request: Request, authorization: Annotated[str | None, Header()] = None
    ):
        expected = request.app.state.token
        if not expected:
            raise HTTPException(503, "write and sweep access is not configured")
        if not secrets.compare_digest(
            (authorization or "").encode(), f"Bearer {expected}".encode()
        ):
            raise HTTPException(
                401, "invalid credentials", headers={"WWW-Authenticate": "Bearer"}
            )

    @app.exception_handler(IntegrityError)
    async def integrity_failure(request, exc):
        return JSONResponse(status_code=409, content={"ok": False, "detail": str(exc)})

    @app.exception_handler(sqlite3.Error)
    async def storage_failure(request, exc):
        return JSONResponse(
            status_code=503, content={"ok": False, "detail": "storage unavailable"}
        )

    @app.post("/api/v1/logs", status_code=201, dependencies=[Depends(authorize)])
    def append(event: Event, store: Annotated[AuditLog, Depends(log)]):
        try:
            return store.append(event.model_dump(mode="json"))
        except (ValueError, RecursionError) as exc:
            raise HTTPException(422, "event cannot be serialized") from exc

    @app.get("/api/v1/sth")
    def sth(store: Annotated[AuditLog, Depends(log)]):
        return {"sth": store.head().to_dict(), "public_key": store.public_key.hex()}

    @app.get("/api/v1/proof/inclusion/{leaf_index}")
    def inclusion(
        leaf_index: Annotated[int, Path(ge=0, le=MAX_INDEX)],
        store: Annotated[AuditLog, Depends(log)],
        tree_size: Annotated[int | None, Query(ge=0, le=MAX_INDEX)] = None,
    ):
        try:
            return store.inclusion(leaf_index, tree_size)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.get("/api/v1/proof/consistency")
    def consistency(
        first: Annotated[int, Query(ge=0, le=MAX_INDEX)],
        second: Annotated[int, Query(ge=0, le=MAX_INDEX)],
        store: Annotated[AuditLog, Depends(log)],
    ):
        try:
            return store.consistency(first, second)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.get("/api/v1/audit/verify-all", dependencies=[Depends(authorize)])
    def sweep(store: Annotated[AuditLog, Depends(log)]):
        return store.verify_all()

    return app


app = create_app()
