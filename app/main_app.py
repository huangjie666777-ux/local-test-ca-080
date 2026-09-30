"""FastAPI HTTP layer."""
from __future__ import annotations

from contextlib import asynccontextmanager
import json

from fastapi import FastAPI, HTTPException, Response
from typing import Any

from pydantic import BaseModel

from .ca_service import CAError, init_or_load_ca
from .policy import PolicyError
from .service import CertificateService
from .settings import get_settings
from .storage import Database, IdempotencyConflict, RevocationConflict


class IssueRequest(BaseModel):
    csr: str
    days: Any
    idempotency_key: str


class RevokeRequest(BaseModel):
    reason: str


def create_app() -> FastAPI:
    settings = get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        try:
            ca = init_or_load_ca(settings)
        except CAError as exc:
            raise RuntimeError(f"refusing to start: {exc}") from exc
        db = Database(settings.db_path)
        db.init_schema(ca.fingerprint_hex)
        app.state.service = CertificateService(settings, ca, db)
        try:
            yield
        finally:
            db.close()

    app = FastAPI(title="Local Test CA", lifespan=lifespan)

    def service() -> CertificateService:
        return app.state.service

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/ca", responses={200: {"content": {"application/x-pem-file": {}}}})
    def download_ca():
        return Response(
            content=service().ca.cert_pem,
            media_type="application/x-pem-file",
            headers={"Content-Disposition": 'attachment; filename="ca.cert.pem"'},
        )

    @app.post("/certificates")
    def issue_certificate(req: IssueRequest):
        try:
            payload, created = service().issue(req.csr, req.days, req.idempotency_key)
        except PolicyError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except IdempotencyConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        from fastapi.responses import JSONResponse

        return JSONResponse(
            content=payload,
            status_code=201 if created else 200,
        )

    @app.get("/certificates/{serial}")
    def get_certificate(serial: int):
        payload = service().get_certificate(serial)
        if payload is None:
            raise HTTPException(status_code=404, detail="unknown certificate serial")
        return payload

    @app.post("/certificates/{serial}/revoke")
    def revoke_certificate(serial: int, req: RevokeRequest):
        try:
            return service().revoke(serial, req.reason)
        except PolicyError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except RevocationConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/crl/publish")
    def publish_crl():
        crl_pem, number = service().publish_crl()
        return {"crl_number": number, "crl": crl_pem.decode("ascii")}

    @app.get("/crl", responses={200: {"content": {"application/x-pem-file": {}}}})
    def download_crl():
        crl_pem = service().current_crl()
        if crl_pem is None:
            raise HTTPException(status_code=404, detail="no CRL has been published yet")
        return Response(
            content=crl_pem,
            media_type="application/x-pem-file",
            headers={"Content-Disposition": 'attachment; filename="crl.pem"'},
        )

    return app
