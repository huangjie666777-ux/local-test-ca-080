"""Application service: coordinates policy, CA signing, storage and CRL file."""
from __future__ import annotations

import datetime as dt
import os
import tempfile
import threading

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .ca_service import CertificateAuthority
from .policy import REASON_MAP, PolicyError, validate_csr
from .settings import Settings
from .storage import Database, RevocationConflict


class CertificateService:
    def __init__(self, settings: Settings, ca: CertificateAuthority, db: Database):
        self.settings = settings
        self.ca = ca
        self.db = db
        self._publish_lock = threading.Lock()

    def issue(self, csr_pem: str, days: int, idempotency_key: str) -> tuple[dict, bool]:
        """Returns (payload, created). Replays the original cert on idempotent retries."""
        if not isinstance(idempotency_key, str) or not idempotency_key.strip():
            raise PolicyError("idempotency_key must be a non-empty string")
        idempotency_key = idempotency_key.strip()
        if not isinstance(days, int) or isinstance(days, bool) or not (1 <= days <= 30):
            raise PolicyError("days must be an integer between 1 and 30")

        try:
            csr = x509.load_pem_x509_csr(csr_pem.encode("ascii"))
        except (ValueError, TypeError) as exc:
            raise PolicyError(f"invalid PEM CSR: {exc}") from exc

        san_names = validate_csr(csr)
        csr_der = csr.public_bytes(serialization.Encoding.DER)
        san_text = ",".join(san_names)

        def signer(serial: int) -> bytes:
            return self.ca.issue_certificate(csr.public_key(), san_names, days, serial)

        row, created = self.db.create_certificate(
            idempotency_key,
            csr_der,
            days,
            san_text,
            dt.datetime.utcnow(),
            signer,
        )

        return self._cert_payload(row), created

    @staticmethod
    def _cert_payload(row) -> dict:
        revoked_at = row["revoke_time"] if "revoke_time" in row.keys() else None
        reason = row["revoke_reason"] if "revoke_reason" in row.keys() else None
        return {
            "serial_number": row["serial"],
            "certificate": row["certificate_pem"],
            "san": row["san"].split(","),
            "days": row["days"],
            "status": "revoked" if revoked_at else "valid",
            "revoked_at": revoked_at,
            "revocation_reason": reason,
        }

    def get_certificate(self, serial: int):
        row = self.db.get_certificate(serial)
        return self._cert_payload(row) if row else None

    def revoke(self, serial: int, reason: str) -> dict:
        if reason not in REASON_MAP:
            raise PolicyError(
                "unsupported revocation reason; allowed: " + ", ".join(sorted(REASON_MAP))
            )
        revoked_at, _already = self.db.revoke(serial, reason)
        return self.get_certificate(serial)

    def publish_crl(self) -> tuple[bytes, int]:
        """Build, persist number for, and atomically write a fresh full CRL."""
        with self._publish_lock:
            revoked = self.db.list_revoked()
            number = self.db.next_crl_number()
            crl_pem = self.ca.build_crl(number, revoked)
            self._atomic_write(self.settings.crl_path, crl_pem)
            return crl_pem, number

    def current_crl(self) -> bytes | None:
        if not os.path.exists(self.settings.crl_path):
            return None
        with open(self.settings.crl_path, "rb") as fh:
            return fh.read()

    @staticmethod
    def _atomic_write(path: str, data: bytes) -> None:
        directory = os.path.dirname(path) or "."
        fd, tmp_path = tempfile.mkstemp(prefix=".crl-", dir=directory)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_path, path)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
