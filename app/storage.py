"""SQLite persistence for certificates, idempotency keys and revocations."""
from __future__ import annotations

import datetime as dt
import sqlite3
import threading
from typing import Optional

from cryptography import x509


SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    ca_fingerprint TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS certificates (
    serial INTEGER PRIMARY KEY AUTOINCREMENT,
    idempotency_key TEXT NOT NULL UNIQUE,
    csr_der BLOB NOT NULL,
    days INTEGER NOT NULL,
    san TEXT NOT NULL,
    certificate_pem TEXT NOT NULL,
    issued_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS revocations (
    serial INTEGER PRIMARY KEY
        REFERENCES certificates(serial),
    reason TEXT NOT NULL,
    revoked_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS crl_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    crl_number INTEGER NOT NULL
);
"""


class IdempotencyConflict(Exception):
    pass


class RevocationConflict(Exception):
    pass


def parse_iso(value: str) -> dt.datetime:
    return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%f")


class Database:
    def __init__(self, db_path: str):
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            db_path, timeout=30, isolation_level=None, check_same_thread=False
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA busy_timeout=30000")

    def init_schema(self, ca_fingerprint: str) -> None:
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.execute(
                "INSERT OR IGNORE INTO meta (id, ca_fingerprint) VALUES (1, ?)",
                (ca_fingerprint,),
            )

    def get_ca_fingerprint(self) -> Optional[str]:
        with self._lock:
            row = self._conn.execute("SELECT ca_fingerprint FROM meta WHERE id = 1").fetchone()
            return row["ca_fingerprint"] if row else None

    def get_by_idempotency_key(self, key: str) -> Optional[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM certificates WHERE idempotency_key = ?",
                (key,),
            ).fetchone()

    def create_certificate(
        self,
        key: str,
        csr_der: bytes,
        days: int,
        san: str,
        issued_at: dt.datetime,
        signer,
    ) -> tuple:
        """Persist a new certificate under one IMMEDIATE transaction.

        The serial is allocated first and passed to ``signer(serial)`` which
        returns the PEM bytes; the row is then back-filled. Any signing failure
        rolls back, leaving no partial record. Concurrent retries lose the
        transaction lock and read the winner's row instead.

        Raises IdempotencyConflict when the key maps to different parameters.
        """
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                existing = self._conn.execute(
                    "SELECT * FROM certificates WHERE idempotency_key = ?",
                    (key,),
                ).fetchone()
                if existing is not None:
                    self._conn.execute("ROLLBACK")
                    self._check_same_request(existing, csr_der, days)
                    return existing, False
                cur = self._conn.execute(
                    "INSERT INTO certificates "
                    "(idempotency_key, csr_der, days, san, certificate_pem, issued_at) "
                    "VALUES (?, ?, ?, ?, '', ?)",
                    (key, csr_der, days, san, issued_at.isoformat()),
                )
                serial = cur.lastrowid
                certificate_pem = signer(serial)
                self._conn.execute(
                    "UPDATE certificates SET certificate_pem = ? WHERE serial = ?",
                    (certificate_pem.decode("ascii"), serial),
                )
                self._conn.execute("COMMIT")
            except (IdempotencyConflict, LookupError):
                raise
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
            row = self._conn.execute(
                "SELECT * FROM certificates WHERE serial = ?", (serial,)
            ).fetchone()
            return row, True

    @staticmethod
    def _check_same_request(row: sqlite3.Row, csr_der: bytes, days: int) -> None:
        if bytes(row["csr_der"]) != csr_der or row["days"] != days:
            raise IdempotencyConflict(
                "idempotency key was already used with a different CSR or days value"
            )

    def get_certificate(self, serial: int) -> Optional[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(
                """SELECT c.*, r.reason AS revoke_reason, r.revoked_at AS revoke_time
                   FROM certificates c
                   LEFT JOIN revocations r ON r.serial = c.serial
                   WHERE c.serial = ?""",
                (serial,),
            ).fetchone()

    def revoke(self, serial: int, reason: str) -> tuple[dt.datetime, bool]:
        """Revoke a certificate. Returns (revoked_at, already_revoked_same_reason).

        Unknown serial raises LookupError; differing reason raises
        RevocationConflict. First revocation time is always preserved.
        """
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                cert_row = self._conn.execute(
                    "SELECT serial FROM certificates WHERE serial = ?", (serial,)
                ).fetchone()
                if cert_row is None:
                    self._conn.execute("ROLLBACK")
                    raise LookupError(f"unknown certificate serial: {serial}")
                existing = self._conn.execute(
                    "SELECT reason, revoked_at FROM revocations WHERE serial = ?",
                    (serial,),
                ).fetchone()
                already = False
                if existing is not None:
                    if existing["reason"] != reason:
                        self._conn.execute("ROLLBACK")
                        raise RevocationConflict(
                            f"certificate already revoked with reason {existing['reason']}"
                        )
                    already = True
                    revoked_at = parse_iso(existing["revoked_at"])
                else:
                    revoked_at = dt.datetime.utcnow()
                    self._conn.execute(
                        "INSERT INTO revocations (serial, reason, revoked_at) VALUES (?, ?, ?)",
                        (serial, reason, revoked_at.isoformat()),
                    )
                self._conn.execute("COMMIT")
                return revoked_at, already
            except (LookupError, RevocationConflict):
                raise
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def list_revoked(self) -> list[tuple[int, dt.datetime, x509.ReasonFlags]]:
        with self._lock:
            rows = self._conn.execute(
                """SELECT r.serial, r.revoked_at, r.reason
                   FROM revocations r JOIN certificates c ON c.serial = r.serial
                   ORDER BY r.serial"""
            ).fetchall()
        from .policy import REASON_MAP
        result = []
        for row in rows:
            result.append((row["serial"], parse_iso(row["revoked_at"]), REASON_MAP[row["reason"]]))
        return result

    def next_crl_number(self) -> int:
        """Atomically increment and persist the CRL number under a transaction."""
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                row = self._conn.execute("SELECT crl_number FROM crl_state WHERE id = 1").fetchone()
                if row is None:
                    number = 1
                    self._conn.execute(
                        "INSERT INTO crl_state (id, crl_number) VALUES (1, 1)"
                    )
                else:
                    number = row["crl_number"] + 1
                    self._conn.execute(
                        "UPDATE crl_state SET crl_number = ? WHERE id = 1", (number,)
                    )
                self._conn.execute("COMMIT")
                return number
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def current_crl_number(self) -> Optional[int]:
        with self._lock:
            row = self._conn.execute("SELECT crl_number FROM crl_state WHERE id = 1").fetchone()
            return row["crl_number"] if row else None

    def close(self) -> None:
        with self._lock:
            self._conn.close()
