"""Root CA lifecycle, certificate issuance and CRL signing."""
from __future__ import annotations

import datetime as dt
import os
import sqlite3

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from .settings import Settings


CA_VALIDITY_DAYS = 3650
CRL_NEXT_UPDATE_DAYS = 7


class CAError(RuntimeError):
    pass


def _utcnow() -> dt.datetime:
    return dt.datetime.utcnow()


class CertificateAuthority:
    def __init__(self, cert: x509.Certificate, key: rsa.RSAPrivateKey):
        self.cert = cert
        self.key = key

    @property
    def cert_pem(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.PEM)

    @property
    def fingerprint_hex(self) -> str:
        return self.cert.fingerprint(hashes.SHA256()).hex()

    def issue_certificate(self, public_key, san_dns_names: list[str], days: int, serial: int) -> bytes:
        now = _utcnow()
        not_after = min(now + dt.timedelta(days=days), self.cert.not_valid_after)
        if not_after <= now:
            raise CAError("CA certificate has expired")
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([]))
            .issuer_name(self.cert.subject)
            .public_key(public_key)
            .serial_number(serial)
            .not_valid_before(now)
            .not_valid_after(not_after)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(public_key),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=None,
                    decipher_only=None,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(name) for name in san_dns_names]),
                critical=False,
            )
        )
        cert = builder.sign(self.key, hashes.SHA256())
        return cert.public_bytes(serialization.Encoding.PEM)

    def build_crl(
        self,
        number: int,
        revoked: list[tuple[int, dt.datetime, x509.ReasonFlags]],
    ) -> bytes:
        now = _utcnow()
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(self.cert.subject)
            .last_update(now)
            .next_update(now + dt.timedelta(days=CRL_NEXT_UPDATE_DAYS))
            .add_extension(x509.CRLNumber(number), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()),
                critical=False,
            )
        )
        for serial, revoked_at, reason in revoked:
            revoked_builder = (
                x509.RevokedCertificateBuilder()
                .serial_number(serial)
                .revocation_date(revoked_at)
                .add_extension(x509.CRLReason(reason), critical=False)
            )
            builder = builder.add_revoked_certificate(revoked_builder.build())
        crl = builder.sign(self.key, hashes.SHA256())
        return crl.public_bytes(serialization.Encoding.PEM)


def _generate_ca(settings: Settings) -> CertificateAuthority:
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    now = _utcnow()
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Local Lab Test CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Local Lab Test Root CA"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=CA_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    fd = os.open(settings.ca_key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key_pem)
    with open(settings.ca_cert_path, "xb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    return CertificateAuthority(cert, key)


def _load_ca(settings: Settings) -> CertificateAuthority:
    with open(settings.ca_key_path, "rb") as fh:
        key = serialization.load_pem_private_key(fh.read(), password=None)
    with open(settings.ca_cert_path, "rb") as fh:
        cert = x509.load_pem_x509_certificate(fh.read())
    if not isinstance(key, rsa.RSAPrivateKey):
        raise CAError("CA private key type is unsupported")
    return CertificateAuthority(cert, key)


def init_or_load_ca(settings: Settings) -> CertificateAuthority:
    """Initialise a fresh CA in an empty data dir, or reuse the existing one.

    Refuse to start when data exists but the CA files / database are missing
    or do not match each other.
    """
    os.makedirs(settings.data_dir, exist_ok=True)
    entries = {e.name for e in os.scandir(settings.data_dir)}
    ca_files_present = {
        settings.ca_key_path and os.path.basename(settings.ca_key_path),
        os.path.basename(settings.ca_cert_path),
    }.issubset(entries)
    db_present = os.path.basename(settings.db_path) in entries

    if not entries:
        ca = _generate_ca(settings)
        from .storage import Database

        db = Database(settings.db_path)
        db.init_schema(ca.fingerprint_hex)
        db.close()
        return ca

    if not ca_files_present:
        raise CAError(
            "data directory is not empty but CA key/certificate is missing; refusing to start"
        )
    if not db_present:
        raise CAError("data directory contains CA files but database is missing; refusing to start")

    ca = _load_ca(settings)
    from .storage import Database

    db = Database(settings.db_path)
    try:
        stored = db.get_ca_fingerprint()
    except sqlite3.DatabaseError as exc:
        raise CAError(f"cannot read CA metadata from database: {exc}") from exc
    finally:
        db.close()
    if stored != ca.fingerprint_hex:
        raise CAError(
            "CA certificate does not match the one recorded in the database; refusing to start"
        )
    return ca
