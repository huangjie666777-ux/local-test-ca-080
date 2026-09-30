"""CSR validation and name policy."""
from __future__ import annotations

import re

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


# Request spelling -> X.509 CRL reason.
REASON_MAP: dict[str, x509.ReasonFlags] = {
    "unspecified": x509.ReasonFlags.unspecified,
    "key_compromise": x509.ReasonFlags.key_compromise,
    "ca_compromise": x509.ReasonFlags.ca_compromise,
    "affiliation_changed": x509.ReasonFlags.affiliation_changed,
    "superseded": x509.ReasonFlags.superseded,
    "cessation_of_operation": x509.ReasonFlags.cessation_of_operation,
    "certificate_hold": x509.ReasonFlags.certificate_hold,
    "privilege_withdrawn": x509.ReasonFlags.privilege_withdrawn,
    "aa_compromise": x509.ReasonFlags.aa_compromise,
}


ALLOWED_BASE_DOMAIN = "lab.test"
MIN_RSA_KEY_SIZE = 2048


class PolicyError(ValueError):
    pass


_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def _valid_dns_label(label: str) -> bool:
    return bool(label) and len(label) <= 63 and _LABEL_RE.fullmatch(label) is not None


def _normalize_dns_name(value: str) -> str:
    name = value.strip().casefold().rstrip(".")
    if not name or "*" in name or ".." in name:
        raise PolicyError("invalid DNS name in SAN")
    labels = name.split(".")
    if not all(_valid_dns_label(label) for label in labels):
        raise PolicyError("invalid DNS name in SAN")
    base = ALLOWED_BASE_DOMAIN.split(".")
    if labels == base:
        return name
    if len(labels) > len(base) and labels[-len(base):] == base:
        return name
    raise PolicyError(f"SAN DNS name must be {ALLOWED_BASE_DOMAIN} or a subdomain")


def validate_csr(csr: x509.CertificateSigningRequest) -> list[str]:
    """Validate CSR and return normalized, deduplicated, sorted SAN DNS names."""
    if not csr.is_signature_valid:
        raise PolicyError("CSR signature is invalid")

    public_key = csr.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise PolicyError("only RSA public keys are accepted")
    if public_key.key_size < MIN_RSA_KEY_SIZE:
        raise PolicyError(f"RSA key must be at least {MIN_RSA_KEY_SIZE} bits")

    try:
        san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        raise PolicyError("subjectAltName is required; CN cannot be used instead") from None

    names = san_ext.value
    if not names:
        raise PolicyError("subjectAltName must be non-empty")

    # Only DNS names are permitted: any other GeneralName type is rejected.
    all_values = list(names)
    dns_names = names.get_values_for_type(x509.DNSName)
    if len(all_values) != len(dns_names):
        raise PolicyError("subjectAltName may contain DNS names only")

    normalized = {_normalize_dns_name(name) for name in dns_names}
    if not normalized:
        raise PolicyError("subjectAltName must be non-empty")

    # CN can never substitute for SAN; it is not consulted for names.
    _ = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return sorted(normalized)
