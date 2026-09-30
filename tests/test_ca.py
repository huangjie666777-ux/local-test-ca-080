import importlib
import os
import sys
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import ExtendedKeyUsageOID
from fastapi.testclient import TestClient

from tests.helpers import make_csr


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("CA_DATA_DIR", str(tmp_path))
    for mod in [m for m in list(sys.modules) if m.startswith("app.") or m == "app"]:
        del sys.modules[mod]
    main_mod = importlib.import_module("app.main")
    with TestClient(main_mod.app) as c:
        yield c, tmp_path, main_mod


def test_ca_initialized_and_reused_on_restart(client):
    c, data, main_mod = client
    assert os.path.exists(data / "ca.key.pem")
    mode = oct((data / "ca.key.pem").stat().st_mode & 0o777)
    assert mode == "0o600"
    ca_pem = c.get("/ca").content
    ca = x509.load_pem_x509_certificate(ca_pem)
    assert ca.issuer == ca.subject
    bc = ca.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is True

    with TestClient(main_mod.app) as c2:
        assert c2.get("/ca").content == ca_pem


def test_mismatched_ca_refuses_start(tmp_path, monkeypatch):
    monkeypatch.setenv("CA_DATA_DIR", str(tmp_path))
    for mod in [m for m in list(sys.modules) if m.startswith("app.")]:
        if mod != "app":
            del sys.modules[mod]
    main_mod = importlib.import_module("app.main")
    with TestClient(main_mod.app):
        pass
    os.unlink(tmp_path / "ca.cert.pem")
    with pytest.raises(RuntimeError, match="refusing to start"):
        with TestClient(main_mod.app):
            pass


def test_issue_success_and_constraints(client):
    c, _, _ = client
    csr = make_csr(["WWW.Lab.Test", "api.lab.test"])
    resp = c.post("/certificates", json={"csr": csr.decode(), "days": 30, "idempotency_key": "k1"})
    assert resp.status_code == 201, resp.text
    body = resp.json()
    serial = body["serial_number"]
    assert isinstance(serial, int) and serial > 0
    assert body["san"] == ["api.lab.test", "www.lab.test"]

    cert = x509.load_pem_x509_certificate(body["certificate"].encode())
    ca = x509.load_pem_x509_certificate(c.get("/ca").content)
    ca.public_key().verify(
        cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm
    )
    assert cert.not_valid_after <= ca.not_valid_after
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(eku) == [ExtendedKeyUsageOID.SERVER_AUTH]
    ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku.digital_signature and ku.key_encipherment and not ku.key_cert_sign


@pytest.mark.parametrize(
    "names,key_size,cn,days,msg",
    [
        (["evil.test"], 2048, None, 10, "lab.test"),
        (["*.lab.test"], 2048, None, 10, "invalid DNS"),
        (["bad..lab.test"], 2048, None, 10, "invalid DNS"),
        (None, 2048, "api.lab.test", 10, "subjectAltName is required"),
        (["IP"], 2048, None, 10, "DNS names only"),
        (["api.lab.test"], 1024, None, 10, "2048"),
        (["api.lab.test"], 2048, None, 0, "days"),
        (["api.lab.test"], 2048, None, 31, "days"),
        (["api.lab.test"], 2048, None, 1.5, "days"),
    ],
)

def test_validation_failures(client, names, key_size, cn, days, msg):
    c, _, _ = client
    csr = make_csr(names, key_size=key_size, cn=cn)
    resp = c.post("/certificates", json={"csr": csr.decode(), "days": days, "idempotency_key": "x"})
    assert resp.status_code == 400, resp.text
    assert msg in resp.json()["detail"]


def test_bad_csr_signature_rejected(client):
    c, _, _ = client
    csr = make_csr(["api.lab.test"], invalid_signature=True)
    resp = c.post("/certificates", json={"csr": csr.decode(), "days": 10, "idempotency_key": "x"})
    assert resp.status_code == 400


def test_idempotent_replay_and_conflict(client):
    c, _, _ = client
    csr = make_csr(["api.lab.test"])
    body = {"csr": csr.decode(), "days": 10, "idempotency_key": "k"}
    r1 = c.post("/certificates", json=body)
    r2 = c.post("/certificates", json=body)
    assert r1.status_code == 201 and r2.status_code == 200
    assert r1.json()["serial_number"] == r2.json()["serial_number"]
    assert r1.json()["certificate"] == r2.json()["certificate"]

    conflict = c.post("/certificates", json={**body, "days": 9})
    assert conflict.status_code == 409
    other_csr = make_csr(["api2.lab.test"]).decode()
    conflict2 = c.post("/certificates", json={**body, "csr": other_csr})
    assert conflict2.status_code == 409


def test_concurrent_identical_requests_single_record(client):
    c, _, main_mod = client
    csr_pem = make_csr(["api.lab.test"]).decode()
    results = []
    errors = []

    def worker():
        try:
            payload, created = main_mod.app.state.service.issue(
                csr_pem, 10, "race"
            )
            results.append((201 if created else 200, payload["serial_number"]))
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors
    assert len({serial for _, serial in results}) == 1


def test_revocation_lifecycle_and_conflict(client):
    c, _, _ = client
    csr = make_csr(["api.lab.test"]).decode()
    serial = c.post(
        "/certificates", json={"csr": csr, "days": 10, "idempotency_key": "k"}
    ).json()["serial_number"]

    assert c.post(f"/certificates/{serial}/revoke", json={"reason": "nope"}).status_code == 400
    assert c.post("/certificates/999999/revoke", json={"reason": "key_compromise"}).status_code == 404

    r1 = c.post(f"/certificates/{serial}/revoke", json={"reason": "key_compromise"})
    assert r1.status_code == 200 and r1.json()["status"] == "revoked"
    first_time = r1.json()["revoked_at"]
    r2 = c.post(f"/certificates/{serial}/revoke", json={"reason": "key_compromise"})
    assert r2.json()["revoked_at"] == first_time
    conflict = c.post(f"/certificates/{serial}/revoke", json={"reason": "superseded"})
    assert conflict.status_code == 409
    got = c.get(f"/certificates/{serial}")
    assert got.json()["status"] == "revoked"
    assert got.json()["revocation_reason"] == "key_compromise"


def test_crl_full_and_numbered_and_persistent(client):
    c, data, main_mod = client
    assert c.get("/crl").status_code == 404
    csr = make_csr(["a.lab.test"]).decode()
    s1 = c.post("/certificates", json={"csr": csr, "days": 5, "idempotency_key": "a"}).json()[
        "serial_number"
    ]
    c.post(f"/certificates/{s1}/revoke", json={"reason": "key_compromise"})

    p1 = c.post("/crl/publish")
    assert p1.status_code == 200 and p1.json()["crl_number"] == 1
    crl1 = x509.load_pem_x509_crl(c.get("/crl").content)
    assert crl1.get_revoked_certificate_by_serial_number(s1) is not None
    ca = x509.load_pem_x509_certificate(c.get("/ca").content)
    ca.public_key().verify(
        crl1.signature, crl1.tbs_certlist_bytes, padding.PKCS1v15(), crl1.signature_hash_algorithm
    )
    assert crl1.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number == 1

    csr2 = make_csr(["b.lab.test"]).decode()
    s2 = c.post("/certificates", json={"csr": csr2, "days": 5, "idempotency_key": "b"}).json()[
        "serial_number"
    ]
    c.post(f"/certificates/{s2}/revoke", json={"reason": "cessation_of_operation"})
    p2 = c.post("/crl/publish")
    assert p2.json()["crl_number"] == 2
    crl2 = x509.load_pem_x509_crl(p2.json()["crl"].encode())
    serials = {rc.serial_number for rc in crl2}
    assert serials == {s1, s2}
    assert crl2.last_update >= crl1.last_update

    # After restart numbering continues and the full CRL remains available.
    with TestClient(main_mod.app) as c3:
        p3 = c3.post("/crl/publish").json()
        assert p3["crl_number"] == 3
        crl3 = x509.load_pem_x509_crl(p3["crl"].encode())
        assert {rc.serial_number for rc in crl3} == {s1, s2}
        assert os.path.exists(data / "crl.pem")
