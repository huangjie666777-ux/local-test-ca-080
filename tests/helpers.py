import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def make_csr(names, key_size=2048, cn=None, invalid_signature=False):
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)] if cn else []
    builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(attrs))
    if names is not None:
        general = [
            x509.IPAddress(ipaddress.ip_address("10.0.0.1"))
            if item == "IP"
            else x509.DNSName(item)
            for item in names
        ]
        builder = builder.add_extension(x509.SubjectAlternativeName(general), critical=False)
    csr = builder.sign(key, hashes.SHA256())
    if invalid_signature:
        # Rebuild the DER with one signature byte flipped.
        der = bytearray(csr.public_bytes(serialization.Encoding.DER))
        sig_len = len(csr.signature)
        der[-1 - sig_len // 2] ^= 0x01
        broken = x509.load_der_x509_csr(bytes(der))
        return broken.public_bytes(serialization.Encoding.PEM)
    return csr.public_bytes(serialization.Encoding.PEM)
