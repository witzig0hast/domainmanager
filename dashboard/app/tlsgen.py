"""Create a self-signed certificate on first start so the dashboard speaks HTTPS out of the box."""
from __future__ import annotations

import datetime
import ipaddress
import os
import socket
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def ensure(cert: Path, key: Path, names: list[str]) -> None:
    if cert.exists() and key.exists():
        return
    cert.parent.mkdir(parents=True, exist_ok=True)
    pk = ec.generate_private_key(ec.SECP256R1())
    sans: list[x509.GeneralName] = []
    for n in names:
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            sans.append(x509.DNSName(n))
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
    crt = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject)
        .public_key(pk.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=825))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(pk, hashes.SHA256())
    )
    fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    cert.write_bytes(crt.public_bytes(serialization.Encoding.PEM))
    print(f"Selbstsigniertes Zertifikat erzeugt: {cert} ({', '.join(names)})", flush=True)


if __name__ == "__main__":
    extra = [n.strip() for n in os.environ.get("TLS_HOSTNAMES", "").split(",") if n.strip()]
    ensure(Path(sys.argv[1]), Path(sys.argv[2]), extra + ["localhost", "127.0.0.1", socket.gethostname()])
