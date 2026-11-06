"""Configuración común de las pruebas de PyTLSInspector.

Genera certificados autofirmados en tiempo de ejecución y levanta servidores
TLS locales para probar la herramienta sin acceder a la red.
"""

from __future__ import annotations

import datetime
import ipaddress
import ssl
import tempfile
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# Momento de referencia para las fechas de validez.
NOW = datetime.datetime.now(datetime.UTC)

# Cifrados que el laboratorio ofrece por defecto: solo conjuntos fuertes con PFS.
DEFAULT_LAB_CIPHERS = (
    "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:"
    "!aNULL:!eNULL:!NULL:!MD5:!SHA1:!RC4:!3DES:!DES:!EXPORT:"
    "!NULL-SHA:!NULL-SHA256:!NULL-SHA384:!ECDHE-RSA-NULL-SHA"
)


@dataclass(frozen=True)
class GeneratedCertificate:
    """Certificado generado para las pruebas."""

    cert_path: Path
    key_path: Path
    common_name: str
    san_dns: tuple[str, ...]
    key_size: int
    not_before: datetime.datetime
    not_after: datetime.datetime


def _build_certificate(
    *,
    common_name: str = "localhost",
    san_dns: tuple[str, ...] = ("localhost",),
    san_ip: tuple[str, ...] = (),
    key_size: int = 2048,
    days_valid: int = 365,
    not_before_offset: int = -1,
    signature_hash: object = hashes.SHA256,
) -> GeneratedCertificate:
    """Genera un certificado autofirmado y lo guarda en un fichero temporal."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])

    alt_names: list[x509.GeneralName] = [x509.DNSName(name) for name in san_dns]
    alt_names.extend(x509.IPAddress(ipaddress.ip_address(name)) for name in san_ip)

    not_before = NOW + datetime.timedelta(days=not_before_offset)
    not_after = NOW + datetime.timedelta(days=days_valid)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.SubjectAlternativeName(alt_names), critical=False)
        .sign(key, signature_hash())
    )

    directory = Path(tempfile.mkdtemp(prefix="pytls-"))
    cert_path = directory / "cert.pem"
    key_path = directory / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    return GeneratedCertificate(
        cert_path=cert_path,
        key_path=key_path,
        common_name=common_name,
        san_dns=san_dns,
        key_size=key_size,
        not_before=not_before,
        not_after=not_after,
    )


class _Handler(BaseHTTPRequestHandler):
    """Manejador mínimo para el servidor TLS de pruebas."""

    protocol_version = "HTTP/1.0"

    def do_GET(self) -> None:  # noqa: N802
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        return


@dataclass
class TLSServer:
    """Servidor TLS local con certificado generado."""

    server: ThreadingHTTPServer
    context: ssl.SSLContext
    certificate: GeneratedCertificate

    @property
    def url(self) -> str:
        """URL base del servidor."""
        return f"https://127.0.0.1:{self.server.server_address[1]}/"

    @property
    def port(self) -> int:
        """Puerto de escucha."""
        return self.server.server_address[1]

    def stop(self) -> None:
        """Detiene el servidor."""
        self.server.shutdown()
        self.server.server_close()


def start_tls_server(
    *,
    certificate: GeneratedCertificate | None = None,
    min_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2,
    max_version: ssl.TLSVersion = ssl.TLSVersion.MAXIMUM_SUPPORTED,
    ciphers: str | None = DEFAULT_LAB_CIPHERS,
) -> TLSServer:
    """Levanta un servidor TLS local con la configuración indicada."""
    cert = certificate or _build_certificate()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert.cert_path), str(cert.key_path))
    context.minimum_version = min_version
    context.maximum_version = max_version
    if ciphers:
        context.set_ciphers(ciphers)

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)

    instance = TLSServer(server=server, context=context, certificate=cert)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return instance


@pytest.fixture(scope="session")
def self_signed_certificate() -> GeneratedCertificate:
    """Certificado autofirmado estándar."""
    return _build_certificate()


@pytest.fixture()
def tls_server(self_signed_certificate: GeneratedCertificate):
    """Servidor TLS con TLS 1.2 y 1.3 habilitados."""
    instance = start_tls_server(certificate=self_signed_certificate)
    yield instance
    instance.stop()


@pytest.fixture(scope="session")
def expired_certificate() -> GeneratedCertificate:
    """Certificado ya caducado."""
    return _build_certificate(days_valid=-1, not_before_offset=-30)


@pytest.fixture(scope="session")
def weak_key_certificate() -> GeneratedCertificate:
    """Certificado con clave RSA corta."""
    return _build_certificate(key_size=1024)


@pytest.fixture(scope="session")
def hostname_mismatch_certificate() -> GeneratedCertificate:
    """Certificado que no cubre el nombre de host utilizado."""
    return _build_certificate(common_name="otro.ejemplo", san_dns=("otro.ejemplo",))


__all__ = [
    "GeneratedCertificate",
    "TLSServer",
    "_build_certificate",
    "ipaddress",
    "ssl",
    "start_tls_server",
]
