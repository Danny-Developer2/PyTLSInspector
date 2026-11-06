"""Obtención y análisis de certificados X.509."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
from datetime import UTC, datetime
from typing import cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from pytlsinspector.exceptions import ConnectionError
from pytlsinspector.models import CertificateInfo, ChainInfo
from pytlsinspector.utils.logger import get_logger
from pytlsinspector.utils.net import is_ip_address

_logger = get_logger("core.certificate")

# Atributos de los certificados que interesan al análisis.
_NAME_ATTRIBUTES = {
    "CN": NameOID.COMMON_NAME,
    "O": NameOID.ORGANIZATION_NAME,
    "C": NameOID.COUNTRY_NAME,
}


async def fetch_chain(
    host: str,
    port: int,
    timeout: float = 10.0,
    verify_tls: bool = True,
) -> ChainInfo:
    """Obtiene la cadena de certificados servida por el objetivo.

    Primero intenta la validación completa contra el almacén de confianza del
    sistema; si falla (por ejemplo, certificado autofirmado), reintenta sin
    verificación para poder analizar igualmente el certificado.

    Raises:
        ConnectionError: Si no se puede establecer la conexión TLS.
    """
    return await asyncio.to_thread(_fetch_sync, host, port, timeout, verify_tls)


def _fetch_sync(
    host: str,
    port: int,
    timeout: float,
    verify_tls: bool,
) -> ChainInfo:
    """Implementación síncrona de la obtención de la cadena."""
    # Python exige server_hostname cuando check_hostname está activo; se usa el
    # propio host, que puede ser una IP (se verifica contra los SAN de tipo IP).
    verification_error: str | None = None
    verified = False

    if verify_tls:
        chain, error = _connect(host, port, timeout, host, verify=True)
        if chain:
            verified = True
        else:
            verification_error = error
            _logger.debug(
                "verificación fallida (%s); se reintenta sin verificar", error or "sin cadena"
            )
            chain, error = _connect(host, port, timeout, host, verify=False)
    else:
        chain, error = _connect(host, port, timeout, host, verify=False)

    if not chain:
        raise ConnectionError(
            f"no se pudo obtener la cadena de certificados de {host}:{port}"
            + (f": {error}" if error else "")
        )

    certificates = [parse_certificate(der, position) for position, der in enumerate(chain)]
    return ChainInfo(
        certificates=certificates,
        leaf=certificates[0] if certificates else None,
        trusted=verified,
        verification_error=verification_error,
    )


def _connect(
    host: str,
    port: int,
    timeout: float,
    server_hostname: str | None,
    verify: bool,
) -> tuple[list[bytes], str | None]:
    """Establece la conexión TLS y devuelve los certificados en formato DER."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED

    if verify:
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_default_certs()
    else:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    error: str | None = None
    try:
        with (
            socket.create_connection((host, port), timeout=timeout) as sock,
            context.wrap_socket(sock, server_hostname=server_hostname) as tls,
        ):
            return _extract_der_chain(tls), None
    except ssl.SSLCertVerificationError as exc:
        error = str(exc)
        return [], error
    except ssl.SSLError as exc:
        error = str(exc)
        return [], error
    except OSError as exc:
        error = str(exc)
        return [], error


def _extract_der_chain(tls: ssl.SSLSocket) -> list[bytes]:
    """Extrae la cadena en formato DER, con y sin verificación."""
    getter = getattr(tls, "get_verified_chain", None)
    if getter is not None:
        try:
            chain = getter()
            if chain:
                return list(chain)
        except (ValueError, ssl.SSLError):
            pass

    binary = tls.getpeercert(binary_form=True)
    return [binary] if binary else []


def parse_certificate(der: bytes, position: int = 0) -> CertificateInfo:
    """Convierte un certificado DER en un objeto ``CertificateInfo``."""
    cert = x509.load_der_x509_certificate(der)

    san_dns, san_ip = _extract_subject_alt_names(cert)
    common_name = _extract_common_name(cert)
    public_key = cert.public_key()

    return CertificateInfo(
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        serial_number=format(cert.serial_number, "x"),
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        signature_algorithm=_signature_algorithm_name(cert),
        key_algorithm=type(public_key).__name__,
        key_size=_key_size(public_key),
        common_name=common_name,
        san_dns=san_dns,
        san_ip=san_ip,
        is_self_signed=cert.subject == cert.issuer,
        is_ca=_is_ca(cert),
        version=_certificate_version(cert),
        sha256_fingerprint=cert.fingerprint(hashes.SHA256()).hex(),
        position=position,
    )


def _extract_subject_alt_names(cert: x509.Certificate) -> tuple[list[str], list[str]]:
    """Extrae los nombres DNS e IP de la extensión Subject Alternative Name."""
    try:
        extension = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except x509.ExtensionNotFound:
        return [], []

    san = cast(x509.SubjectAlternativeName, extension.value)
    names = list(san.get_values_for_type(x509.DNSName))
    addresses = [str(value) for value in san.get_values_for_type(x509.IPAddress)]
    return names, addresses


def _extract_common_name(cert: x509.Certificate) -> str:
    """Extrae el nombre común del sujeto."""
    attributes = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(attributes[0].value) if attributes else ""


def _is_ca(cert: x509.Certificate) -> bool:
    """Indica si el certificado está marcado como autoridad de certificación."""
    try:
        extension = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
    except x509.ExtensionNotFound:
        return False
    constraints = cast(x509.BasicConstraints, extension.value)
    return bool(constraints.ca)


def _certificate_version(cert: x509.Certificate) -> int | None:
    """Devuelve la versión del certificado (1, 2 o 3)."""
    try:
        return int(cert.version.value)
    except (ValueError, AttributeError):
        return None


def _signature_algorithm_name(cert: x509.Certificate) -> str:
    """Devuelve el nombre del algoritmo de firma."""
    oid = cert.signature_algorithm_oid
    name = getattr(oid, "_name", None)
    if name:
        return str(name)
    return str(oid.dotted_string)


def _key_size(public_key: object) -> int | None:
    """Devuelve el tamaño de clave en bits, si es conocido."""
    key_size = getattr(public_key, "key_size", None)
    return int(key_size) if key_size is not None else None


def verify_hostname(cert: CertificateInfo, host: str) -> bool:
    """Comprueba si el certificado cubre el nombre de host indicado.

    Admite comodines de un solo nivel (``*.ejemplo.com``) y compara sin
    distinguir mayúsculas de minúsculas.
    """
    candidate = host.strip().lower().rstrip(".")

    if is_ip_address(candidate):
        return candidate in {str(ip).lower() for ip in cert.san_ip}

    # Se conservan los comodines; la comparación los trata en _dns_matches.
    names = [name.lower() for name in cert.san_dns]
    names.append(cert.common_name.lower())

    return any(_dns_matches(candidate, name) for name in names)


def _dns_matches(host: str, pattern: str) -> bool:
    """Compara un nombre de host con un patrón que puede incluir comodín."""
    if pattern.startswith("*."):
        suffix = pattern[1:]  # incluye el punto
        return host.endswith(suffix) and "." not in host[: -len(suffix)]
    return host == pattern


def is_expired(cert: CertificateInfo) -> bool:
    """Indica si el certificado ha caducado."""
    return datetime.now(UTC) > cert.not_after


def is_not_yet_valid(cert: CertificateInfo) -> bool:
    """Indica si el certificado aún no es válido."""
    return datetime.now(UTC) < cert.not_before


def is_weak_signature(cert: CertificateInfo) -> bool:
    """Indica si el algoritmo de firma se considera obsoleto."""
    return cert.signature_algorithm.upper().startswith(("MD5", "SHA1", "SHA-1", "MD2", "MD4"))


def is_weak_key(cert: CertificateInfo) -> bool:
    """Indica si la clave pública es demasiado corta."""
    if cert.key_size is None:
        return False
    return cert.key_size < 2048


def key_type(cert: CertificateInfo) -> str:
    """Clasifica el tipo de clave pública del certificado."""
    name = cert.key_algorithm.lower()
    if "rsa" in name:
        return "rsa"
    if "ec" in name or "elliptic" in name:
        return "ec"
    if "dsa" in name:
        return "dsa"
    if "ed25519" in name or "ed448" in name:
        return "edwards"
    return "desconocido"


__all__ = [
    "fetch_chain",
    "is_expired",
    "is_not_yet_valid",
    "is_weak_key",
    "is_weak_signature",
    "key_type",
    "parse_certificate",
    "verify_hostname",
]


# Referencias cruzadas para evitar importaciones no usadas.
_ = (ec, rsa, ipaddress)
