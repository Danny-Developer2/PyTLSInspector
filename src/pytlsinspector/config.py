"""Configuración de PyTLSInspector y catálogos de protocolos y cifrados."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from pytlsinspector.models import Scope


@dataclass(slots=True)
class AuditConfig:
    """Configuración de una auditoría TLS."""

    target: str
    port: int = 443
    timeout: float = 10.0
    verify_tls: bool = True
    probe_ciphers: bool = True
    max_ciphers: int = 32
    concurrency: int = 8
    rate_limit: float = 8.0
    scope: Scope | None = None
    scope_file: str | None = None
    confirm_authorized: bool = False


# Protocolos que se prueban, en orden de preferencia histórica.
TLS_PROTOCOLS: tuple[tuple[str, str, bool], ...] = (
    # (nombre, identificador interno, obsoleto)
    ("SSLv2", "SSLv2", True),
    ("SSLv3", "SSLv3", True),
    ("TLS 1.0", "TLSv1", True),
    ("TLS 1.1", "TLSv1_1", True),
    ("TLS 1.2", "TLSv1_2", False),
    ("TLS 1.3", "TLSv1_3", False),
)

# Configuraciones de cifrado obsoletas o débiles que deben detectarse.
WEAK_CIPHER_MARKERS: tuple[str, ...] = (
    "RC4",
    "DES",
    "3DES",
    "MD5",
    "SHA1",
    "NULL",
    "EXPORT",
    "anon",
    "IDEA",
    "SEED",
    "ARIA-128",
    "DES-CBC",
    "eNULL",
    "aNULL",
)

# Conjuntos de cifrado que se prueban individualmente.
# (nombre, fortaleza estimada, intercambio de claves, notas)
CIPHER_SUITES: tuple[tuple[str, str, str | None, str | None], ...] = (
    ("TLS_AES_256_GCM_SHA384", "fuerte", "ECDHE", "TLS 1.3, AEAD, PFS"),
    ("TLS_CHACHA20_POLY1305_SHA256", "fuerte", "ECDHE", "TLS 1.3, AEAD, PFS"),
    ("TLS_AES_128_GCM_SHA256", "fuerte", "ECDHE", "TLS 1.3, AEAD, PFS"),
    ("ECDHE-RSA-AES256-GCM-SHA384", "fuerte", "ECDHE", "PFS con curva elíptica"),
    ("ECDHE-RSA-AES128-GCM-SHA256", "fuerte", "ECDHE", "PFS con curva elíptica"),
    ("ECDHE-RSA-CHACHA20-POLY1305", "fuerte", "ECDHE", "PFS con curva elíptica"),
    ("DHE-RSA-AES256-GCM-SHA384", "fuerte", "DHE", "PFS con Diffie-Hellman"),
    ("DHE-RSA-AES128-GCM-SHA256", "fuerte", "DHE", "PFS con Diffie-Hellman"),
    ("ECDHE-RSA-AES256-SHA384", "media", "ECDHE", "CBC, sin AEAD"),
    ("ECDHE-RSA-AES128-SHA256", "media", "ECDHE", "CBC, sin AEAD"),
    ("AES256-GCM-SHA384", "media", "RSA", "Sin secreto directo (PFS)"),
    ("AES128-GCM-SHA256", "media", "RSA", "Sin secreto directo (PFS)"),
    ("AES256-SHA256", "debil", "RSA", "CBC y sin PFS"),
    ("AES128-SHA", "debil", "RSA", "CBC y sin PFS"),
    ("DES-CBC3-SHA", "debil", "RSA", "3DES, considerado obsoleto"),
    ("RC4-SHA", "debil", "RSA", "RC4, roto en la práctica"),
    ("RC4-MD5", "debil", "RSA", "RC4 y MD5, ambos obsoletos"),
    ("EXP-RC4-MD5", "debil", "RSA", "Cifrado de exportación, extremadamente débil"),
    ("NULL-SHA256", "debil", "RSA", "Sin cifrado efectivo"),
    ("ECDHE-RSA-NULL-SHA", "debil", "ECDHE", "Sin cifrado efectivo"),
)

CipherStrength = Literal["fuerte", "media", "debil", "desconocida"]

# Recomendaciones de protocolo para el informe.
RECOMMENDED_MIN_PROTOCOL = "TLS 1.2"
RECOMMENDED_PROTOCOLS = ("TLS 1.2", "TLS 1.3")

# Longitudes de clave mínimas consideradas aceptables.
MIN_RSA_KEY_SIZE = 2048
MIN_EC_KEY_SIZE = 224

# Días de antelación para avisar de la caducidad.
EXPIRY_WARNING_DAYS = 30

# Referencias técnicas.
REFERENCES: dict[str, list[str]] = {
    "protocolos": [
        "https://owasp.org/www-project-transport-layer-protection-cheat-sheet/",
        "https://datatracker.ietf.org/doc/html/rfc8996",
    ],
    "certificado": [
        "https://owasp.org/www-project-web-security-testing-guide/",
        "https://cabforum.org/",
    ],
    "cifrados": [
        "https://ciphersuite.info/",
        "https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml",
    ],
    "confianza": ["https://docs.python.org/3/library/ssl.html"],
    "hostname": ["https://datatracker.ietf.org/doc/html/rfc6125"],
}


@dataclass(slots=True)
class TLSDefaults:
    """Valores por defecto reutilizables."""

    port: int = 443
    timeout: float = 10.0
    concurrency: int = 8
    rate_limit: float = 8.0


MAX_CIPHERS_DEFAULT = 32


__all__ = [
    "AuditConfig",
    "CipherStrength",
    "CIPHER_SUITES",
    "EXPIRY_WARNING_DAYS",
    "MAX_CIPHERS_DEFAULT",
    "MIN_EC_KEY_SIZE",
    "MIN_RSA_KEY_SIZE",
    "RECOMMENDED_MIN_PROTOCOL",
    "RECOMMENDED_PROTOCOLS",
    "REFERENCES",
    "TLS_PROTOCOLS",
    "TLSDefaults",
    "WEAK_CIPHER_MARKERS",
]


MAX_CIPHERS_DEFAULT = 32
