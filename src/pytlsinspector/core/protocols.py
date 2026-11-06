"""Detección de protocolos TLS admitidos por el servidor."""

from __future__ import annotations

import asyncio
import socket
import ssl

from pytlsinspector.config import TLS_PROTOCOLS
from pytlsinspector.models import TLSVersionInfo
from pytlsinspector.utils.logger import get_logger

_logger = get_logger("core.protocols")

# Mapeo de identificadores internos a versiones del módulo ssl.
_SSL_VERSIONS: dict[str, ssl.TLSVersion | None] = {
    "SSLv2": None,  # No soportado por el módulo ssl moderno.
    "SSLv3": None,
    "TLSv1": ssl.TLSVersion.TLSv1,
    "TLSv1_1": ssl.TLSVersion.TLSv1_1,
    "TLSv1_2": ssl.TLSVersion.TLSv1_2,
    "TLSv1_3": ssl.TLSVersion.TLSv1_3,
}

# Opciones que deshabilitan protocolos concretos.
_SSL_OPTIONS: dict[str, int | None] = {
    "SSLv2": getattr(ssl, "OP_NO_SSLv2", 0),
    "SSLv3": getattr(ssl, "OP_NO_SSLv3", 0),
    "TLSv1": getattr(ssl, "OP_NO_TLSv1", 0),
    "TLSv1_1": getattr(ssl, "OP_NO_TLSv1_1", 0),
    "TLSv1_2": getattr(ssl, "OP_NO_TLSv1_2", 0),
    "TLSv1_3": getattr(ssl, "OP_NO_TLSv1_3", 0),
}


async def probe_protocols(
    host: str,
    port: int,
    timeout: float = 10.0,
    concurrency: int = 4,
) -> list[TLSVersionInfo]:
    """Prueba cada protocolo TLS de forma aislada.

    Returns:
        Un resultado por protocolo indicando si el servidor lo acepta.
    """
    semaphore = asyncio.Semaphore(concurrency)

    async def _probe(name: str, internal: str, deprecated: bool) -> TLSVersionInfo:
        async with semaphore:
            return await asyncio.to_thread(
                _probe_sync, host, port, timeout, name, internal, deprecated
            )

    results = await asyncio.gather(
        *(_probe(name, internal, deprecated) for name, internal, deprecated in TLS_PROTOCOLS)
    )
    return list(results)


def _probe_sync(
    host: str,
    port: int,
    timeout: float,
    name: str,
    internal: str,
    deprecated: bool,
) -> TLSVersionInfo:
    """Prueba un único protocolo contra el servidor."""
    version = _SSL_VERSIONS.get(internal)
    if version is None:
        # Protocolo no disponible en esta versión de Python/OpenSSL.
        return TLSVersionInfo(name=name, enabled=False, deprecated=deprecated, error="no soportado")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = version
    context.maximum_version = version

    try:
        with (
            socket.create_connection((host, port), timeout=timeout) as sock,
            context.wrap_socket(sock, server_hostname=host),
        ):
            return TLSVersionInfo(name=name, enabled=True, deprecated=deprecated)
    except (ssl.SSLError, OSError) as exc:
        return TLSVersionInfo(
            name=name,
            enabled=False,
            deprecated=deprecated,
            error=str(exc),
        )


def supported_protocols(results: list[TLSVersionInfo]) -> list[str]:
    """Devuelve los nombres de los protocolos habilitados."""
    return [r.name for r in results if r.enabled]


def deprecated_protocols(results: list[TLSVersionInfo]) -> list[str]:
    """Devuelve los protocolos obsoletos que siguen habilitados."""
    return [r.name for r in results if r.enabled and r.deprecated]


__all__ = ["deprecated_protocols", "probe_protocols", "supported_protocols"]
