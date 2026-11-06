"""Enumeración y evaluación de conjuntos de cifrado."""

from __future__ import annotations

import asyncio
import socket
import ssl

from pytlsinspector.config import CIPHER_SUITES, WEAK_CIPHER_MARKERS
from pytlsinspector.models import CipherInfo
from pytlsinspector.utils.logger import get_logger

_logger = get_logger("core.ciphers")


async def enumerate_ciphers(
    host: str,
    port: int,
    timeout: float = 10.0,
    max_ciphers: int = 32,
    concurrency: int = 8,
) -> list[CipherInfo]:
    """Prueba los conjuntos de cifrado configurados de forma individual.

    Args:
        host: Nombre de host o dirección IP del objetivo.
        port: Puerto TLS.
        timeout: Tiempo de espera por intento.
        max_ciphers: Límite de conjuntos a probar.
        concurrency: Número de intentos simultáneos.

    Returns:
        Un resultado por conjunto de cifrado.
    """
    suites = CIPHER_SUITES[:max_ciphers]
    semaphore = asyncio.Semaphore(concurrency)

    async def _probe(suite: tuple[str, str, str | None, str | None]) -> CipherInfo:
        name, strength, key_exchange, notes = suite
        async with semaphore:
            enabled, error = await asyncio.to_thread(_probe_sync, host, port, timeout, name)
        return CipherInfo(
            name=name,
            enabled=enabled,
            strength=_evaluate_strength(name, strength, enabled),
            key_exchange=key_exchange,
            notes=notes,
            error=error,
        )

    results = await asyncio.gather(*(_probe(suite) for suite in suites))
    return list(results)


def _probe_sync(host: str, port: int, timeout: float, cipher: str) -> tuple[bool, str | None]:
    """Intenta negociar un único conjunto de cifrado.

    ``set_ciphers`` solo gobierna TLS 1.2 e inferiores; los conjuntos de TLS 1.3 se
    controlan con ``set_ciphersuites``. Además se limita la versión para que el
    servidor no pueda negociar un cifrado distinto al solicitado.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    is_tls13 = cipher.startswith("TLS_")
    if is_tls13:
        setter = getattr(context, "set_ciphersuites", None)
        if setter is None:
            return False, "este OpenSSL no permite configurar conjuntos de TLS 1.3"
        try:
            setter(cipher)
        except ssl.SSLError as exc:
            return False, str(exc)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
    else:
        try:
            context.set_ciphers(cipher)
        except ssl.SSLError as exc:
            return False, str(exc)
        context.maximum_version = ssl.TLSVersion.TLSv1_2

    try:
        with (
            socket.create_connection((host, port), timeout=timeout) as sock,
            context.wrap_socket(sock, server_hostname=host) as tls,
        ):
            cipher_info = tls.cipher()
            negotiated = cipher_info[0] if cipher_info else None
            if negotiated != cipher:
                return False, f"se negoció {negotiated} en lugar de {cipher}"
            return True, None
    except (ssl.SSLError, OSError) as exc:
        return False, str(exc)


def _evaluate_strength(name: str, declared: str, enabled: bool) -> str:
    """Ajusta la fortaleza declarada en función de si el servidor lo admite."""
    if not enabled:
        return "no admitido"
    return declared


def is_weak_cipher(name: str) -> bool:
    """Indica si un conjunto de cifrado contiene algoritmos obsoletos."""
    upper = name.upper()
    return any(marker.upper() in upper for marker in WEAK_CIPHER_MARKERS)


def enabled_weak_ciphers(ciphers: list[CipherInfo]) -> list[CipherInfo]:
    """Devuelve los conjuntos débiles que el servidor admite."""
    return [c for c in ciphers if c.enabled and is_weak_cipher(c.name)]


__all__ = [
    "enumerate_ciphers",
    "enabled_weak_ciphers",
    "is_weak_cipher",
]
