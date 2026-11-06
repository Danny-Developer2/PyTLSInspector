"""Utilidades de red para PyTLSInspector."""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass

from pytlsinspector.exceptions import ValidationError
from pytlsinspector.utils.logger import get_logger

_logger = get_logger("utils.net")


@dataclass(frozen=True, slots=True)
class Endpoint:
    """Extremo TLS resuelto a nombre de host y puerto."""

    host: str
    port: int

    def __str__(self) -> str:
        return f"{self.host}:{self.port}"


def parse_target(target: str, default_port: int = 443) -> Endpoint:
    """Divide un objetivo ``host`` o ``host:puerto``.

    Acepta también URLs completas (``https://host:puerto/``) para facilitar su uso.

    Raises:
        ValidationError: Si el objetivo está vacío o el puerto no es válido.
    """
    cleaned = target.strip()
    if not cleaned:
        raise ValidationError("el objetivo no puede estar vacío")

    if "://" in cleaned:
        scheme, _, rest = cleaned.partition("://")
        if not scheme or not rest:
            raise ValidationError(f"el objetivo {target!r} no es una URL válida")
        cleaned = rest
    cleaned = cleaned.split("/", 1)[0]

    if cleaned.startswith("[") and "]" in cleaned:
        # IPv6 entre corchetes.
        host, _, rest = cleaned[1:].partition("]")
        port_part = rest.lstrip(":")
    elif cleaned.count(":") == 1:
        host, _, port_part = cleaned.partition(":")
    else:
        host, port_part = cleaned, ""

    host = host.strip()
    if not host:
        raise ValidationError(f"el objetivo {target!r} no contiene un nombre de host válido")

    if port_part:
        if not port_part.isdigit():
            raise ValidationError(f"el puerto {port_part!r} no es un número")
        port = int(port_part)
        if not 1 <= port <= 65535:
            raise ValidationError(f"el puerto {port} está fuera del rango 1-65535")
    else:
        port = default_port

    return Endpoint(host=host, port=port)


def resolve_host(host: str, timeout: float = 5.0) -> str | None:
    """Resuelve un nombre de host a IPv4/IPv6.

    Returns:
        La primera dirección resuelta o ``None`` si no se puede resolver.
    """
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, OSError) as exc:
        _logger.debug("no se pudo resolver %s: %s", host, exc)
        return None

    for info in infos:
        address = str(info[4][0])
        if _is_global_address(address):
            return address
    return str(infos[0][4][0]) if infos else None


def _is_global_address(address: str) -> bool:
    """Indica si una dirección es accesible de forma global."""
    try:
        return ipaddress.ip_address(address).is_global
    except ValueError:
        return False


def is_ip_address(host: str) -> bool:
    """Indica si el valor es una dirección IP en lugar de un nombre de host."""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def check_connectivity(host: str, port: int, timeout: float = 5.0) -> bool:
    """Comprueba si el puerto TCP está abierto sin negociar TLS."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError as exc:
        _logger.debug("no se pudo conectar con %s:%s: %s", host, port, exc)
        return False
