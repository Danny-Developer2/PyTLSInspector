"""Orquestador principal de la auditoría TLS de PyTLSInspector."""

from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import UTC, datetime

from pytlsinspector.config import AuditConfig
from pytlsinspector.core.certificate import fetch_chain
from pytlsinspector.core.ciphers import enumerate_ciphers
from pytlsinspector.core.protocols import probe_protocols
from pytlsinspector.core.trust import (
    analyze_certificate,
    analyze_chain,
    analyze_ciphers,
    analyze_protocols,
)
from pytlsinspector.exceptions import ConnectionError
from pytlsinspector.models import (
    Category,
    ChainInfo,
    CipherInfo,
    Finding,
    Severity,
    TLSAuditResult,
    TLSVersionInfo,
)
from pytlsinspector.utils.logger import get_logger

_logger = get_logger("core.auditor")


class Auditor:
    """Ejecuta una auditoría TLS completa sobre un objetivo autorizado."""

    def __init__(self, config: AuditConfig) -> None:
        self.config = config
        self.logger = get_logger("core.auditor")

    async def run(self) -> TLSAuditResult:
        """Ejecuta el análisis y devuelve el resultado consolidado."""
        started = datetime.now(UTC)
        self.logger.info(
            "auditoría TLS iniciada contra %s:%s", self.config.target, self.config.port
        )

        chain: ChainInfo | None = None
        protocols: list[TLSVersionInfo] = []
        ciphers: list[CipherInfo] = []
        findings: list[Finding] = []
        connected = False
        negotiated_protocol: str | None = None
        negotiated_cipher: str | None = None

        try:
            chain = await fetch_chain(
                self.config.target,
                self.config.port,
                self.config.timeout,
                self.config.verify_tls,
            )
            connected = True

            if chain.leaf is not None:
                findings.extend(analyze_certificate(chain.leaf, self.config.target))
            findings.extend(analyze_chain(chain))

            negotiated_protocol, negotiated_cipher = await asyncio.to_thread(
                _negotiated_parameters,
                self.config.target,
                self.config.port,
                self.config.timeout,
            )

            protocols = await probe_protocols(
                self.config.target,
                self.config.port,
                self.config.timeout,
                self.config.concurrency,
            )
            findings.extend(analyze_protocols(protocols))

            if self.config.probe_ciphers:
                ciphers = await enumerate_ciphers(
                    self.config.target,
                    self.config.port,
                    self.config.timeout,
                    self.config.max_ciphers,
                    self.config.concurrency,
                )
                findings.extend(analyze_ciphers(ciphers))

        except ConnectionError as exc:
            self.logger.error("no se pudo conectar con el objetivo: %s", exc)
            findings.append(
                Finding(
                    id="connection_failed",
                    category=Category.GENERAL,
                    severity=Severity.INDICIO,
                    title="No se pudo establecer la conexión TLS",
                    description=(
                        "El servidor no aceptó la conexión en el puerto indicado o no "
                        "completa el handshake TLS."
                    ),
                    evidence=str(exc),
                    recommendation=(
                        "Comprueba que el servicio esté activo y que el puerto sea el correcto."
                    ),
                )
            )

        finished = datetime.now(UTC)
        result = TLSAuditResult(
            target=self.config.target,
            port=self.config.port,
            scope=self.config.scope.name if self.config.scope else None,
            authorized=self.config.confirm_authorized or self.config.scope is not None,
            started_at=started,
            finished_at=finished,
            duration_seconds=round((finished - started).total_seconds(), 3),
            connected=connected,
            negotiated_protocol=negotiated_protocol,
            negotiated_cipher=negotiated_cipher,
            chain=chain,
            protocols=protocols,
            ciphers=ciphers,
            findings=findings,
            statistics=self._statistics(findings),
        )
        self.logger.info(
            "auditoría finalizada en %.2f s: %d hallazgos",
            result.duration_seconds,
            len(findings),
        )
        return result

    def _statistics(self, findings: list[Finding]) -> dict[str, int]:
        """Cuenta los hallazgos por severidad."""
        counts = {s.value: 0 for s in Severity}
        for finding in findings:
            counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
        return counts


def _negotiated_parameters(host: str, port: int, timeout: float) -> tuple[str | None, str | None]:
    """Devuelve el protocolo y el conjunto de cifrado negociados por defecto."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with (
            socket.create_connection((host, port), timeout=timeout) as sock,
            context.wrap_socket(sock, server_hostname=host) as tls,
        ):
            cipher_info = tls.cipher()
            return tls.version(), (cipher_info[0] if cipher_info else None)
    except (ssl.SSLError, OSError) as exc:
        _logger.debug("no se pudieron obtener los parámetros negociados: %s", exc)
        return None, None


__all__ = ["Auditor"]
