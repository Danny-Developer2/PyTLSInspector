"""Modelos de datos de PyTLSInspector (Pydantic).

Todos los modelos son inmutables para garantizar que los resultados no se
modifiquen una vez generados.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    """Niveles de severidad, de mayor a menor impacto."""

    CONFIRMADO = "confirmado"
    PROBABLE = "probable"
    POTENCIAL = "potencial"
    INDICIO = "indicio"
    RECOMENDACION = "recomendacion"


class Category(StrEnum):
    """Áreas de análisis de la auditoría TLS."""

    CERTIFICATE = "certificado"
    PROTOCOL = "protocolo"
    CIPHER = "cifrado"
    TRUST = "confianza"
    HOSTNAME = "hostname"
    CHAIN = "cadena"
    GENERAL = "general"


class Scope(BaseModel):
    """Alcance autorizado de la auditoría."""

    model_config = ConfigDict(frozen=True)

    name: str = "Auditoría autorizada"
    authorized_targets: list[str] = Field(default_factory=list)

    def matches(self, host: str, port: int | None = None) -> bool:
        """Indica si un host (y puerto opcional) está dentro del alcance."""
        normalised = host.lower().strip()
        for target in self.authorized_targets:
            candidate = target.lower().strip()
            candidate_host, _, candidate_port = candidate.partition(":")
            if candidate_port.isdigit() and port is not None:
                if normalised == candidate_host and int(candidate_port) == port:
                    return True
                continue
            if normalised == candidate_host:
                return True
        return False


class CertificateInfo(BaseModel):
    """Información extraída de un certificado X.509."""

    model_config = ConfigDict(frozen=True)

    subject: str
    issuer: str
    serial_number: str
    not_before: datetime
    not_after: datetime
    signature_algorithm: str
    key_algorithm: str
    key_size: int | None = None
    common_name: str
    san_dns: list[str] = Field(default_factory=list)
    san_ip: list[str] = Field(default_factory=list)
    is_self_signed: bool = False
    is_ca: bool = False
    version: int | None = None
    sha256_fingerprint: str
    position: int = 0

    @property
    def expired(self) -> bool:
        """Indica si el certificado ha caducado."""
        return datetime.now(UTC) > self.not_after

    @property
    def not_yet_valid(self) -> bool:
        """Indica si el certificado aún no es válido."""
        return datetime.now(UTC) < self.not_before

    @property
    def days_until_expiry(self) -> int:
        """Días restantes hasta la caducidad (negativo si ya caducó)."""
        return (self.not_after - datetime.now(UTC)).days


class ChainInfo(BaseModel):
    """Cadena de certificados servida por el objetivo."""

    model_config = ConfigDict(frozen=True)

    certificates: list[CertificateInfo] = Field(default_factory=list)
    trusted: bool = False
    verification_error: str | None = None
    leaf: CertificateInfo | None = None

    @property
    def length(self) -> int:
        """Número de certificados de la cadena."""
        return len(self.certificates)


class TLSVersionInfo(BaseModel):
    """Resultado de probar un protocolo concreto."""

    model_config = ConfigDict(frozen=True)

    name: str
    enabled: bool
    deprecated: bool = False
    error: str | None = None


class CipherInfo(BaseModel):
    """Resultado de probar un conjunto de cifrado."""

    model_config = ConfigDict(frozen=True)

    name: str
    enabled: bool
    strength: str = "desconocida"
    key_exchange: str | None = None
    notes: str | None = None
    error: str | None = None


class Finding(BaseModel):
    """Hallazgo de seguridad."""

    model_config = ConfigDict(frozen=True)

    id: str
    category: Category
    severity: Severity
    title: str
    description: str
    evidence: str
    recommendation: str
    references: list[str] = Field(default_factory=list)


class TLSAuditResult(BaseModel):
    """Resultado consolidado de una auditoría TLS."""

    model_config = ConfigDict(frozen=True)

    tool: str = "PyTLSInspector"
    version: str = "1.0.0"
    target: str
    port: int
    scope: str | None = None
    authorized: bool = False
    started_at: datetime
    finished_at: datetime
    duration_seconds: float = 0.0
    connected: bool = False
    negotiated_protocol: str | None = None
    negotiated_cipher: str | None = None
    chain: ChainInfo | None = None
    protocols: list[TLSVersionInfo] = Field(default_factory=list)
    ciphers: list[CipherInfo] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    statistics: dict[str, int] = Field(default_factory=dict)

    def findings_by_severity(self, severity: Severity) -> list[Finding]:
        """Devuelve los hallazgos de una severidad concreta."""
        return [f for f in self.findings if f.severity is severity]

    @property
    def confirmed_count(self) -> int:
        """Número de hallazgos confirmados."""
        return len(self.findings_by_severity(Severity.CONFIRMADO))

    def summary(self) -> dict[str, Any]:
        """Resumen apto para registros y depuración."""
        return {
            "target": f"{self.target}:{self.port}",
            "connected": self.connected,
            "protocol": self.negotiated_protocol,
            "cipher": self.negotiated_cipher,
            "chain_length": self.chain.length if self.chain else 0,
            "findings": len(self.findings),
            "statistics": self.statistics,
        }
