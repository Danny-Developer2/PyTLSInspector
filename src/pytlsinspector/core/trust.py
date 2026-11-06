"""Análisis de confianza, validez y conformidad del certificado."""

from __future__ import annotations

from datetime import UTC, datetime

from pytlsinspector.config import (
    EXPIRY_WARNING_DAYS,
    MIN_EC_KEY_SIZE,
    MIN_RSA_KEY_SIZE,
    RECOMMENDED_MIN_PROTOCOL,
    RECOMMENDED_PROTOCOLS,
    REFERENCES,
)
from pytlsinspector.core.certificate import (
    is_expired,
    is_not_yet_valid,
    is_weak_key,
    is_weak_signature,
    key_type,
    verify_hostname,
)
from pytlsinspector.models import (
    Category,
    CertificateInfo,
    ChainInfo,
    CipherInfo,
    Finding,
    Severity,
    TLSVersionInfo,
)


def analyze_certificate(
    cert: CertificateInfo,
    host: str,
) -> list[Finding]:
    """Evalúa un certificado contra las buenas prácticas."""
    findings: list[Finding] = []

    if is_expired(cert):
        findings.append(
            _finding(
                id="certificate_expired",
                category=Category.CERTIFICATE,
                severity=Severity.CONFIRMADO,
                title="Certificado caducado",
                description=(
                    "El certificado ha superado su fecha de caducidad, por lo que los "
                    "clientes rechazarán la conexión."
                ),
                evidence=f"notAfter: {cert.not_after.isoformat()}",
                recommendation="Renueva el certificado y planifica su rotación.",
                references=REFERENCES["certificado"],
            )
        )
    elif cert.days_until_expiry <= EXPIRY_WARNING_DAYS:
        findings.append(
            _finding(
                id="certificate_expiring_soon",
                category=Category.CERTIFICATE,
                severity=Severity.INDICIO,
                title="Certificado próximo a caducar",
                description=(
                    "El certificado caducará en breve; una renovación tardía puede "
                    "dejar el servicio inaccesible."
                ),
                evidence=(
                    f"notAfter: {cert.not_after.isoformat()} "
                    f"({cert.days_until_expiry} días restantes)"
                ),
                recommendation="Programa la renovación antes de la fecha de caducidad.",
                references=REFERENCES["certificado"],
            )
        )

    if is_not_yet_valid(cert):
        findings.append(
            _finding(
                id="certificate_not_yet_valid",
                category=Category.CERTIFICATE,
                severity=Severity.CONFIRMADO,
                title="Certificado aún no válido",
                description=(
                    "La fecha de inicio de validez del certificado es posterior a la "
                    "fecha actual, lo que impide su uso."
                ),
                evidence=f"notBefore: {cert.not_before.isoformat()}",
                recommendation="Comprueba la fecha del sistema y la vigencia del certificado.",
                references=REFERENCES["certificado"],
            )
        )

    if cert.is_self_signed:
        findings.append(
            _finding(
                id="certificate_self_signed",
                category=Category.TRUST,
                severity=Severity.PROBABLE,
                title="Certificado autofirmado",
                description=(
                    "El certificado ha sido firmado por sí mismo y no proviene de una "
                    "autoridad de certificación de confianza pública."
                ),
                evidence=f"Subject e Issuer coinciden: {cert.subject}",
                recommendation=(
                    "Usa un certificado emitido por una CA de confianza o instala tu CA "
                    "interna en los clientes."
                ),
                references=REFERENCES["confianza"],
            )
        )

    if not verify_hostname(cert, host):
        findings.append(
            _finding(
                id="hostname_mismatch",
                category=Category.HOSTNAME,
                severity=Severity.PROBABLE,
                title="El certificado no cubre el nombre de host",
                description=(
                    "El nombre de host consultado no aparece en el Subject Alternative "
                    "Name ni en el Common Name del certificado."
                ),
                evidence=(
                    f"Host: {host} · CN: {cert.common_name or '—'} · "
                    f"SAN DNS: {', '.join(cert.san_dns) or '—'}"
                ),
                recommendation="Emite un certificado que incluya el nombre de host utilizado.",
                references=REFERENCES["hostname"],
            )
        )

    if is_weak_signature(cert):
        findings.append(
            _finding(
                id="weak_signature_algorithm",
                category=Category.CERTIFICATE,
                severity=Severity.PROBABLE,
                title="Algoritmo de firma obsoleto",
                description=(
                    "El certificado usa un algoritmo de firma considerado inseguro, lo "
                    "que facilita falsificaciones."
                ),
                evidence=f"signatureAlgorithm: {cert.signature_algorithm}",
                recommendation="Emite el certificado con SHA-256 o superior.",
                references=REFERENCES["certificado"],
            )
        )

    if is_weak_key(cert):
        findings.append(
            _finding(
                id="weak_key_size",
                category=Category.CERTIFICATE,
                severity=Severity.PROBABLE,
                title="Longitud de clave insuficiente",
                description=(
                    "La clave pública del certificado es más corta de lo recomendado, "
                    "lo que reduce la seguridad del intercambio."
                ),
                evidence=(f"keyAlgorithm: {cert.key_algorithm} · keySize: {cert.key_size} bits"),
                recommendation=(
                    f"Usa claves RSA de al menos {MIN_RSA_KEY_SIZE} bits o curvas "
                    f"elípticas de al menos {MIN_EC_KEY_SIZE} bits."
                ),
                references=REFERENCES["certificado"],
            )
        )

    if cert.is_ca:
        findings.append(
            _finding(
                id="leaf_is_ca_certificate",
                category=Category.CERTIFICATE,
                severity=Severity.POTENCIAL,
                title="El certificado hoja está marcado como CA",
                description=(
                    "Un certificado de servidor no debería tener la extensión de "
                    "autoridad de certificación, ya que podría emitir certificados."
                ),
                evidence="basicConstraints: CA=TRUE en el certificado hoja",
                recommendation="Emite el certificado de servidor sin la marca de CA.",
                references=REFERENCES["certificado"],
            )
        )

    return findings


def analyze_chain(chain: ChainInfo) -> list[Finding]:
    """Evalúa la cadena de certificados servida."""
    findings: list[Finding] = []

    if chain.certificates and not chain.trusted and chain.verification_error:
        findings.append(
            _finding(
                id="chain_not_trusted",
                category=Category.CHAIN,
                severity=Severity.PROBABLE,
                title="La cadena no se valida contra el almacén de confianza",
                description=(
                    "La cadena servida no termina en una autoridad de confianza "
                    "reconocida, por lo que los clientes mostrarán advertencias."
                ),
                evidence=chain.verification_error,
                recommendation=(
                    "Sirve la cadena completa, incluido el certificado intermedio, "
                    "emitido por una CA de confianza."
                ),
                references=REFERENCES["confianza"],
            )
        )

    leaf = chain.leaf or (chain.certificates[0] if chain.certificates else None)
    if chain.length < 2 and leaf is not None and not leaf.is_self_signed:
        findings.append(
            _finding(
                id="incomplete_chain",
                category=Category.CHAIN,
                severity=Severity.POTENCIAL,
                title="Cadena de certificados incompleta",
                description=(
                    "El servidor no envía los certificados intermedios, lo que obliga "
                    "a los clientes a reconstruir la cadena por su cuenta."
                ),
                evidence=f"Certificados recibidos: {chain.length}",
                recommendation="Configura el servidor para enviar la cadena completa.",
                references=REFERENCES["confianza"],
            )
        )

    return findings


def analyze_protocols(protocols: list[TLSVersionInfo]) -> list[Finding]:
    """Evalúa los protocolos habilitados."""
    findings: list[Finding] = []

    for protocol in protocols:
        if not protocol.enabled or not protocol.deprecated:
            continue
        severity = Severity.CONFIRMADO if protocol.name in {"SSLv2", "SSLv3"} else Severity.PROBABLE
        slug = _slug(protocol.name)
        findings.append(
            _finding(
                id=f"deprecated_protocol_{slug}",
                category=Category.PROTOCOL,
                severity=severity,
                title=f"Protocolo obsoleto habilitado: {protocol.name}",
                description=(
                    f"El servidor acepta {protocol.name}, un protocolo con debilidades "
                    "conocidas y sin soporte en los navegadores modernos."
                ),
                evidence=f"El servidor completa el handshake con {protocol.name}.",
                recommendation=(
                    f"Deshabilita {protocol.name} y deja como mínimo {RECOMMENDED_MIN_PROTOCOL}."
                ),
                references=REFERENCES["protocolos"],
            )
        )

    enabled = {p.name for p in protocols if p.enabled}
    if enabled and not enabled.intersection(RECOMMENDED_PROTOCOLS):
        findings.append(
            _finding(
                id="no_recommended_protocol",
                category=Category.PROTOCOL,
                severity=Severity.CONFIRMADO,
                title="No se ofrece ningún protocolo recomendado",
                description=(
                    "El servidor no admite TLS 1.2 ni TLS 1.3, por lo que las conexiones "
                    "modernas no son posibles."
                ),
                evidence=f"Protocolos habilitados: {', '.join(sorted(enabled))}",
                recommendation="Habilita TLS 1.2 como mínimo y TLS 1.3 si es posible.",
                references=REFERENCES["protocolos"],
            )
        )

    return findings


def analyze_ciphers(ciphers: list[CipherInfo]) -> list[Finding]:
    """Evalúa los conjuntos de cifrado habilitados."""
    findings: list[Finding] = []

    weak = [c for c in ciphers if c.enabled and c.strength == "debil"]
    if weak:
        findings.append(
            _finding(
                id="weak_ciphers_enabled",
                category=Category.CIPHER,
                severity=Severity.PROBABLE,
                title="Conjuntos de cifrado débiles habilitados",
                description=(
                    "El servidor admite algoritmos de cifrado obsoletos o rotos que "
                    "reducen la confidencialidad de las comunicaciones."
                ),
                evidence=", ".join(c.name for c in weak),
                recommendation=(
                    "Restringe la configuración a conjuntos AEAD con intercambio de "
                    "claves con secreto directo (PFS)."
                ),
                references=REFERENCES["cifrados"],
            )
        )

    no_pfs = [c for c in ciphers if c.enabled and c.key_exchange == "RSA"]
    if no_pfs:
        findings.append(
            _finding(
                id="ciphers_without_forward_secrecy",
                category=Category.CIPHER,
                severity=Severity.POTENCIAL,
                title="Conjuntos de cifrado sin secreto directo",
                description=(
                    "Estos conjuntos usan el certificado RSA para el intercambio de "
                    "claves, por lo que una fuga de la clave privada permitiría "
                    "descifrar comunicaciones grabadas."
                ),
                evidence=", ".join(c.name for c in no_pfs),
                recommendation="Prioriza conjuntos con ECDHE o DHE.",
                references=REFERENCES["cifrados"],
            )
        )

    return findings


def _finding(
    *,
    id: str,
    category: Category,
    severity: Severity,
    title: str,
    description: str,
    evidence: str,
    recommendation: str,
    references: list[str] | None = None,
) -> Finding:
    """Construye un hallazgo con los campos normalizados."""
    return Finding(
        id=id,
        category=category,
        severity=severity,
        title=title,
        description=description,
        evidence=evidence,
        recommendation=recommendation,
        references=references or [],
    )


def _slug(value: str) -> str:
    """Genera un identificador estable a partir de un nombre legible."""
    return "".join(ch if ch.isalnum() else "_" for ch in value.lower()).strip("_")


def _now() -> datetime:
    """Fecha actual en UTC (auxiliar para pruebas)."""
    return datetime.now(UTC)


__all__ = [
    "analyze_certificate",
    "analyze_chain",
    "analyze_ciphers",
    "analyze_protocols",
    "key_type",
]
