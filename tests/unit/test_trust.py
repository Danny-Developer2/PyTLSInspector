"""Pruebas unitarias del análisis de confianza y conformidad."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from pytlsinspector.core.trust import (
    analyze_certificate,
    analyze_chain,
    analyze_ciphers,
    analyze_protocols,
)
from pytlsinspector.models import (
    Category,
    CertificateInfo,
    ChainInfo,
    CipherInfo,
    Severity,
    TLSVersionInfo,
)


def _certificate(
    *,
    self_signed: bool = False,
    expired: bool = False,
    not_yet_valid: bool = False,
    key_size: int = 2048,
    signature: str = "sha256WithRSAEncryption",
    common_name: str = "localhost",
    san_dns: tuple[str, ...] = ("localhost",),
    is_ca: bool = False,
) -> CertificateInfo:
    """Construye un certificado de prueba con las propiedades indicadas."""
    now = datetime.now(UTC)
    return CertificateInfo(
        subject=f"CN={common_name}",
        issuer=f"CN={common_name}" if self_signed else "CN=CA de prueba",
        serial_number="0a",
        not_before=now - timedelta(days=30 if not not_yet_valid else -30),
        not_after=now + timedelta(days=-1 if expired else 300),
        signature_algorithm=signature,
        key_algorithm="RSAPublicKey",
        key_size=key_size,
        common_name=common_name,
        san_dns=list(san_dns),
        san_ip=[],
        is_self_signed=self_signed,
        is_ca=is_ca,
        version=3,
        sha256_fingerprint="ab" * 32,
    )


class TestCertificado:
    def test_certificado_caducado(self):
        findings = analyze_certificate(_certificate(expired=True), "localhost")
        assert any(f.id == "certificate_expired" for f in findings)
        assert any(f.severity is Severity.CONFIRMADO for f in findings)

    def test_certificado_proximo_a_caducar(self):
        cert = _certificate()
        cert = cert.model_copy(update={"not_after": datetime.now(UTC) + timedelta(days=10)})
        findings = analyze_certificate(cert, "localhost")
        assert any(f.id == "certificate_expiring_soon" for f in findings)

    def test_certificado_autofirmado(self):
        findings = analyze_certificate(_certificate(self_signed=True), "localhost")
        assert any(f.id == "certificate_self_signed" for f in findings)

    def test_hostname_no_cubierto(self):
        findings = analyze_certificate(
            _certificate(common_name="otro", san_dns=("otro",)), "localhost"
        )
        assert any(f.id == "hostname_mismatch" for f in findings)
        assert all(f.category is Category.HOSTNAME for f in findings if f.id == "hostname_mismatch")

    def test_firma_debil(self):
        findings = analyze_certificate(_certificate(signature="sha1WithRSAEncryption"), "localhost")
        assert any(f.id == "weak_signature_algorithm" for f in findings)

    def test_clave_corta(self):
        findings = analyze_certificate(_certificate(key_size=1024), "localhost")
        assert any(f.id == "weak_key_size" for f in findings)

    def test_certificado_ca_como_hoja(self):
        findings = analyze_certificate(_certificate(is_ca=True), "localhost")
        assert any(f.id == "leaf_is_ca_certificate" for f in findings)

    def test_certificado_sin_hallazgos(self):
        cert = _certificate()
        cert = cert.model_copy(update={"not_after": datetime.now(UTC) + timedelta(days=300)})
        findings = analyze_certificate(cert, "localhost")
        assert findings == []


class TestCadena:
    def test_cadena_no_confiable(self):
        chain = ChainInfo(
            certificates=[_certificate(self_signed=True)],
            trusted=False,
            verification_error="self signed certificate",
        )
        findings = analyze_chain(chain)
        assert any(f.id == "chain_not_trusted" for f in findings)

    def test_cadena_incompleta(self):
        chain = ChainInfo(
            certificates=[_certificate()],
            trusted=False,
            verification_error="unable to get local issuer certificate",
        )
        findings = analyze_chain(chain)
        assert any(f.id == "incomplete_chain" for f in findings)

    def test_cadena_valida_sin_hallazgos(self):
        chain = ChainInfo(
            certificates=[_certificate(), _certificate(common_name="CA")],
            trusted=True,
        )
        assert analyze_chain(chain) == []


class TestProtocolos:
    def _protocols(self, enabled: list[str]) -> list[TLSVersionInfo]:
        known = {"SSLv2", "SSLv3", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"}
        deprecated = {"SSLv2", "SSLv3", "TLS 1.0", "TLS 1.1"}
        return [
            TLSVersionInfo(name=name, enabled=name in enabled, deprecated=name in deprecated)
            for name in sorted(known)
        ]

    def test_protocolo_obsoleto(self):
        findings = analyze_protocols(self._protocols(["TLS 1.0", "TLS 1.2", "TLS 1.3"]))
        assert any(f.id == "deprecated_protocol_tls_1_0" for f in findings)

    def test_sin_protocolo_recomendado(self):
        findings = analyze_protocols(self._protocols(["TLS 1.0", "TLS 1.1"]))
        assert any(f.id == "no_recommended_protocol" for f in findings)

    def test_configuracion_correcta(self):
        findings = analyze_protocols(self._protocols(["TLS 1.2", "TLS 1.3"]))
        assert findings == []


class TestCifrados:
    def test_cifrados_debiles(self):
        ciphers = [CipherInfo(name="RC4-SHA", enabled=True, strength="debil")]
        findings = analyze_ciphers(ciphers)
        assert any(f.id == "weak_ciphers_enabled" for f in findings)

    def test_sin_secreto_directo(self):
        ciphers = [
            CipherInfo(name="AES256-SHA", enabled=True, strength="media", key_exchange="RSA")
        ]
        findings = analyze_ciphers(ciphers)
        assert any(f.id == "ciphers_without_forward_secrecy" for f in findings)

    def test_configuracion_correcta(self):
        ciphers = [
            CipherInfo(
                name="TLS_AES_256_GCM_SHA384", enabled=True, strength="fuerte", key_exchange="ECDHE"
            )
        ]
        assert analyze_ciphers(ciphers) == []
