"""Pruebas unitarias de la obtención y el análisis de certificados."""

from __future__ import annotations

import ssl

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from pytlsinspector.core.certificate import (
    fetch_chain,
    is_expired,
    is_not_yet_valid,
    is_weak_key,
    key_type,
    parse_certificate,
    verify_hostname,
)
from pytlsinspector.exceptions import PyTLSInspectorError
from tests.conftest import GeneratedCertificate, _build_certificate, start_tls_server


def _info(certificate: GeneratedCertificate):
    """Construye un CertificateInfo a partir de un certificado generado."""
    cert = x509.load_pem_x509_certificate(certificate.cert_path.read_bytes())
    return parse_certificate(cert.public_bytes(Encoding.DER))


@pytest.fixture()
def tls_server_with_cert(self_signed_certificate: GeneratedCertificate):
    """Servidor TLS que usa el certificado autofirmado de sesión."""
    instance = start_tls_server(certificate=self_signed_certificate)
    yield instance
    instance.stop()


class TestParseCertificate:
    async def test_parsea_certificado_autofirmado(self, tls_server_with_cert):
        chain = await fetch_chain("127.0.0.1", tls_server_with_cert.port, verify_tls=False)
        assert chain.leaf is not None
        leaf = chain.leaf
        assert leaf.common_name == "localhost"
        assert "localhost" in leaf.san_dns
        assert leaf.is_self_signed is True
        assert leaf.key_size == 2048
        assert len(leaf.sha256_fingerprint) == 64

    async def test_cadena_contiene_el_certificado(self, tls_server_with_cert):
        chain = await fetch_chain("127.0.0.1", tls_server_with_cert.port, verify_tls=False)
        assert chain.length >= 1
        assert chain.leaf is not None
        assert chain.leaf.subject


class TestValidacionHost:
    def test_hostname_cubierto(self, self_signed_certificate):
        cert = _info(self_signed_certificate)
        assert verify_hostname(cert, "localhost") is True

    def test_hostname_no_cubierto(self, self_signed_certificate):
        cert = _info(self_signed_certificate)
        assert verify_hostname(cert, "otro.ejemplo") is False

    def test_hostname_con_comodin(self):
        cert = _build_certificate(common_name="*.ejemplo.com", san_dns=("*.ejemplo.com",))
        info = _info(cert)
        assert verify_hostname(info, "www.ejemplo.com") is True
        assert verify_hostname(info, "ejemplo.com") is False
        assert verify_hostname(info, "a.b.ejemplo.com") is False

    def test_ip_en_san(self):
        cert = _build_certificate(common_name="127.0.0.1", san_dns=(), san_ip=("127.0.0.1",))
        info = _info(cert)
        assert verify_hostname(info, "127.0.0.1") is True

    def test_ip_ausente_en_san(self):
        cert = _build_certificate(common_name="localhost", san_dns=("localhost",))
        info = _info(cert)
        assert verify_hostname(info, "127.0.0.1") is False


class TestPropiedades:
    def test_certificado_caducado(self, expired_certificate):
        info = _info(expired_certificate)
        assert is_expired(info) is True

    def test_certificado_valido(self, self_signed_certificate):
        info = _info(self_signed_certificate)
        assert is_expired(info) is False
        assert is_not_yet_valid(info) is False

    def test_clave_debil(self, weak_key_certificate):
        info = _info(weak_key_certificate)
        assert is_weak_key(info) is True

    def test_clave_fuerte(self, self_signed_certificate):
        info = _info(self_signed_certificate)
        assert is_weak_key(info) is False

    def test_tipo_de_clave(self, self_signed_certificate):
        info = _info(self_signed_certificate)
        assert key_type(info) == "rsa"


class TestConexion:
    async def test_error_si_no_hay_servidor(self):
        with pytest.raises(PyTLSInspectorError):
            await fetch_chain("127.0.0.1", 1, timeout=2.0, verify_tls=False)

    async def test_servidor_con_tls13(self):
        instance = start_tls_server(
            min_version=ssl.TLSVersion.TLSv1_2,
            max_version=ssl.TLSVersion.TLSv1_3,
        )
        try:
            chain = await fetch_chain("127.0.0.1", instance.port, verify_tls=False)
            assert chain.length >= 1
            assert chain.leaf is not None
        finally:
            instance.stop()
