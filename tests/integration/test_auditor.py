"""Pruebas de integración del auditor TLS contra el laboratorio local."""

from __future__ import annotations

import ssl

from pytlsinspector.config import AuditConfig
from pytlsinspector.core.auditor import Auditor
from pytlsinspector.models import Severity
from tests.conftest import start_tls_server


class TestAuditorTLS:
    async def test_analiza_servidor_tls(self, tls_server):
        config = AuditConfig(target="127.0.0.1", port=tls_server.port, confirm_authorized=True)
        result = await Auditor(config).run()

        assert result.connected is True
        assert result.chain is not None
        assert result.chain.leaf is not None
        assert result.negotiated_protocol in {"TLSv1.2", "TLSv1.3"}
        assert result.findings

    async def test_detecta_certificado_autofirmado(self, tls_server):
        config = AuditConfig(target="127.0.0.1", port=tls_server.port, confirm_authorized=True)
        result = await Auditor(config).run()
        ids = {f.id for f in result.findings}
        assert "certificate_self_signed" in ids
        assert "hostname_mismatch" in ids

    async def test_detecta_cadena_no_confiable(self, tls_server):
        config = AuditConfig(target="127.0.0.1", port=tls_server.port, confirm_authorized=True)
        result = await Auditor(config).run()
        ids = {f.id for f in result.findings}
        assert "chain_not_trusted" in ids

    async def test_estadisticas_coherentes(self, tls_server):
        config = AuditConfig(target="127.0.0.1", port=tls_server.port, confirm_authorized=True)
        result = await Auditor(config).run()
        assert sum(result.statistics.values()) == len(result.findings)

    async def test_todas_las_severidades_validas(self, tls_server):
        config = AuditConfig(target="127.0.0.1", port=tls_server.port, confirm_authorized=True)
        result = await Auditor(config).run()
        assert all(f.severity in set(Severity) for f in result.findings)


class TestAuditorProtocolos:
    async def test_servidor_solo_tls12(self):
        instance = start_tls_server(
            min_version=ssl.TLSVersion.TLSv1_2,
            max_version=ssl.TLSVersion.TLSv1_2,
        )
        try:
            config = AuditConfig(target="127.0.0.1", port=instance.port, confirm_authorized=True)
            result = await Auditor(config).run()
            enabled = {p.name for p in result.protocols if p.enabled}
            assert enabled == {"TLS 1.2"}
        finally:
            instance.stop()


class TestAuditorOpciones:
    async def test_sin_enumarar_cifrados(self, tls_server):
        config = AuditConfig(
            target="127.0.0.1",
            port=tls_server.port,
            confirm_authorized=True,
            probe_ciphers=False,
        )
        result = await Auditor(config).run()
        assert result.ciphers == []
        assert not any(f.id.startswith("weak_ciphers") for f in result.findings)


class TestAuditorErrores:
    async def test_objetivo_inaccesible(self):
        config = AuditConfig(
            target="127.0.0.1",
            port=1,
            timeout=2.0,
            confirm_authorized=True,
        )
        result = await Auditor(config).run()
        assert result.connected is False
        assert any(f.id == "connection_failed" for f in result.findings)
        assert result.chain is None
