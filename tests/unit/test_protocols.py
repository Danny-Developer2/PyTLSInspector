"""Pruebas unitarias de la detección de protocolos."""

from __future__ import annotations

import ssl

from pytlsinspector.core.protocols import (
    deprecated_protocols,
    probe_protocols,
    supported_protocols,
)
from tests.conftest import start_tls_server


class TestProtocolos:
    async def test_detecta_tls12_y_tls13(self, tls_server):
        results = await probe_protocols("127.0.0.1", tls_server.port, timeout=5.0)
        names = supported_protocols(results)
        assert "TLS 1.2" in names
        assert "TLS 1.3" in names
        assert not deprecated_protocols(results)

    async def test_servidor_solo_tls12(self):
        instance = start_tls_server(
            min_version=ssl.TLSVersion.TLSv1_2,
            max_version=ssl.TLSVersion.TLSv1_2,
        )
        try:
            results = await probe_protocols("127.0.0.1", instance.port, timeout=5.0)
            names = supported_protocols(results)
            assert names == ["TLS 1.2"]
        finally:
            instance.stop()

    async def test_resultado_completo(self, tls_server):
        results = await probe_protocols("127.0.0.1", tls_server.port, timeout=5.0)
        assert len(results) == 6
        for result in results:
            assert result.name
            assert isinstance(result.enabled, bool)

    async def test_obsoletos_marcados(self, tls_server):
        results = await probe_protocols("127.0.0.1", tls_server.port, timeout=5.0)
        deprecated = {r.name for r in results if r.deprecated}
        assert "TLS 1.0" in deprecated
        assert "TLS 1.1" in deprecated
        assert "TLS 1.2" not in deprecated
