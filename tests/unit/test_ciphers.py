"""Pruebas unitarias de la enumeración de conjuntos de cifrado."""

from __future__ import annotations

from pytlsinspector.core.ciphers import (
    enabled_weak_ciphers,
    enumerate_ciphers,
    is_weak_cipher,
)
from pytlsinspector.models import CipherInfo


class TestClasificacionCifrados:
    def test_cifrados_debiles(self):
        assert is_weak_cipher("RC4-SHA") is True
        assert is_weak_cipher("DES-CBC3-SHA") is True
        assert is_weak_cipher("NULL-SHA256") is True
        assert is_weak_cipher("EXP-RC4-MD5") is True

    def test_cifrados_fuertes(self):
        assert is_weak_cipher("TLS_AES_256_GCM_SHA384") is False
        assert is_weak_cipher("ECDHE-RSA-AES256-GCM-SHA384") is False

    def test_cifrado_desconocido(self):
        assert is_weak_cipher("TLS_ALGO_EXOTICO") is False


class TestEnumeracion:
    async def test_enumera_cifrados(self, tls_server):
        results = await enumerate_ciphers(
            "127.0.0.1", tls_server.port, timeout=5.0, max_ciphers=10, concurrency=4
        )
        assert len(results) == 10
        assert any(c.enabled for c in results)

    async def test_sin_cifrados_debiles_en_servidor_moderno(self, tls_server):
        results = await enumerate_ciphers(
            "127.0.0.1", tls_server.port, timeout=5.0, max_ciphers=32, concurrency=8
        )
        weak = enabled_weak_ciphers(results)
        assert weak == []

    async def test_fortaleza_correcta(self, tls_server):
        results = await enumerate_ciphers(
            "127.0.0.1", tls_server.port, timeout=5.0, max_ciphers=8, concurrency=4
        )
        for cipher in results:
            assert cipher.strength in {"fuerte", "media", "debil", "no admitido", "desconocida"}


class TestEnabledWeakCiphers:
    def test_filtra_correctamente(self):
        ciphers = [
            CipherInfo(name="RC4-SHA", enabled=True, strength="debil"),
            CipherInfo(name="TLS_AES_256_GCM_SHA384", enabled=True, strength="fuerte"),
            CipherInfo(name="DES-CBC3-SHA", enabled=False, strength="no admitido"),
        ]
        weak = enabled_weak_ciphers(ciphers)
        assert [c.name for c in weak] == ["RC4-SHA"]
