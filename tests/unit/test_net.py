"""Pruebas unitarias de las utilidades de red."""

from __future__ import annotations

from pytlsinspector.utils.net import (
    check_connectivity,
    is_ip_address,
    parse_target,
    resolve_host,
)


class TestParseTarget:
    def test_host_simple(self):
        endpoint = parse_target("ejemplo.test")
        assert endpoint.host == "ejemplo.test"
        assert endpoint.port == 443

    def test_host_con_puerto(self):
        endpoint = parse_target("ejemplo.test:8443")
        assert endpoint.port == 8443

    def test_url_completa(self):
        endpoint = parse_target("https://ejemplo.test:8443/ruta")
        assert endpoint.host == "ejemplo.test"
        assert endpoint.port == 8443

    def test_puerto_por_defecto_personalizado(self):
        endpoint = parse_target("ejemplo.test", default_port=8443)
        assert endpoint.port == 8443

    def test_ipv6_entre_corchetes(self):
        endpoint = parse_target("[::1]:8443")
        assert endpoint.host == "::1"
        assert endpoint.port == 8443

    def test_objetivo_vacio(self):
        from pytlsinspector.exceptions import ValidationError

        try:
            parse_target("")
        except ValidationError:
            return
        raise AssertionError("se esperaba ValidationError")


class TestIsIpAddress:
    def test_ipv4(self):
        assert is_ip_address("127.0.0.1") is True

    def test_ipv6(self):
        assert is_ip_address("::1") is True

    def test_nombre_de_host(self):
        assert is_ip_address("ejemplo.test") is False


class TestResolveHost:
    def test_resuelve_localhost(self):
        assert resolve_host("localhost") in {"127.0.0.1", "::1"}

    def test_resuelve_ip_directa(self):
        assert resolve_host("127.0.0.1") == "127.0.0.1"

    def test_host_inexistente(self):
        assert resolve_host("dominio-que-no-existe-12345.invalid") is None


class TestCheckConnectivity:
    def test_puerto_cerrado(self):
        assert check_connectivity("127.0.0.1", 1, timeout=1.0) is False
