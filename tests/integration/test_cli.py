"""Pruebas de integración de la interfaz de línea de comandos."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from pytlsinspector.cli import app
from tests.conftest import TLSServer

runner = CliRunner()


class TestComandoVersion:
    def test_version(self):
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "PyTLSInspector" in result.output


class TestControlAutorizacion:
    def test_sin_autorizacion_sale_con_error(self, tls_server: TLSServer):
        result = runner.invoke(app, ["scan", f"127.0.0.1:{tls_server.port}"])
        assert result.exit_code == 2

    def test_objetivo_invalido(self):
        result = runner.invoke(app, ["scan", "ejemplo.test:abc", "--confirm-authorized"])
        assert result.exit_code == 2


class TestComandoScan:
    def test_scan_json(self, tls_server: TLSServer, tmp_path: Path):
        salida = tmp_path / "informe"
        result = runner.invoke(
            app,
            [
                "scan",
                f"127.0.0.1:{tls_server.port}",
                "--confirm-authorized",
                "--output",
                str(salida),
                "--format",
                "json",
            ],
        )
        assert result.exit_code == 0, result.output
        datos = json.loads((tmp_path / "informe.json").read_text(encoding="utf-8"))
        assert datos["schema"] == "pytlsinspector/audit-result"
        assert datos["connected"] is True
        assert datos["findings"]

    def test_scan_html(self, tls_server: TLSServer, tmp_path: Path):
        salida = tmp_path / "informe"
        result = runner.invoke(
            app,
            [
                "scan",
                f"127.0.0.1:{tls_server.port}",
                "--confirm-authorized",
                "--output",
                str(salida),
                "--format",
                "html",
            ],
        )
        assert result.exit_code == 0, result.output
        html = (tmp_path / "informe.html").read_text(encoding="utf-8")
        assert "Informe de auditoría SSL/TLS" in html

    def test_scan_csv(self, tls_server: TLSServer, tmp_path: Path):
        salida = tmp_path / "informe"
        result = runner.invoke(
            app,
            [
                "scan",
                f"127.0.0.1:{tls_server.port}",
                "--confirm-authorized",
                "--output",
                str(salida),
                "--format",
                "csv",
            ],
        )
        assert result.exit_code == 0, result.output
        assert (tmp_path / "informe.csv").exists()

    def test_scan_con_scope_fuera_de_alcance(self, tls_server: TLSServer, tmp_path: Path):
        scope = tmp_path / "scope.json"
        scope.write_text(
            json.dumps({"name": "Otro", "authorized_targets": ["10.0.0.1"]}),
            encoding="utf-8",
        )
        result = runner.invoke(
            app,
            ["scan", f"127.0.0.1:{tls_server.port}", "--scope", str(scope)],
        )
        assert result.exit_code == 2

    def test_scan_sin_cifrados(self, tls_server: TLSServer):
        result = runner.invoke(
            app,
            [
                "scan",
                f"127.0.0.1:{tls_server.port}",
                "--confirm-authorized",
                "--no-ciphers",
            ],
        )
        assert result.exit_code == 0, result.output
