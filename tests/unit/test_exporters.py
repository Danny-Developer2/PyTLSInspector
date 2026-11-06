"""Pruebas unitarias de los exportadores de PyTLSInspector."""

from __future__ import annotations

import csv
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from pytlsinspector.exceptions import ExportError
from pytlsinspector.export import export_result
from pytlsinspector.export.csv_export import export_csv
from pytlsinspector.export.html_export import export_html
from pytlsinspector.export.json_export import export_json
from pytlsinspector.models import (
    Category,
    CipherInfo,
    Finding,
    Severity,
    TLSAuditResult,
    TLSVersionInfo,
)


def _sample_result() -> TLSAuditResult:
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    return TLSAuditResult(
        target="ejemplo.test",
        port=443,
        authorized=True,
        started_at=now,
        finished_at=now + timedelta(seconds=2),
        duration_seconds=2.0,
        connected=True,
        negotiated_protocol="TLSv1.3",
        negotiated_cipher="TLS_AES_256_GCM_SHA384",
        protocols=[TLSVersionInfo(name="TLS 1.3", enabled=True, deprecated=False)],
        ciphers=[CipherInfo(name="TLS_AES_256_GCM_SHA384", enabled=True, strength="fuerte")],
        findings=[
            Finding(
                id="ejemplo_1",
                category=Category.PROTOCOL,
                severity=Severity.PROBABLE,
                title="Protocolo obsoleto habilitado: TLS 1.0",
                description="Descripción de ejemplo",
                evidence="El servidor completa el handshake con TLS 1.0.",
                recommendation="Deshabilita TLS 1.0.",
                references=["https://ejemplo.test/ref"],
            )
        ],
        statistics={
            "confirmado": 0,
            "probable": 1,
            "potencial": 0,
            "indicio": 0,
            "recomendacion": 0,
        },
    )


class TestJsonExport:
    def test_genera_json_valido(self, tmp_path: Path):
        path = export_json(_sample_result(), tmp_path / "resultado.json")
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["tool"] == "PyTLSInspector"
        assert data["schema"] == "pytlsinspector/audit-result"
        assert data["findings"][0]["id"] == "ejemplo_1"

    def test_incluye_certificado_si_existe(self, tmp_path: Path):
        path = export_json(_sample_result(), tmp_path / "resultado.json")
        data = json.loads(path.read_text(encoding="utf-8"))
        assert "chain" in data


class TestCsvExport:
    def test_una_fila_por_hallazgo(self, tmp_path: Path):
        path = export_csv(_sample_result(), tmp_path / "resultado.csv")
        with path.open(encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        assert len(rows) == 1
        assert rows[0]["severidad"] == "probable"
        assert rows[0]["objetivo"] == "ejemplo.test:443"


class TestHtmlExport:
    def test_genera_html_con_hallazgos(self, tmp_path: Path):
        path = export_html(_sample_result(), tmp_path / "resultado.html")
        html = path.read_text(encoding="utf-8")
        assert "Informe de auditoría SSL/TLS" in html
        assert "Protocolo obsoleto habilitado" in html
        assert "TLS_AES_256_GCM_SHA384" in html

    def test_escapa_contenido_malicioso(self, tmp_path: Path):
        result = _sample_result()
        original = result.findings[0]
        result.findings[0] = Finding(
            id=original.id,
            category=original.category,
            severity=original.severity,
            title=original.title,
            description="<script>alert(1)</script>",
            evidence=original.evidence,
            recommendation=original.recommendation,
            references=original.references,
        )
        path = export_html(result, tmp_path / "resultado.html")
        html = path.read_text(encoding="utf-8")
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html


class TestExportResult:
    @pytest.mark.parametrize("fmt", ["json", "csv", "html"])
    def test_formatos_soportados(self, tmp_path: Path, fmt: str):
        written = export_result(_sample_result(), tmp_path / "salida", fmt)
        assert written.exists()
        assert written.suffix == f".{fmt}"

    def test_formato_no_soportado(self, tmp_path: Path):
        with pytest.raises(ExportError):
            export_result(_sample_result(), tmp_path / "salida", "pdf")
