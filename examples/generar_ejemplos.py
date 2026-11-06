"""Genera informes de ejemplo de PyTLSInspector contra un laboratorio local.

Levanta un servidor TLS con certificado autofirmado y ejecuta la auditoría
completa, exportando los informes en JSON, CSV y HTML dentro de ``examples/``.

Uso:
    python examples/generar_ejemplos.py
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

# Añade el directorio src al path cuando se ejecuta desde el repositorio.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from conftest import start_tls_server  # noqa: E402

from pytlsinspector.config import AuditConfig  # noqa: E402
from pytlsinspector.core.auditor import Auditor  # noqa: E402
from pytlsinspector.export import export_result  # noqa: E402

DESTINO = ROOT / "examples"


async def main() -> int:
    """Levanta el laboratorio, ejecuta la auditoría y escribe los informes."""
    server = start_tls_server()
    try:
        config = AuditConfig(
            target="127.0.0.1",
            port=server.port,
            confirm_authorized=True,
        )
        result = await Auditor(config).run()

        DESTINO.mkdir(parents=True, exist_ok=True)
        for fmt in ("json", "csv", "html"):
            written = export_result(result, DESTINO / "informe-ejemplo", fmt)
            print(f"  {fmt.upper():4} -> {written.relative_to(ROOT)}")

        print(
            f"\nAuditoría completada: {len(result.findings)} hallazgos "
            f"en {result.duration_seconds:.2f} s"
        )
        if result.chain and result.chain.leaf:
            leaf = result.chain.leaf
            print(
                f"Certificado: {leaf.common_name or leaf.subject} · "
                f"caduca en {leaf.days_until_expiry} días"
            )
        if result.negotiated_protocol:
            print(
                f"Protocolo negociado: {result.negotiated_protocol} · "
                f"cifrado: {result.negotiated_cipher}"
            )
    finally:
        server.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
