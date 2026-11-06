# PyTLSInspector

Herramienta profesional de auditoría de configuración SSL/TLS, escrita en Python puro.

PyTLSInspector inspecciona certificados, protocolos, conjuntos de cifrado y cadenas de confianza para identificar configuraciones criptográficas débiles. Está diseñada para auditorías autorizadas y **no realiza explotación activa ni pruebas destructivas**.

> ⚠️ **Uso exclusivo para auditorías autorizadas.** No utilices esta herramienta contra sistemas sin autorización expresa y por escrito.

---

## Características

| Área | Comprobaciones |
| --- | --- |
| Certificado | Caducidad, validez, autofirmado, algoritmo de firma, longitud de clave, marca de CA |
| Nombre de host | Cobertura del SAN y del CN, con soporte de comodines |
| Cadena | Validación contra el almacén de confianza, completitud de la cadena |
| Protocolos | SSLv2, SSLv3, TLS 1.0, TLS 1.1, TLS 1.2 y TLS 1.3 |
| Cifrados | Enumeración individual y clasificación por fortaleza, PFS y algoritmos obsoletos |
| Confianza | Problemas de validación y certificados intermedios ausentes |

Cada hallazgo incluye evidencia, recomendación y referencias técnicas.

## Niveles de severidad

| Nivel | Significado |
| --- | --- |
| `confirmado` | Problema verificado con evidencia directa |
| `probable` | Muy probable, pendiente de validación manual |
| `potencial` | Posible problema en determinados contextos |
| `indicio` | Dato observable que puede ser relevante |
| `recomendacion` | Mejora de endurecimiento, no es una vulnerabilidad |

## Requisitos

- Python 3.11 o superior
- Sin dependencias externas de sistema

## Instalación

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Uso rápido

```bash
# Auditoría completa
pytlsinspector scan ejemplo.com --confirm-authorized

# Host y puerto concretos
pytlsinspector scan ejemplo.com:8443 --confirm-authorized

# Con alcance definido en un fichero
pytlsinspector scan ejemplo.com --scope ./scope.json

# Generar informe HTML
pytlsinspector scan ejemplo.com --confirm-authorized -o informe --format html

# Omitir la enumeración de cifrados (más rápido)
pytlsinspector scan ejemplo.com --confirm-authorized --no-ciphers

# Laboratorio: no verificar el certificado
pytlsinspector scan 127.0.0.1:8443 --confirm-authorized --ignore-tls-errors
```

### Opciones principales

| Opción | Descripción |
| --- | --- |
| `--scope` | Fichero JSON con el alcance autorizado |
| `--confirm-authorized` | Declara que se dispone de autorización expresa |
| `--port` / `-p` | Puerto TLS (por defecto 443) |
| `--timeout` / `-t` | Tiempo de espera por prueba |
| `--concurrency` / `-c` | Pruebas simultáneas |
| `--rate-limit` | Pruebas por segundo |
| `--max-ciphers` | Límite de conjuntos de cifrado a probar |
| `--output` / `-o` | Ruta del informe (se añade la extensión) |
| `--format` / `-f` | `json`, `csv` o `html` |
| `--no-ciphers` | Omitir la enumeración de conjuntos de cifrado |
| `--ignore-tls-errors` | No verificar el certificado (solo laboratorio) |
| `--log-file` | Volcar el registro a fichero |
| `--verbose` / `-v` | Registro detallado |

## Control de autorización

La herramienta no ejecuta el análisis salvo que se cumpla una de estas dos condiciones:

1. Se proporciona `--confirm-authorized`.
2. Se proporciona `--scope` con un fichero JSON cuyo `authorized_targets` incluya el objetivo.

Formato del fichero de alcance:

```json
{
  "name": "Auditoría mensual",
  "authorized_targets": ["ejemplo.com", "127.0.0.1:8443"]
}
```

Los objetivos pueden incluir el puerto; si no lo hacen, se acepta cualquier puerto de ese host.

## Uso como biblioteca

```python
import asyncio
from pathlib import Path

from pytlsinspector.config import AuditConfig
from pytlsinspector.core.auditor import Auditor
from pytlsinspector.export import export_result


async def main():
    config = AuditConfig(target="ejemplo.com", confirm_authorized=True)
    result = await Auditor(config).run()

    if result.chain and result.chain.leaf:
        leaf = result.chain.leaf
        print(f"{leaf.common_name} · caduca en {leaf.days_until_expiry} días")

    for finding in result.findings_by_severity(result.Severity.CONFIRMADO):
        print(finding.title)

    export_result(result, Path("informe"), "html")


asyncio.run(main())
```

## Formatos de salida

- **JSON**: esquema versionado (`pytlsinspector/audit-result`, versión 1).
- **CSV**: una fila por hallazgo, adecuado para hojas de cálculo.
- **HTML**: informe autónomo con certificado, protocolos, cifrados y hallazgos.

## Calidad del proyecto

| Comprobación | Resultado |
| --- | --- |
| Pruebas (`pytest`) | 106 superadas |
| Cobertura | 92 % |
| Tipos (`mypy --strict`) | Sin errores |
| Estilo (`ruff`) | Sin avisos |

Las pruebas generan certificados autofirmados en tiempo de ejecución y levantan servidores TLS locales, por lo que no requieren acceso a la red.

## Estructura del proyecto

```
src/pytlsinspector/
├── core/            # Certificados, protocolos, cifrados y confianza
├── export/          # Exportadores JSON, CSV y HTML
├── utils/           # Red, registro y validadores
├── cli.py           # Interfaz de línea de comandos (Typer + Rich)
├── config.py        # Configuración y catálogos
├── models.py        # Modelos de datos (Pydantic)
└── exceptions.py    # Excepciones propias

tests/
├── unit/            # Pruebas unitarias por módulo
└── integration/     # Pruebas contra el laboratorio TLS local
```

## Limitaciones

- La detección de protocolos depende de las versiones que OpenSSL permita habilitar en el sistema que ejecuta la herramienta.
- La enumeración de cifrados prueba un conjunto representativo, no todos los soportados por el servidor.
- Los resultados son indicativos; los hallazgos `probable` y `potencial` requieren validación manual.
- No comprueba la presencia en listas de revocación (CRL/OCSP).

## Licencia

MIT. Consulta el fichero `LICENSE`.

## Aviso legal

Esta herramienta se distribuye con fines educativos y profesionales. El uso contra sistemas sin autorización es ilegal y es responsabilidad exclusiva de quien la ejecuta.
