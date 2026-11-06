"""Excepciones propias de PyTLSInspector.

Una jerarquía propia permite al llamador distinguir entre un objetivo no
alcanzable, una entrada no válida o un problema al exportar el informe.
"""

from __future__ import annotations


class PyTLSInspectorError(Exception):
    """Excepción base de PyTLSInspector."""


class ValidationError(PyTLSInspectorError):
    """Entrada no válida (host, puerto o parámetro incorrecto)."""


class AuthorizationError(PyTLSInspectorError):
    """El objetivo no está dentro del alcance autorizado."""


class ScopeError(PyTLSInspectorError):
    """El fichero de alcance está ausente o es incorrecto."""


class ConnectionError(PyTLSInspectorError):
    """No se pudo establecer la conexión TLS con el objetivo."""


class ExportError(PyTLSInspectorError):
    """No se pudo escribir el informe."""
