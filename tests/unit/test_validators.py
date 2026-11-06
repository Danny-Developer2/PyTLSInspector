"""Pruebas unitarias de validadores y control de autorización."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pytlsinspector.exceptions import AuthorizationError, ScopeError, ValidationError
from pytlsinspector.models import Scope
from pytlsinspector.utils.validators import (
    ensure_authorized,
    ensure_path_writable,
    is_target_in_scope,
    load_scope_file,
    validate_target,
)


class TestValidateTarget:
    @pytest.mark.parametrize(
        "target,host,port",
        [
            ("ejemplo.test", "ejemplo.test", 443),
            ("ejemplo.test:8443", "ejemplo.test", 8443),
            ("https://ejemplo.test/", "ejemplo.test", 443),
            ("https://ejemplo.test:8443/ruta", "ejemplo.test", 8443),
            ("127.0.0.1:8000", "127.0.0.1", 8000),
        ],
    )
    def test_objetivos_validos(self, target, host, port):
        endpoint = validate_target(target)
        assert endpoint.host == host
        assert endpoint.port == port

    @pytest.mark.parametrize(
        "target", ["", "   ", "ejemplo.test:abc", "ejemplo.test:0", "ejemplo.test:70000", "://raro"]
    )
    def test_objetivos_invalidos(self, target):
        with pytest.raises(ValidationError):
            validate_target(target)


class TestScope:
    @pytest.fixture()
    def scope(self) -> Scope:
        return Scope(name="Lab", authorized_targets=["ejemplo.test", "127.0.0.1:8443"])

    def test_host_dentro_del_scope(self, scope):
        assert is_target_in_scope("ejemplo.test", 443, scope)

    def test_host_con_puerto_dentro_del_scope(self, scope):
        assert is_target_in_scope("127.0.0.1", 8443, scope)

    def test_host_fuera_del_scope(self, scope):
        assert not is_target_in_scope("otro.test", 443, scope)

    def test_puerto_distinto_fuera_del_scope(self, scope):
        assert not is_target_in_scope("127.0.0.1", 443, scope)


class TestEnsureAuthorized:
    def test_sin_scope_ni_confirmacion(self):
        with pytest.raises(AuthorizationError):
            ensure_authorized("ejemplo.test", 443, None, False)

    def test_confirmacion_directa(self):
        ensure_authorized("ejemplo.test", 443, None, True)

    def test_fuera_de_alcance(self):
        scope = Scope(name="Lab", authorized_targets=["127.0.0.1:8443"])
        with pytest.raises(ValidationError):
            ensure_authorized("127.0.0.1", 443, scope, True)


class TestLoadScopeFile:
    def test_scope_valido(self, tmp_path: Path):
        path = tmp_path / "scope.json"
        path.write_text(
            json.dumps({"name": "Lab", "authorized_targets": ["ejemplo.test"]}),
            encoding="utf-8",
        )
        scope = load_scope_file(path)
        assert scope is not None
        assert scope.name == "Lab"

    def test_sin_fichero_devuelve_none(self):
        assert load_scope_file(None) is None

    def test_scope_invalido(self, tmp_path: Path):
        path = tmp_path / "scope.json"
        path.write_text("{ no valido", encoding="utf-8")
        with pytest.raises(ScopeError):
            load_scope_file(path)

    def test_scope_sin_authorized_targets(self, tmp_path: Path):
        path = tmp_path / "scope.json"
        path.write_text(json.dumps({"name": "Lab"}), encoding="utf-8")
        with pytest.raises(ScopeError):
            load_scope_file(path)

    def test_scope_inexistente(self, tmp_path: Path):
        with pytest.raises(ScopeError):
            load_scope_file(tmp_path / "ausente.json")


class TestEnsurePathWritable:
    def test_ruta_valida(self, tmp_path: Path):
        ensure_path_writable(tmp_path / "salida.json")

    def test_carpeta_como_fichero(self, tmp_path: Path):
        with pytest.raises(ValidationError):
            ensure_path_writable(tmp_path)

    def test_directorio_inexistente(self, tmp_path: Path):
        with pytest.raises(ValidationError):
            ensure_path_writable(tmp_path / "inexistente" / "salida.json")
