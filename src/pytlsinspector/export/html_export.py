"""Exportación de resultados a HTML (informe autónomo y legible)."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, select_autoescape

from pytlsinspector.exceptions import ExportError
from pytlsinspector.models import Severity, TLSAuditResult

_TEMPLATE = """<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Informe PyTLSInspector — {{ result.target }}:{{ result.port }}</title>
<style>
:root{--bg:#0f1419;--panel:#171e26;--line:#263140;--fg:#e6edf3;--muted:#8b98a5;--accent:#3ddc97;--warn:#f0b429;--bad:#ef5350;--info:#58a6ff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;line-height:1.55;font-size:15px}
main{max-width:1100px;margin:0 auto;padding:32px 20px 64px}
h1{font-size:26px;margin:0 0 4px}
h2{font-size:19px;margin:32px 0 12px;border-bottom:1px solid var(--line);padding-bottom:6px}
h3{font-size:16px;margin:24px 0 8px}
.sub{color:var(--muted);font-size:13px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:20px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px}
.card .num{font-size:26px;font-weight:700}
.card .lbl{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em}
.sev-confirmado{color:var(--bad)}.sev-probable{color:var(--warn)}.sev-potencial{color:var(--info)}.sev-indicio{color:var(--muted)}.sev-recomendacion{color:var(--accent)}
table{width:100%;border-collapse:collapse;margin-top:8px;font-size:14px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.05em}
tr:hover td{background:rgba(255,255,255,.02)}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;border:1px solid var(--line)}
.finding{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px;margin:12px 0}
.finding h3{margin:0 0 6px;font-size:16px}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px}
.evidence{background:rgba(88,166,255,.07);border-left:3px solid var(--info);padding:8px 12px;margin:8px 0;font-size:13px}
.reco{background:rgba(61,220,151,.07);border-left:3px solid var(--accent);padding:8px 12px;margin:8px 0;font-size:13px}
.ok{color:var(--accent)}.bad{color:var(--bad)}.warn{color:var(--warn)}
.foot{margin-top:40px;color:var(--muted);font-size:12px;border-top:1px solid var(--line);padding-top:12px}
</style>
</head>
<body>
<main>
  <h1>Informe de auditoría SSL/TLS</h1>
  <p class="sub">
    Herramienta: <strong>{{ result.tool }}</strong> v{{ result.version }}
    &middot; Objetivo: <span class="mono">{{ result.target }}:{{ result.port }}</span>
    {% if result.scope %}&middot; Alcance: {{ result.scope }}{% endif %}
  </p>
  <p class="sub">
    Inicio: {{ result.started_at.strftime('%Y-%m-%d %H:%M:%S') }} &middot;
    Fin: {{ result.finished_at.strftime('%Y-%m-%d %H:%M:%S') }} &middot;
    Duración: {{ "%.2f"|format(result.duration_seconds) }} s
    &middot; Conexión:
    {% if result.connected %}<span class="ok">establecida</span>
    {% else %}<span class="bad">no establecida</span>{% endif %}
    {% if result.negotiated_protocol %}
    &middot; Protocolo negociado: <span class="mono">{{ result.negotiated_protocol }}</span>
    {% endif %}
    {% if result.negotiated_cipher %}
    &middot; Cifrado negociado: <span class="mono">{{ result.negotiated_cipher }}</span>
    {% endif %}
  </p>

  <div class="cards">
    <div class="card"><div class="num sev-confirmado">{{ result.statistics.get('confirmado', 0) }}</div><div class="lbl">Confirmados</div></div>
    <div class="card"><div class="num sev-probable">{{ result.statistics.get('probable', 0) }}</div><div class="lbl">Probables</div></div>
    <div class="card"><div class="num sev-potencial">{{ result.statistics.get('potencial', 0) }}</div><div class="lbl">Potenciales</div></div>
    <div class="card"><div class="num sev-indicio">{{ result.statistics.get('indicio', 0) }}</div><div class="lbl">Indicios</div></div>
    <div class="card"><div class="num sev-recomendacion">{{ result.statistics.get('recomendacion', 0) }}</div><div class="lbl">Recomendaciones</div></div>
  </div>

  {% if result.chain and result.chain.leaf %}
  <h2>Certificado</h2>
  {% set leaf = result.chain.leaf %}
  <div class="cards">
    <div class="card"><div class="num">{{ leaf.subject[:24] or '—' }}</div><div class="lbl">Sujeto</div></div>
    <div class="card"><div class="num">{{ leaf.issuer[:24] or '—' }}</div><div class="lbl">Emisor</div></div>
    <div class="card"><div class="num">{{ leaf.key_size or '—' }} bits</div><div class="lbl">Clave ({{ leaf.key_algorithm }})</div></div>
    <div class="card"><div class="num">{{ leaf.days_until_expiry }}</div><div class="lbl">Días hasta caducar</div></div>
    <div class="card"><div class="num">{{ result.chain.length }}</div><div class="lbl">Certificados en cadena</div></div>
  </div>
  <table>
    <tbody>
      <tr><th>Sujeto</th><td class="mono">{{ leaf.subject }}</td></tr>
      <tr><th>Emisor</th><td class="mono">{{ leaf.issuer }}</td></tr>
      <tr><th>Nombre común</th><td class="mono">{{ leaf.common_name or '—' }}</td></tr>
      <tr><th>Válido desde</th><td class="mono">{{ leaf.not_before.strftime('%Y-%m-%d %H:%M:%S') }} UTC</td></tr>
      <tr><th>Válido hasta</th><td class="mono">{{ leaf.not_after.strftime('%Y-%m-%d %H:%M:%S') }} UTC</td></tr>
      <tr><th>Algoritmo de firma</th><td class="mono">{{ leaf.signature_algorithm }}</td></tr>
      <tr><th>Nombres alternativos (DNS)</th><td class="mono">{{ ', '.join(leaf.san_dns) or '—' }}</td></tr>
      <tr><th>Nombres alternativos (IP)</th><td class="mono">{{ ', '.join(leaf.san_ip) or '—' }}</td></tr>
      <tr><th>Número de serie</th><td class="mono">{{ leaf.serial_number }}</td></tr>
      <tr><th>Huella SHA-256</th><td class="mono">{{ leaf.sha256_fingerprint }}</td></tr>
      <tr><th>Autofirmado</th><td>{{ 'Sí' if leaf.is_self_signed else 'No' }}</td></tr>
      <tr><th>Cadena de confianza</th><td>
        {% if result.chain.trusted %}<span class="ok">Validada</span>
        {% else %}<span class="bad">No validada</span>
        {% if result.chain.verification_error %}<div class="mono sub">{{ result.chain.verification_error }}</div>{% endif %}
        {% endif %}
      </td></tr>
    </tbody>
  </table>
  {% endif %}

  <h2>Hallazgos</h2>
  {% if result.findings %}
    {% for finding in result.findings %}
    <div class="finding">
      <h3><span class="badge sev-{{ finding.severity.value }}">{{ finding.severity.value }}</span>
          {{ finding.title }}</h3>
      <p class="sub">Categoría: {{ finding.category.value }} · ID: <span class="mono">{{ finding.id }}</span></p>
      <p>{{ finding.description }}</p>
      {% if finding.evidence %}<div class="evidence"><strong>Evidencia:</strong> {{ finding.evidence }}</div>{% endif %}
      {% if finding.recommendation %}<div class="reco"><strong>Recomendación:</strong> {{ finding.recommendation }}</div>{% endif %}
      {% if finding.references %}<p class="sub">Referencias: {% for ref in finding.references %}<span class="mono">{{ ref }}</span>{% if not loop.last %} · {% endif %}{% endfor %}</p>{% endif %}
    </div>
    {% endfor %}
  {% else %}
    <p>No se han registrado hallazgos.</p>
  {% endif %}

  <h2>Protocolos</h2>
  {% if result.protocols %}
  <table>
    <thead><tr><th>Protocolo</th><th>Habilitado</th><th>Estado</th></tr></thead>
    <tbody>
    {% for protocol in result.protocols %}
      <tr>
        <td class="mono">{{ protocol.name }}</td>
        <td>{% if protocol.enabled %}<span class="bad">Sí</span>{% else %}<span class="ok">No</span>{% endif %}</td>
        <td>{% if protocol.deprecated and protocol.enabled %}<span class="bad">Obsoleto habilitado</span>
            {% elif protocol.deprecated %}<span class="ok">Obsoleto y deshabilitado</span>
            {% else %}<span class="ok">Recomendado</span>{% endif %}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p class="sub">No se obtuvieron datos de protocolos.</p>
  {% endif %}

  <h2>Conjuntos de cifrado</h2>
  {% if result.ciphers %}
  <table>
    <thead><tr><th>Conjunto</th><th>Admitido</th><th>Fortaleza</th><th>Intercambio</th></tr></thead>
    <tbody>
    {% for cipher in result.ciphers %}
      <tr>
        <td class="mono">{{ cipher.name }}</td>
        <td>{% if cipher.enabled %}<span class="warn">Sí</span>{% else %}No{% endif %}</td>
        <td>{% if cipher.strength == 'debil' %}<span class="bad">Débil</span>
            {% elif cipher.strength == 'media' %}<span class="warn">Media</span>
            {% elif cipher.strength == 'fuerte' %}<span class="ok">Fuerte</span>
            {% else %}—{% endif %}</td>
        <td class="mono">{{ cipher.key_exchange or '—' }}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p class="sub">No se obtuvieron datos de conjuntos de cifrado.</p>
  {% endif %}

  <div class="foot">
    <p>Generado por {{ result.tool }} v{{ result.version }}. Informe de auditoría autorizada.
    No incluye datos personales ni credenciales. Verifique siempre los hallazgos antes de
    considerarlos definitivos.</p>
  </div>
</main>
</body>
</html>
"""


def render_html(result: TLSAuditResult) -> str:
    """Renderiza el informe HTML a partir de la plantilla."""
    env = Environment(autoescape=select_autoescape(("html", "xml")))
    template = env.from_string(_TEMPLATE)
    return template.render(result=result, Severity=Severity)


def export_html(result: TLSAuditResult, path: Path) -> Path:
    """Escribe el informe HTML.

    Raises:
        ExportError: Si no se puede escribir el fichero.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render_html(result), encoding="utf-8")
    except OSError as exc:
        raise ExportError(f"no se pudo escribir el HTML en {path}: {exc}") from exc
    return path
