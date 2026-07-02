"""Génération de rapports (JSON, Markdown, HTML)."""

from __future__ import annotations

import datetime as _dt
import html
import json
from pathlib import Path

from .findings import FindingsCollection, Severity

_SEV_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}

_SEV_COLOR = {
    "critical": "#b00020",
    "high": "#e65100",
    "medium": "#f9a825",
    "low": "#1565c0",
    "info": "#616161",
}


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def write_json(findings: FindingsCollection, target: str, path: str | Path) -> Path:
    payload = {
        "scan_target": target,
        "generated_at": _now(),
        "summary": findings.by_severity(),
        "highest_severity": findings.highest_severity().value,
        "total_findings": len(findings),
        "findings": findings.to_list(),
    }
    p = Path(path)
    p.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return p


def write_markdown(findings: FindingsCollection, target: str, path: str | Path) -> Path:
    counts = findings.by_severity()
    lines: list[str] = []
    lines.append(f"# Rapport d'analyse de sécurité — `{target}`")
    lines.append("")
    lines.append(f"*Généré le {_now()} par CyberBot.*")
    lines.append("")
    lines.append("## Synthèse")
    lines.append("")
    lines.append("| Sévérité | Nombre |")
    lines.append("| --- | --- |")
    for sev in reversed(list(Severity)):
        emoji = _SEV_EMOJI[sev.value]
        lines.append(f"| {emoji} {sev.value.capitalize()} | {counts[sev.value]} |")
    lines.append(f"| **Total** | **{len(findings)}** |")
    lines.append("")

    if not len(findings):
        lines.append("_Aucun finding relevé._")
    else:
        lines.append("## Détail des findings")
        lines.append("")
        for i, f in enumerate(findings.items, start=1):
            emoji = _SEV_EMOJI[f.severity.value]
            lines.append(f"### {i}. {emoji} {f.title}")
            lines.append("")
            lines.append(f"- **Sévérité** : {f.severity.value}")
            lines.append(f"- **Cible** : `{f.target}`")
            lines.append(f"- **Module** : `{f.module}`")
            if f.description:
                lines.append(f"- **Description** : {f.description}")
            if f.evidence:
                lines.append(f"- **Preuve** :")
                lines.append("")
                lines.append("  ```")
                for ln in f.evidence.splitlines() or [f.evidence]:
                    lines.append(f"  {ln}")
                lines.append("  ```")
            if f.recommendation:
                lines.append(f"- **Recommandation** : {f.recommendation}")
            if f.references:
                refs = ", ".join(f"[{r}]({r})" for r in f.references)
                lines.append(f"- **Références** : {refs}")
            lines.append("")

    p = Path(path)
    p.write_text("\n".join(lines), encoding="utf-8")
    return p


def write_html(findings: FindingsCollection, target: str, path: str | Path) -> Path:
    counts = findings.by_severity()
    esc = html.escape

    rows = ""
    for sev in reversed(list(Severity)):
        color = _SEV_COLOR[sev.value]
        rows += (
            f"<tr><td><span class='dot' style='background:{color}'></span>"
            f"{sev.value.capitalize()}</td><td>{counts[sev.value]}</td></tr>"
        )

    cards = ""
    for i, f in enumerate(findings.items, start=1):
        color = _SEV_COLOR[f.severity.value]
        refs = "".join(
            f"<li><a href='{esc(r)}'>{esc(r)}</a></li>" for r in f.references
        )
        refs_block = f"<ul class='refs'>{refs}</ul>" if refs else ""
        ev_block = (
            f"<pre>{esc(f.evidence)}</pre>" if f.evidence else ""
        )
        cards += f"""
        <div class="card" style="border-left:6px solid {color}">
          <h3>{i}. {esc(f.title)}
            <span class="badge" style="background:{color}">{f.severity.value}</span>
          </h3>
          <p class="meta">Cible <code>{esc(f.target)}</code> · Module <code>{esc(f.module)}</code></p>
          {f'<p>{esc(f.description)}</p>' if f.description else ''}
          {ev_block}
          {f'<p class="reco"><strong>Recommandation :</strong> {esc(f.recommendation)}</p>' if f.recommendation else ''}
          {refs_block}
        </div>"""

    if not len(findings):
        cards = "<p><em>Aucun finding relevé.</em></p>"

    doc = f"""<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rapport CyberBot — {esc(target)}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
         margin: 0; padding: 2rem; max-width: 960px; margin-inline: auto;
         line-height: 1.5; }}
  h1 {{ margin-bottom: .2rem; }}
  .sub {{ color: #888; margin-top: 0; }}
  table {{ border-collapse: collapse; margin: 1rem 0; }}
  td, th {{ padding: .4rem .8rem; border-bottom: 1px solid #8883; text-align: left; }}
  .dot {{ display:inline-block; width:.8rem; height:.8rem; border-radius:50%;
          margin-right:.5rem; vertical-align:middle; }}
  .card {{ background:#8881; border-radius:8px; padding:1rem 1.2rem; margin:1rem 0; }}
  .card h3 {{ margin:.2rem 0 .4rem; }}
  .badge {{ color:#fff; font-size:.7rem; padding:.15rem .5rem; border-radius:99px;
            vertical-align:middle; margin-left:.5rem; text-transform:uppercase; }}
  .meta {{ color:#888; font-size:.9rem; margin:.2rem 0 .6rem; }}
  pre {{ background:#0002; padding:.7rem; border-radius:6px; overflow:auto;
         font-size:.85rem; }}
  code {{ background:#8882; padding:.1rem .3rem; border-radius:4px; }}
  .reco {{ background:#2e7d3222; padding:.5rem .7rem; border-radius:6px; }}
  .refs a {{ font-size:.85rem; }}
</style>
</head>
<body>
  <h1>Rapport d'analyse de sécurité</h1>
  <p class="sub">Cible : <code>{esc(target)}</code> · Généré le {_now()}</p>
  <h2>Synthèse</h2>
  <table>
    <tr><th>Sévérité</th><th>Nombre</th></tr>
    {rows}
    <tr><td><strong>Total</strong></td><td><strong>{len(findings)}</strong></td></tr>
  </table>
  <h2>Findings</h2>
  {cards}
  <hr>
  <p class="sub">CyberBot — usage autorisé uniquement.</p>
</body>
</html>"""

    p = Path(path)
    p.write_text(doc, encoding="utf-8")
    return p


def write_all(
    findings: FindingsCollection,
    target: str,
    out_dir: str | Path,
    basename: str | None = None,
) -> dict[str, Path]:
    """Écrit les trois formats et retourne les chemins."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    safe = (basename or target).replace("/", "_").replace(":", "_")
    base = f"{safe}-{stamp}"
    return {
        "json": write_json(findings, target, out / f"{base}.json"),
        "markdown": write_markdown(findings, target, out / f"{base}.md"),
        "html": write_html(findings, target, out / f"{base}.html"),
    }
