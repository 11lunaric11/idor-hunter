"""Output formats: CSV for raw probes, HTML for findings."""
from __future__ import annotations

import csv
import html
import json
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .analyzer import Finding
from .scanner import Probe


def write_probes_csv(probes: list[Probe], path: Path) -> None:
    """Dump every probe to CSV for ad-hoc analysis."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if not probes:
        path.write_text("", encoding="utf-8")
        return

    fieldnames = list(probes[0].to_dict().keys())
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for p in probes:
            row = p.to_dict()
            # CSV-safe: truncate body preview to 500 chars
            row["body_preview"] = (row.get("body_preview") or "")[:500]
            w.writerow(row)


def write_findings_json(findings: list[Finding], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "findings": [f.to_dict() for f in findings],
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _harvested_pairs(probes: list[Probe]) -> list[tuple[str, str]]:
    """(id, source_url) pairs for probes that came from a harvest pass.

    Deduplicated by id (a harvested UUID probed against multiple users
    shouldn't appear multiple times in the report).
    """
    seen: set[str] = set()
    out: list[tuple[str, str]] = []
    for p in probes:
        if not p.discovered_via or p.id in seen:
            continue
        seen.add(p.id)
        out.append((p.id, p.discovered_via))
    return out


def write_html_report(
    findings: list[Finding],
    stats: dict,
    probes_count: int,
    path: Path,
    config_name: str = "",
    probes: list[Probe] | None = None,
) -> None:
    """Render the human-readable HTML report."""
    path.parent.mkdir(parents=True, exist_ok=True)

    template_dir = Path(__file__).parent / "templates"
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html"]),
    )
    env.filters["pretty_json"] = lambda v: json.dumps(v, indent=2)
    env.filters["e"] = html.escape

    harvested = _harvested_pairs(probes) if probes else []

    template = env.get_template("report.html.j2")
    rendered = template.render(
        findings=findings,
        stats=stats,
        probes_count=probes_count,
        config_name=config_name,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        harvested=harvested,
    )
    path.write_text(rendered, encoding="utf-8")
