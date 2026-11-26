"""Scan report rendering: JSON, CSV, SARIF 2.1.0 and standalone HTML."""
from __future__ import annotations

import csv
import io
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from . import __version__
from .models import Finding, Scan, Target
from .scanner.knowledge import SEVERITIES, SEVERITY_ORDER

_env = Environment(loader=FileSystemLoader(Path(__file__).parent / "templates"),
                   autoescape=select_autoescape(default=True, default_for_string=True))

SEVERITY_LABEL = {"critical": "Crítica", "high": "Alta", "medium": "Média", "low": "Baixa", "info": "Informativa"}
STATUS_LABEL = {"open": "Aberto", "fixed": "Corrigido", "false_positive": "Falso positivo",
                "accepted_risk": "Risco aceito"}


def iso(dt) -> str | None:
    return dt.isoformat(timespec="seconds") + "Z" if dt else None


def finding_dict(f: Finding) -> dict:
    return {
        "id": f.id, "target_id": f.target_id, "check_id": f.check_id, "title": f.title,
        "severity": f.severity, "confidence": f.confidence, "cwe": f.cwe, "owasp": f.owasp, "cvss": f.cvss,
        "url": f.url, "method": f.method, "parameter": f.parameter, "evidence": f.evidence,
        "description": f.description, "remediation": f.remediation, "references": f.references or [],
        "status": f.status, "status_note": f.status_note, "first_seen": iso(f.first_seen),
        "last_seen": iso(f.last_seen), "resolved_at": iso(f.resolved_at),
        "first_scan_id": f.first_scan_id, "last_scan_id": f.last_scan_id,
    }


def scan_dict(s: Scan) -> dict:
    return {
        "id": s.id, "target_id": s.target_id, "target_name": s.target.name if s.target else None,
        "target_url": s.target.base_url if s.target else None, "profile": s.profile, "status": s.status,
        "stage": s.stage, "progress": s.progress, "pages_crawled": s.pages_crawled,
        "requests_sent": s.requests_sent, "summary": s.summary or {}, "notes": s.notes or [], "error": s.error,
        "triggered_by": s.triggered_by, "created_at": iso(s.created_at), "started_at": iso(s.started_at),
        "finished_at": iso(s.finished_at),
    }


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], -f.cvss, f.title, f.url))


def as_json(scan: Scan, target: Target, findings: list[Finding]) -> dict:
    return {"generator": f"Atalaia {__version__}", "scan": scan_dict(scan),
            "target": {"id": target.id, "name": target.name, "base_url": target.base_url},
            "findings": [finding_dict(f) for f in _sorted(findings)]}


def _csv_safe(value) -> str:
    """Neutralise spreadsheet formula injection: evidence comes from scanned sites."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def as_csv(findings: list[Finding]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    cols = ["severity", "cvss", "title", "url", "method", "parameter", "cwe", "owasp", "confidence", "status",
            "first_seen", "last_seen", "evidence", "remediation"]
    writer.writerow(cols)
    for f in _sorted(findings):
        d = finding_dict(f)
        writer.writerow([_csv_safe(d[c]) for c in cols])
    return buf.getvalue()


_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def as_sarif(scan: Scan, target: Target, findings: list[Finding]) -> dict:
    rules: dict[str, dict] = {}
    results = []
    for f in _sorted(findings):
        if f.check_id not in rules:
            rule = {"id": f.check_id, "name": f.check_id,
                    "shortDescription": {"text": f.title.split(":")[0].split(" (")[0]},
                    "fullDescription": {"text": f.description}, "help": {"text": f.remediation},
                    "properties": {"security-severity": str(f.cvss),
                                   "tags": ["security", f.owasp] + ([f"CWE-{f.cwe}"] if f.cwe else [])}}
            if f.references:
                rule["helpUri"] = f.references[0]
            rules[f.check_id] = rule
        results.append({
            "ruleId": f.check_id, "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.title}. {f.evidence}"[:1500]},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.url}}}],
            "partialFingerprints": {"atalaia/v1": f.fingerprint},
            "properties": {"severity": f.severity, "confidence": f.confidence, "status": f.status,
                           "parameter": f.parameter, "method": f.method},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "Atalaia", "version": __version__,
                                      "informationUri": "https://example.invalid/atalaia",
                                      "rules": list(rules.values())}},
                  "results": results,
                  "properties": {"target": target.base_url, "scanId": scan.id, "profile": scan.profile}}],
    }


def as_html(scan: Scan, target: Target, findings: list[Finding]) -> str:
    ordered = _sorted(findings)
    counts = {s: sum(1 for f in ordered if f.severity == s and f.status == "open") for s in SEVERITIES}
    return _env.get_template("report.html").render(
        scan=scan_dict(scan), target=target, findings=[finding_dict(f) for f in ordered], counts=counts,
        profile_label={"passive": "Passiva", "standard": "Padrão", "full": "Completa"}[scan.profile],
        scan_status={"queued": "Na fila", "running": "Em andamento", "completed": "Concluída",
                     "failed": "Falhou", "canceled": "Cancelada"}[scan.status],
        conf_label={"confirmed": "confirmada por execução no navegador", "high": "alta", "medium": "média",
                    "low": "baixa"},
        severities=SEVERITIES, sev_label=SEVERITY_LABEL, status_label=STATUS_LABEL, version=__version__)
