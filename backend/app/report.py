"""Markdown report (10 section 1.9): executive summary, inventory, evidence, risk factors, migration roadmap, limitations, metadata."""
from __future__ import annotations

from sqlalchemy.orm import Session

from . import analysis
from .db import FindingRow, ScanRow
from .ingestion import IngestionError
from .risk import LABEL


def _esc(s: object) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ")


def build_report(db: Session, scan_id: str) -> str:
    sm = analysis.summarize(db, scan_id)
    scan = db.get(ScanRow, scan_id)
    if scan is None or scan.status != "analyzed":
        raise IngestionError("not_analyzed", "Analyze the scan before generating a report.", 409)
    t, an = sm["totals"], scan.analysis or {}
    rows = [r for r in analysis._rows(db, scan_id) if not r.suppressed]
    code = [r for r in rows if not r.comment_only]
    L: list[str] = [f"# Quantum Migration Copilot report: {scan.repo_name}", "",
                    "> **Static-analysis estimates. Not a certification.** Quantum-vulnerable means vulnerable to a *future* "
                    "cryptographically relevant quantum computer, not broken today.", "",
                    "## 1. Executive summary", "",
                    f"- **{t['crypto_findings']}** cryptographic findings in **{t['services']}** service(s); **{t['quantum_vulnerable']}** use quantum-vulnerable public-key cryptography.",
                    f"- **{t['critical']}** findings are in the Critical priority band; **{t['hndl_elevated']}** carry an *elevated harvest-now-decrypt-later* flag "
                    "(long-lived sensitive data protected by quantum-vulnerable key establishment).",
                    f"- **{t['already_pqc']}** finding(s) already use post-quantum algorithms. {t['high_confidence']} findings are high-confidence; the rest require human review.",
                    f"- Priority bands: " + ", ".join(f"{k} {v}" for k, v in sm["by_band"].items()) + ".", ""]
    top = [r for r in code if r.band in ("Critical", "High")][:5]
    if top:
        L += ["Top priorities:", ""] + [f"1. **{r.algorithm}** {r.operation.replace('_', ' ')} in `{r.file}:{r.data['line_start']}` ({r.service}), QMP {r.qmp} {r.band}"
                                      + (" + HNDL elevated" if r.hndl else "") for r in top] + [""]
    L += ["## 2. Services", "", "| Service | Data | Exposure | Quantum-vulnerable | Critical | Status |", "|---|---|---|---|---|---|"]
    for v in sm["services"]:
        L.append(f"| {_esc(v['service'])} | {v['data_classification'] or '?'} | {'internet-facing' if v['internet_exposed'] else 'internal' if v['internet_exposed'] is False else '?'} | "
                 f"{v['quantum_vulnerable']} | {v['critical']} | {_esc(v['migration_status'])} |")
    L += ["", "## 3. Cryptographic inventory", "", "| ID | Priority | Algorithm | Operation | Service | Location | Confidence | Quantum |", "|---|---|---|---|---|---|---|---|"]
    for r in code:
        q = "post-quantum" if r.already_pqc else "vulnerable" if r.quantum_vulnerable else "no"
        L.append(f"| {r.fid} | {r.band} {r.qmp} | {_esc(r.algorithm)} | {r.operation} | {_esc(r.service)} | `{_esc(r.file)}:{r.data['line_start']}` | {r.confidence_level} | {q} |")
    L += ["", "## 4. Findings with evidence and risk factors (Critical and High)", "", f"*{LABEL}*", ""]
    for r in [x for x in code if x.band in ("Critical", "High")]:
        k = r.risk["factors"]
        L += [f"### {r.fid}: {r.algorithm} {r.operation.replace('_', ' ')} ({r.service})", "",
              f"- Location: `{r.file}:{r.data['line_start']}`; rule `{r.data['rule_id']}` v{r.data['rule_version']}; confidence {r.confidence_level} ({r.data['confidence']})",
              f"- Evidence: `{_esc(r.data['evidence'])}`",
              f"- QMP **{r.qmp}** ({r.band}); role: {r.risk['role']}" + (f"; **HNDL {r.risk['hndl']['severity']}**" if r.hndl else ""), "",
              "| Factor | Value | Weight | Why |", "|---|---|---|---|"]
        L += [f"| {k[x]['label']} ({x}) | {k[x]['value']} | {k[x]['weight']} | {_esc(k[x]['why'])} |" for x in ("QE", "DS", "IE", "BC", "MC")]
        L += [f"", f"raw = {r.risk['raw']} → `{r.risk['formula']}`", ""]
    L += ["## 5. Migration roadmap (candidate directions)", "",
          "| Priority | Current crypto | Candidate | Service | Complexity | First step |", "|---|---|---|---|---|---|"]
    plan = analysis.migration_plan(db, scan_id)
    for p in plan["rows"]:
        L.append(f"| {p['band']} {p['qmp']} | {_esc(p['current'])} @ `{p['file']}:{p['line_start']}` | {_esc(p['direction'])} | {_esc(p['service'])} | {p['complexity']} | {_esc(p['steps'][0] if p['steps'] else '-')} |")
    L += ["", "### Crypto-agility recommendations", ""] + [f"{i}. {c}" for i, c in enumerate(plan["crypto_agility"], 1)]
    L += ["", "### Migration notes", ""] + [f"- {h}" for h in plan["honesty"]]
    sup = [r for r in analysis._rows(db, scan_id) if r.suppressed]
    if sup:
        L += ["", "### Suppressed findings (nothing disappears silently)", ""] + [f"- {r.fid} `{r.file}` : {r.suppression['reason']} ({r.suppression['author']})" for r in sup]
    L += ["", "## 6. Limitations", "",
          "- This is a static-analysis estimate and **not a certification** of security or of \"quantum safety\".",
          "- Static analysis misses dynamically loaded crypto, native binaries, external services and obfuscated code; low/medium findings require human review.",
          "- QMP is an internal prototype prioritization methodology, **not** an official NIST score and not CVSS.",
          "- Candidate migration directions assume peer ecosystems support the targets; final decisions need human security review.",
          f"- {t['comment_or_doc_mentions']} comment/documentation mentions are listed in the inventory API but not scored.", "",
          "## 7. Scan metadata", "",
          f"- Scan ID: `{scan_id}`; engine `{an.get('engine_version')}`; scanned as of {an.get('as_of')}",
          f"- Archive: {scan.original_filename} ({scan.manifest.get('archive_type')}); files scanned: {an.get('files_scanned')}",
          f"- Redacted secret values (not stored): {scan.manifest.get('stats', {}).get('redaction_count')}", "", "| Rule | Version | Hits |", "|---|---|---|"]
    L += [f"| {rid} | {an.get('rule_versions', {}).get(rid)} | {n} |" for rid, n in an.get("rule_hits", {}).items()]
    return "\n".join(L) + "\n"
