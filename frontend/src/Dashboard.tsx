import { useState } from "react";
import { api, type Summary } from "./api";
import { Band, BAND_COLOR, Badge, Kpi, pretty, rowLink, where } from "./ui";

export default function Dashboard({ s }: { s: Summary }) {
  const t = s.totals;
  const bandTotal = Object.values(s.by_band).reduce((a, b) => a + b, 0) || 1;
  const primMax = Math.max(1, ...Object.values(s.by_primitive));
  const [dlError, setDlError] = useState<string | null>(null);
  const warnings = s.scan_warnings ?? [];
  return (
    <div>
      <p className="meta">
        <strong>{s.scan.repo_name}</strong> · scanned {new Date(s.scan.created_at).toLocaleString()} · engine {s.scan.analysis?.engine_version} ·
        {" "}{s.scan.ingestion.stats.file_count} files ingested · scan <code>{s.scan.id.slice(0, 8)}</code>
      </p>
      <div className="row">
        <button className="btn primary" onClick={() => { setDlError(null); api.downloadReport(s.scan.id).catch((e: Error) => setDlError(e.message)); }}>
          Download report (Markdown)</button>
        <a className="btn" href="#/planner">Migration planner</a>
        <a className="btn" href="#/graph">Dependency graph</a>
        <a className="btn" href="#/inventory">Crypto inventory</a>
      </div>
      {dlError && <p className="error" role="alert">{dlError}</p>}
      {s.readiness?.available && (
        <section className={`panel level level-${({ not_ready_blockers: "critical", not_ready: "high", in_transition: "review" } as Record<string, string>)[s.readiness.level ?? ""] ?? "info"}`}
                 aria-labelledby="rd-h">
          <p className="eyebrow">PQC readiness</p>
          <h3 id="rd-h">{s.readiness.label}</h3>
          <p>{s.readiness.blockers ? `${s.readiness.blockers} critical blocker(s). ` : ""}
            {s.readiness.top_recommendation && <>First recommendation: <b>{s.readiness.top_recommendation}</b>.</>}</p>
          <div className="row">
            <a className="btn primary" href="#/readiness">Open readiness assessment</a>
            <a className="btn" href="#/simulate">Simulate a migration</a>
            <a className="btn" href="#/graph">Dependency graph</a>
          </div>
        </section>)}
      {warnings.length > 0 && (
        <div className="callout warn" role="alert">
          <b>Scan may be incomplete.</b>
          <ul>{warnings.map((w) => <li key={w}>{w}</li>)}</ul>
        </div>)}
      <div className="kpis">
        <Kpi value={t.crypto_findings} label="crypto assets found" hint="Executable crypto usages and crypto configuration (comments excluded)" />
        <Kpi value={t.quantum_vulnerable} label="quantum-vulnerable" tone="var(--band-high)" hint="Public-key crypto vulnerable to a FUTURE quantum computer (not broken today)" />
        <Kpi value={t.critical} label="critical priority" tone="var(--band-critical)" />
        <Kpi value={t.hndl_elevated} label="elevated HNDL risk" tone="var(--band-critical)" hint="Harvest-now-decrypt-later: long-lived sensitive data protected by quantum-vulnerable key establishment" />
        <Kpi value={t.services} label="services affected" />
        <Kpi value={t.already_pqc} label="already post-quantum" tone="var(--ok)" />
      </div>

      <div className="grid2">
        <section className="panel">
          <h3>Priority bands</h3>
          <div className="stack" role="img" aria-label="Findings by priority band">
            {Object.entries(s.by_band).filter(([, n]) => n > 0).map(([b, n]) => (
              <div key={b} style={{ width: `${(n / bandTotal) * 100}%`, background: BAND_COLOR[b] }} title={`${b}: ${n}`}>{n}</div>
            ))}
          </div>
          <ul className="legend">{Object.entries(s.by_band).map(([b, n]) => (
            <li key={b}><i style={{ background: BAND_COLOR[b] }} />{b} <b>{n}</b></li>))}</ul>
          <p className="fine">Bands come from the internal QMP prototype methodology. Medium/low-confidence findings are capped at Review.</p>
        </section>
        <section className="panel">
          <h3>By primitive category</h3>
          {Object.entries(s.by_primitive).map(([p, n]) => (
            <div className="barrow" key={p}><span>{p}</span><div><i style={{ width: `${(n / primMax) * 100}%` }} /></div><b>{n}</b></div>))}
          <p className="fine">Algorithms: {Object.entries(s.by_algorithm).slice(0, 8).map(([a, n]) => `${a} ${n}`).join(" · ")}</p>
        </section>
      </div>

      <section className="panel">
        <h3>Highest-priority findings</h3>
        <table className="tbl">
          <thead><tr><th>Priority</th><th>Algorithm / operation</th><th>Service</th><th>Where</th><th>Confidence</th><th /></tr></thead>
          <tbody>{s.top_findings.map((f) => (
            <tr key={f.id} {...rowLink(`#/finding/${f.id}`, `Open finding ${f.id}`)} className="click">
              <td><Band band={f.band} qmp={f.qmp} /></td>
              <td><b>{f.algorithm}</b> <span className="dim">{pretty(f.operation)}</span></td>
              <td>{f.service}</td>
              <td><code>{where(f.file, f.line_start)}</code></td>
              <td>{f.confidence_level}</td>
              <td>{f.hndl && <Badge tone="hndl">HNDL {f.hndl_severity}</Badge>}</td>
            </tr>))}</tbody>
        </table>
      </section>

      <section className="panel">
        <h3>Services and migration status</h3>
        <table className="tbl">
          <thead><tr><th>Service</th><th>Data</th><th>Exposure</th><th>Quantum-vulnerable</th><th>Critical</th><th>Status</th></tr></thead>
          <tbody>{s.services.map((v) => (
            <tr key={v.service}>
              <td><b>{v.service}</b>{v.metadata_missing && <> <Badge tone="warn">metadata missing</Badge></>}</td>
              <td>{v.data_classification ?? "?"}{v.data_lifetime_years != null && <span className="dim"> · {v.data_lifetime_years}y</span>}</td>
              <td>{v.internet_exposed == null ? "?" : v.internet_exposed ? "internet-facing" : "internal"}</td>
              <td>{v.quantum_vulnerable}</td><td>{v.critical}</td>
              <td>{v.migration_status}</td>
            </tr>))}</tbody>
        </table>
      </section>

      <p className="fine">
        {t.comment_or_doc_mentions} comment/doc mentions and {t.test_path} test-path finding(s) are hidden by default (not deleted) ·{" "}
        {t.suppressed} suppressed. <a href="#/inventory">Open the full inventory →</a>
      </p>
      {s.dependency_graph?.available && (
        <p className="fine">Dependency graph: {s.dependency_graph.crypto_files} file(s) use cryptography and{" "}
          {s.dependency_graph.dependent_files} more import them.{" "}
          {s.dependency_graph.imports_available ? "" : "Import relationships are unavailable for this scan (re-scan to compute them). "}
          <a href="#/graph">Explore the blast radius →</a></p>)}
      <p className="fine">{s.qmp_label}</p>
    </div>
  );
}
