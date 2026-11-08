import { useEffect, useState } from "react";
import { api, type Readiness as R, type ReadinessEvidence, type ReadinessStatus } from "./api";
import { Band, Badge, where } from "./ui";

const STATUS_LABEL: Record<ReadinessStatus, string> = {
  blocker: "Blocker", action: "Action needed", review: "Review", positive: "PQC in use", partial: "Partial",
  not_detected: "Not detected", info: "Observation",
};
const LEVEL_TONE: Record<string, string> = {
  not_ready_blockers: "critical", not_ready: "high", in_transition: "review", no_vulnerable_usage_detected: "info",
};
const simLink = (node: string) => `#/simulate/${encodeURIComponent(node)}`;

export function EvidenceRows({ items, max = 8 }: { items: ReadinessEvidence[]; max?: number }) {
  const [all, setAll] = useState(false);
  if (!items.length) return null;
  const shown = all ? items : items.slice(0, max);
  return (
    <>
      <ul className="evidence">
        {shown.map((e) => (
          <li key={`${e.fid}-${e.line}`}>
            <a href={`#/finding/${e.fid}`}>{e.fid}</a> <code className="loc">{where(e.file, e.line)}</code> <code>{e.text}</code>
            {e.band && <> <Band band={e.band} /></>}
          </li>))}
      </ul>
      {items.length > max && (
        <button className="linklike fine" onClick={() => setAll((a) => !a)}>{all ? "Show fewer" : `Show all ${items.length}`}</button>)}
    </>
  );
}

function Refs({ ids, refs }: { ids: string[]; refs: R["references"] }) {
  if (!ids.length) return null;
  return (
    <p className="fine refs">References:{" "}
      {ids.filter((i) => refs[i]).map((i, k) => (
        <span key={i}>{k > 0 && " · "}<a href={refs[i].url} target="_blank" rel="noreferrer noopener">{refs[i].title.split(":")[0]}</a></span>))}
    </p>
  );
}

export default function Readiness({ scanId }: { scanId: string }) {
  const [a, setA] = useState<R | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    setA(null); setError(null);
    api.readiness(scanId).then((r) => live && setA(r)).catch((e: Error) => live && setError(e.message));
    return () => { live = false; };
  }, [scanId]);

  if (error) return <div className="panel"><p className="error" role="alert">Could not load the readiness assessment: {error}</p></div>;
  if (!a) return <p className="dim" role="status">Assessing PQC readiness…</p>;
  const c = a.counts;

  return (
    <div className="readiness">
      <section className={`panel level level-${LEVEL_TONE[a.level.id] ?? "info"}`} aria-labelledby="lvl-h">
        <p className="eyebrow">Overall readiness</p>
        <h3 id="lvl-h">{a.level.label}</h3>
        <p>{a.level.rule}</p>
        <p className="fine">{a.statement}</p>
        <div className="row">
          <span className="pill"><b>{a.blockers.length}</b> blocker(s)</span>
          <span className="pill"><b>{c.quantum_vulnerable}</b> quantum-vulnerable usage(s) in <b>{c.vulnerable_files}</b> file(s)</span>
          <span className="pill"><b>{c.hndl_elevated}</b> elevated HNDL</span>
          <span className="pill"><b>{c.pqc_outside_tests}</b> PQC usage(s) in production paths</span>
        </div>
        <details className="fine"><summary>How the level is decided</summary>
          <ol>{a.level_rules.map((r) => <li key={r.id}><b className={r.id === a.level.id ? "current" : ""}>{r.label}</b>: {r.rule}</li>)}</ol>
          <p>The rules are applied in this order; the first one that matches is the result. There is no percentage score.</p>
        </details>
      </section>

      {a.blockers.length > 0 && (
        <section className="panel" aria-labelledby="blk-h">
          <h3 id="blk-h">Critical blockers</h3>
          {a.blockers.map((b) => (
            <article key={b.id} className="blocker">
              <h4>{b.title} <span className="dim">· {b.services.join(", ")}</span></h4>
              <p>{b.why}</p>
              <EvidenceRows items={b.evidence} />
              <Refs ids={b.references} refs={a.references} />
            </article>))}
        </section>)}

      <section className="panel" aria-labelledby="rec-h">
        <h3 id="rec-h">Prioritized recommendations</h3>
        {a.recommendations.length === 0 && <p className="dim">No recommendations: nothing in the analyzed files needs migration.</p>}
        <ol className="recs">{a.recommendations.map((r, i) => (
          <li key={i}>
            <div className="rec-head"><span className={`prio p${r.priority}`}>P{r.priority}</span> <b>{r.title}</b>
              {r.simulate && <a className="btn small" href={simLink(r.simulate)}>Simulate migration</a>}</div>
            <p>{r.action}</p>
            {r.hubs && r.hubs.length > 0 && (
              <ul className="plain fine">{r.hubs.map((h) => <li key={h.file}><code>{h.file}</code> imported by {h.imported_by.length} file(s)</li>)}</ul>)}
            {r.libraries && <p className="fine">Libraries: {r.libraries.join(", ")}</p>}
            <EvidenceRows items={r.evidence} max={4} />
            {r.evidence_total > r.evidence.length && <p className="fine">{r.evidence_total - r.evidence.length} more usage(s) not listed.</p>}
            <Refs ids={r.references} refs={a.references} />
          </li>))}
        </ol>
      </section>

      <section className="panel" aria-labelledby="cat-h">
        <h3 id="cat-h">Category breakdown</h3>
        <div className="cats">{a.categories.map((cat) => (
          <article key={cat.id} className={`cat st-${cat.status}`}>
            <header><h4>{cat.title}</h4><span className={`status s-${cat.status}`}>{STATUS_LABEL[cat.status]}</span></header>
            <p>{cat.summary}</p>
            {cat.note && <p className="fine">{cat.note}</p>}
            {cat.count > 0 && cat.id !== "agility" && (
              <p className="fine">{cat.count} usage(s) · {cat.files} file(s) · {cat.services.join(", ")} ·{" "}
                {Object.entries(cat.algorithms).map(([k, v]) => `${k} ${v}`).join(", ")}</p>)}
            {cat.hubs && cat.hubs.length > 0 && (
              <ul className="plain fine">{cat.hubs.map((h) => (
                <li key={h.file}><a href={`#/graph/${encodeURIComponent(`file:${h.file}`)}`}>{h.file}</a> ← {h.imported_by.join(", ")}</li>))}</ul>)}
            {cat.evidence.length > 0 && (
              <details><summary>Evidence ({cat.evidence.length})</summary><EvidenceRows items={cat.evidence} /></details>)}
          </article>))}
        </div>
      </section>

      <section className="panel" aria-labelledby="lib-h">
        <h3 id="lib-h">Cryptographic libraries</h3>
        <table className="tbl">
          <thead><tr><th>Library</th><th>Findings</th><th>Quantum-vulnerable</th><th>PQC support known to QMC</th></tr></thead>
          <tbody>{a.libraries.map((l) => (
            <tr key={l.library}><td><b>{l.library}</b></td><td>{l.findings}</td><td>{l.vulnerable_findings}</td>
              <td>{l.pqc_support ?? <span className="dim">Not verified by QMC: check the project's documentation.</span>}
                {l.references.length > 0 && <Refs ids={l.references} refs={a.references} />}</td></tr>))}</tbody>
        </table>
        <p className="fine">Installed versions are not determined (dependency manifests are not analyzed): verify the version you deploy.</p>
      </section>

      <div className="grid2">
        <section className="panel" aria-labelledby="an-h">
          <h3 id="an-h">What was analyzed</h3>
          <ul className="plain">
            <li>Files scanned: {Object.entries(a.analyzed.files_scanned).map(([k, v]) => `${k} ${v}`).join(", ") || "none"}</li>
            <li>Scan status: {a.analyzed.scan_status ?? "unknown"} · engine {a.analyzed.engine_version ?? "?"}</li>
            <li>Skipped files: {a.analyzed.skipped_files}{a.analyzed.skipped_files > 0 &&
              ` (${Object.entries(a.analyzed.skipped_by_reason).map(([k, v]) => `${k} ${v}`).join(", ")})`}</li>
            <li>Import relationships: {a.analyzed.import_relationships ? "available" : "not available (re-scan)"}</li>
            <li>Services with complete metadata: {a.analyzed.services_with_metadata.join(", ") || "none"}</li>
            {Object.entries(a.analyzed.excluded).filter(([, v]) => v).map(([k, v]) => <li key={k}>Excluded ({k.replace("_", " ")}): {v}</li>)}
          </ul>
          {a.limitations.length > 0 && <><h4>Limitations</h4><ul>{a.limitations.map((l) => <li key={l}>{l}</li>)}</ul></>}
        </section>
        <section className="panel" aria-labelledby="na-h">
          <h3 id="na-h">Not analyzed</h3>
          <ul>{a.not_analyzed.map((x) => <li key={x}>{x}</li>)}</ul>
          <p className="fine"><Badge tone="warn">important</Badge> No finding here does not mean the application is quantum-safe.</p>
        </section>
      </div>
    </div>
  );
}
