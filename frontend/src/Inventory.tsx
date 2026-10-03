import { useEffect, useMemo, useState } from "react";
import { api, type Card, type Facets } from "./api";
import { Band, Badge, pretty, where } from "./ui";

type F = { q: string; band: string; algorithm: string; primitive: string; service: string; confidence: string; vuln: string;
           comments: boolean; tests: boolean; suppressed: boolean; language: string };
const EMPTY: F = { q: "", band: "", algorithm: "", primitive: "", service: "", confidence: "", vuln: "", comments: false, tests: false, suppressed: false, language: "" };

export default function Inventory({ scanId }: { scanId: string }) {
  const [f, setF] = useState<F>(EMPTY);
  const [rows, setRows] = useState<Card[]>([]);
  const [facets, setFacets] = useState<Facets | null>(null);
  const [meta, setMeta] = useState({ count: 0, total: 0 });
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const qs = useMemo(() => {
    const p = new URLSearchParams();
    if (f.q) p.set("q", f.q); if (f.band) p.set("band", f.band); if (f.algorithm) p.set("algorithm", f.algorithm);
    if (f.primitive) p.set("primitive", f.primitive); if (f.service) p.set("service", f.service);
    if (f.confidence) p.set("confidence", f.confidence); if (f.language) p.set("language", f.language);
    if (f.vuln === "yes") p.set("vulnerable", "true"); if (f.vuln === "pqc") p.set("pqc", "true");
    if (f.comments) p.set("include_comments", "true"); if (f.tests) p.set("include_tests", "true"); if (f.suppressed) p.set("include_suppressed", "true");
    return p.toString();
  }, [f]);

  useEffect(() => {
    let live = true; setLoading(true);
    const t = setTimeout(() => {
      api.findings(scanId, qs).then((r) => { if (!live) return; setRows(r.findings); setFacets(r.facets); setMeta({ count: r.count, total: r.total_all }); setError(null); })
        .catch((e: Error) => live && setError(e.message)).finally(() => live && setLoading(false));
    }, 200);
    return () => { live = false; clearTimeout(t); };
  }, [scanId, qs]);

  const set = <K extends keyof F>(k: K, v: F[K]) => setF((o) => ({ ...o, [k]: v }));
  const sel = (k: "band" | "algorithm" | "primitive" | "service" | "confidence", label: string, opts: string[] | undefined) => (
    <label className="fld">{label}
      <select value={f[k]} onChange={(e) => set(k, e.target.value)}>
        <option value="">All</option>{(opts ?? []).map((o) => <option key={o}>{o}</option>)}
      </select></label>);

  return (
    <div>
      <div className="panel filters">
        <label className="fld grow">Search<input placeholder="file, algorithm, evidence, rule…" value={f.q} onChange={(e) => set("q", e.target.value)} /></label>
        {sel("band", "Priority", facets?.band)}
        {sel("algorithm", "Algorithm", facets?.algorithm)}
        {sel("primitive", "Primitive", facets?.primitive)}
        {sel("service", "Service", facets?.service)}
        {sel("confidence", "Confidence", facets?.confidence_level)}
        <label className="fld">Language
          <select value={f.language} onChange={(e) => set("language", e.target.value)}>
            <option value="">All</option><option value="python">Python</option><option value="java">Java</option><option value="js">JS/TS</option><option value="config">Config / TLS / certs</option>
          </select></label>
        <label className="fld">Quantum
          <select value={f.vuln} onChange={(e) => set("vuln", e.target.value)}>
            <option value="">All</option><option value="yes">Quantum-vulnerable only</option><option value="pqc">Already PQC</option>
          </select></label>
        <div className="checks">
          <label><input type="checkbox" checked={f.comments} onChange={(e) => set("comments", e.target.checked)} /> comment/doc mentions</label>
          <label><input type="checkbox" checked={f.tests} onChange={(e) => set("tests", e.target.checked)} /> test paths</label>
          <label><input type="checkbox" checked={f.suppressed} onChange={(e) => set("suppressed", e.target.checked)} /> suppressed</label>
        </div>
        <div className="row">
          <button className="btn" onClick={() => setF(EMPTY)}>Reset</button>
          <a className="btn" href={api.csvUrl(scanId, qs)}>Export CSV</a>
        </div>
      </div>
      <p className="fine">{loading ? "Loading…" : `${meta.count} of ${meta.total} findings shown`}. Every row traces to a file, line and evidence string.</p>
      {error && <p className="error" role="alert">{error}</p>}
      <table className="tbl inv">
        <thead><tr><th>Priority</th><th>Algorithm</th><th>Operation</th><th>Service</th><th>File</th><th>Confidence</th><th>Quantum</th><th /></tr></thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id} className={`click ${r.suppressed ? "muted" : ""}`} onClick={() => (location.hash = `#/finding/${r.id}`)}>
              <td><Band band={r.band} qmp={r.qmp} /></td>
              <td><b>{r.algorithm}</b></td><td>{pretty(r.operation)}</td><td>{r.service}</td>
              <td><code>{where(r.file, r.line_start)}</code></td>
              <td>{r.confidence_level}</td>
              <td>{r.already_pqc ? <Badge tone="pqc">post-quantum</Badge> : r.quantum_vulnerable ? <Badge tone="warn">vulnerable</Badge> : <span className="dim">no</span>}</td>
              <td>{r.hndl && <Badge tone="hndl">HNDL</Badge>} {r.test_path && <Badge tone="dim">test</Badge>} {r.comment_only && <Badge tone="dim">comment</Badge>} {r.suppressed && <Badge tone="dim">suppressed</Badge>}</td>
            </tr>))}
          {!loading && rows.length === 0 && <tr><td colSpan={8} className="dim">No findings match these filters.</td></tr>}
        </tbody>
      </table>
    </div>
  );
}
