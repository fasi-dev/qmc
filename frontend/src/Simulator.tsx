import { useEffect, useMemo, useState } from "react";
import { api, type GraphData, type GraphEdge, type GraphNode, type NodeType, type Simulation, type SimTrack } from "./api";
import { edgePath, layoutGraph } from "./graphLayout";
import { Badge, where } from "./ui";

const ALL_TYPES: Record<NodeType, boolean> = { service: true, file: true, finding: false, algorithm: true, library: true };

/** Static, evidence-only architecture view (current or proposed) rendered with the graph layout. */
export function MiniGraph({ nodes, edges, label }: { nodes: (GraphNode & { proposed?: boolean })[]; edges: GraphEdge[]; label: string }) {
  const layout = useMemo(() => layoutGraph({ version: 1, nodes, edges, limitations: [], stats: {} as GraphData["stats"] },
                                           { showFindings: false, types: ALL_TYPES, query: "" }), [nodes, edges]);
  const placed = new Map(layout.nodes.map((n) => [n.id, n] as const));
  if (!layout.nodes.length) return <p className="dim">Nothing to draw.</p>;
  return (
    <svg className="minigraph" viewBox={`0 0 ${layout.width} ${layout.height}`} role="img" aria-label={label}
         style={{ maxHeight: Math.min(480, layout.height) }}>
      {layout.edges.map((e) => {
        const s = placed.get(e.source), t = placed.get(e.target);
        return s && t ? <path key={e.id} d={edgePath(e, s, t)} className={`edge e-${e.type.split(" ")[0].toLowerCase()} ${e.confidence}`} /> : null;
      })}
      {layout.nodes.map((n) => {
        const proposed = (n as { proposed?: boolean }).proposed;
        const chars = Math.floor((n.w - 16) / 7);
        const text = n.label.length > chars ? "…" + n.label.slice(-(chars - 1)) : n.label;
        const role = (n as { role_in_change?: string }).role_in_change;
        return (
          <g key={n.id} transform={`translate(${n.x},${n.y})`} className={`node t-${n.type} ${proposed ? "proposed" : ""} ${role === "direct" ? "direct" : role === "indirect" ? "indirect" : ""}`}>
            <rect width={n.w} height={n.h} rx={6} /><text x={10} y={n.h / 2 + 4}>{text}</text><title>{n.label}</title>
          </g>);
      })}
    </svg>
  );
}

function Track({ t, onTarget, refs }: { t: SimTrack; onTarget: (id: string) => void; refs: Simulation["references"] }) {
  return (
    <section className="panel track" aria-labelledby={`tr-${t.id}`}>
      <header className="track-head">
        <h3 id={`tr-${t.id}`}>{t.title}</h3>
        <span className="dim">{t.findings.length} finding(s) · {t.affected.direct_files.length} file(s) to change ·{" "}
          {t.affected.indirect_files.length} dependent file(s)</span>
      </header>

      <div className="compare">
        <div>
          <p className="eyebrow">Current</p>
          <p><b>{Object.entries(t.current.algorithms).map(([k, v]) => `${k} ×${v}`).join(", ")}</b></p>
          <p className="fine">Operations: {Object.entries(t.current.operations).map(([k, v]) => `${k.replace(/_/g, " ")} ×${v}`).join(", ")}</p>
          <p className="fine">APIs: {t.current.apis.join(", ")}{t.current.libraries.length > 0 && ` · libraries: ${t.current.libraries.join(", ")}`}</p>
          {Object.entries(t.current.sizes).filter(([, v]) => Object.keys(v).length).map(([alg, v]) => (
            <table key={alg} className="tbl sizes"><caption>{alg} (classical encoding)</caption><tbody>
              {Object.entries(v).map(([k, val]) => <tr key={k}><td>{k}</td><td>{val} {/^\d/.test(val) ? "bytes" : ""}</td></tr>)}</tbody></table>))}
        </div>
        <div aria-hidden="true" className="arrow">→</div>
        <div>
          <p className="eyebrow">Proposed target</p>
          {t.target_options.length > 0 ? (
            <label className="fld">Target
              <select value={t.target?.id ?? ""} onChange={(e) => onTarget(e.target.value)}>
                {t.target_options.map((o) => <option key={o.id} value={o.id}>{o.name} ({o.standard})</option>)}
              </select>
            </label>) : <p className="callout" role="note">No target proposed: the cryptographic role must be decided first.</p>}
          {t.target && (
            <>
              <p className="fine">{t.target.note}</p>
              <table className="tbl sizes"><caption>{t.target.name} (published parameters)</caption><tbody>
                {Object.entries(t.target.sizes).map(([k, v]) => <tr key={k}><td>{k}</td><td>{v.toLocaleString()} bytes</td></tr>)}</tbody></table>
            </>)}
        </div>
      </div>

      <h4>Affected files and components</h4>
      <p className="fine">Components: {t.affected.components.join(", ")}{t.affected.hndl > 0 && <> · <Badge tone="hndl">{t.affected.hndl} HNDL</Badge></>}</p>
      <div className="grid2">
        <div>
          <p className="fine"><b>Change directly ({t.affected.direct_files.length})</b></p>
          <ul className="plain">{t.affected.direct_files.map((f) => (
            <li key={f}><a href={`#/graph/${encodeURIComponent(`file:${f}`)}`}>{f}</a></li>))}</ul>
        </div>
        <div>
          <p className="fine"><b>Re-test: depend on them ({t.affected.indirect_confirmed} confirmed, {t.affected.indirect_inferred} inferred)</b></p>
          {t.affected.indirect_files.length === 0 && <p className="dim">None found by static imports.</p>}
          <ul className="plain">{t.affected.indirect_files.map((x) => (
            <li key={x.node}><a href={`#/graph/${encodeURIComponent(x.node)}`}>{x.file}</a> <span className="dim">depth {x.depth}</span>{" "}
              {x.confidence === "inferred" && <Badge tone="warn">inferred</Badge>}
              <span className="fine"> via {x.path.map((p) => p.evidence[0] ? where(p.evidence[0].file, p.evidence[0].line) : p.from.slice(5)).join(" ← ")}</span></li>))}</ul>
        </div>
      </div>

      {t.integration_changes.length > 0 && (
        <>
          <h4>Potential integration changes</h4>
          <ol className="changes">{t.integration_changes.map((c) => (
            <li key={c.operation}><b>{c.change}</b> <span className="fine">{c.why}</span>
              <ul className="evidence">{c.call_sites.map((cs) => (
                <li key={`${cs.fid}`}><a href={`#/finding/${cs.fid}`}>{cs.fid}</a> <code className="loc">{where(cs.file, cs.line)}</code> <code>{cs.text}</code></li>))}</ul>
            </li>))}</ol>
        </>)}

      {t.rules.length > 0 && (
        <>
          <h4>Migration rules</h4>
          <ul className="plain">{t.rules.map((r) => (
            <li key={r.rule_id}><code>{r.rule_id}</code> {r.name}: {r.direction ?? "no PQC mapping"} ({r.findings} finding(s))
              {r.steps.length > 0 && <ol className="fine">{r.steps.map((s) => <li key={s}>{s}</li>)}</ol>}</li>))}</ul>
        </>)}

      <h4>Compatibility considerations</h4>
      <ul>{t.compatibility.map((c) => <li key={c}>{c}</li>)}</ul>
      {t.libraries.length > 0 && (
        <ul className="plain fine">{t.libraries.map((l) => (
          <li key={l.library}><b>{l.library}</b>: {l.pqc_support ?? "PQC support not verified by QMC; a different provider may be needed."}</li>))}</ul>)}

      <h4>Architecture: current vs proposed</h4>
      <div className="grid2 arch">
        <figure><figcaption>Current (scanner evidence)</figcaption>
          <MiniGraph nodes={t.architecture.current.nodes} edges={t.architecture.current.edges} label={`Current architecture for ${t.title}`} /></figure>
        <figure><figcaption>Proposed (planning only, dashed = not implemented)</figcaption>
          <MiniGraph nodes={t.architecture.proposed.nodes} edges={t.architecture.proposed.edges} label={`Proposed architecture for ${t.title}`} /></figure>
      </div>
      <p className="fine">{t.architecture.note}</p>

      <div className="callout" role="note"><b>Unresolved dependencies and limitations</b>
        <ul>{t.limitations.map((l) => <li key={l}>{l}</li>)}</ul></div>
      {t.references.length > 0 && (
        <p className="fine refs">References: {t.references.filter((r) => refs[r]).map((r, i) => (
          <span key={r}>{i > 0 && " · "}<a href={refs[r].url} target="_blank" rel="noreferrer noopener">{refs[r].title.split(":")[0]}</a></span>))}</p>)}
    </section>
  );
}

export default function Simulator({ scanId, initialNode, initialTarget }: { scanId: string; initialNode?: string; initialTarget?: string }) {
  const [graph, setGraph] = useState<GraphData | null>(null);
  const [node, setNode] = useState<string>(initialNode ?? "");
  const [target, setTarget] = useState<string | null>(initialTarget ?? null);
  const [sim, setSim] = useState<Simulation | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => { api.graph(scanId).then(setGraph).catch((e: Error) => setError(e.message)); }, [scanId]);
  const options = useMemo(() => {
    const n = graph?.nodes ?? [];
    const rank = (x: GraphNode) => (x.quantum_vulnerable ? 0 : 1);
    return {
      algorithms: n.filter((x) => x.type === "algorithm" && (x.finding_count ?? 0) > 0).sort((a, b) => rank(a) - rank(b) || (a.label < b.label ? -1 : 1)),
      libraries: n.filter((x) => x.type === "library" && (x.finding_count ?? 0) > 0).sort((a, b) => (a.label < b.label ? -1 : 1)),
    };
  }, [graph]);
  useEffect(() => {                                   // default selection: the first quantum-vulnerable algorithm
    if (!node && options.algorithms.length) setNode(options.algorithms[0].id);
  }, [node, options]);

  useEffect(() => {
    if (!node) return;
    let live = true;
    setLoading(true); setError(null);
    api.simulate(scanId, node, target).then((s) => { if (live) setSim(s); })
      .catch((e: Error) => { if (live) { setSim(null); setError(e.message); } })
      .finally(() => { if (live) setLoading(false); });
    try { history.replaceState(null, "", `#/simulate/${encodeURIComponent(node)}${target ? `/${encodeURIComponent(target)}` : ""}`); } catch { /* ignore */ }
    return () => { live = false; };
  }, [scanId, node, target]);

  const known = graph && node ? graph.nodes.find((n) => n.id === node) : null;
  return (
    <div className="simulator">
      <div className="callout" role="note"><b>Planning simulation.</b> QMC does not change code and does not confirm compatibility. Whether a
        replacement works depends on protocols, libraries and versions, key formats, message-size budgets and every peer that must interoperate.</div>
      <div className="panel filters" role="group" aria-label="Simulation input">
        <label className="fld grow">Cryptography to migrate
          <select value={node} onChange={(e) => { setTarget(null); setNode(e.target.value); }}>
            {node && !known && <option value={node}>{node}</option>}
            <optgroup label="Algorithms">{options.algorithms.map((n) => (
              <option key={n.id} value={n.id}>{n.label}{n.quantum_vulnerable ? " (quantum-vulnerable)" : ""} · {n.finding_count} finding(s)</option>))}</optgroup>
            <optgroup label="Libraries">{options.libraries.map((n) => <option key={n.id} value={n.id}>{n.label} · {n.finding_count} finding(s)</option>)}</optgroup>
          </select>
        </label>
        <a className="btn" href={`#/graph/${encodeURIComponent(node)}`}>Open in dependency graph</a>
      </div>
      {error && <p className="error" role="alert">{error}</p>}
      {loading && <p className="dim" role="status">Simulating…</p>}
      {sim && !loading && (
        <>
          <div className="kpis">
            <div className="kpi"><div className="kpi-v">{sim.summary.findings_in_scope}</div><div className="kpi-l">findings in scope</div></div>
            <div className="kpi"><div className="kpi-v">{sim.summary.direct_files}</div><div className="kpi-l">files to change</div></div>
            <div className="kpi"><div className="kpi-v">{sim.summary.indirect_files}</div><div className="kpi-l">dependent files to re-test</div></div>
            <div className="kpi"><div className="kpi-v">{sim.summary.components}</div><div className="kpi-l">components</div></div>
            <div className="kpi"><div className="kpi-v">{sim.summary.no_migration_needed}</div><div className="kpi-l">need no migration</div></div>
          </div>
          {sim.tracks.length === 0 && (
            <div className="panel empty-state"><h3>No migration needed for this selection</h3>
              <p className="dim">Its findings are already post-quantum or not quantum-vulnerable.</p></div>)}
          {sim.tracks.map((t) => <Track key={t.id} t={t} refs={sim.references} onTarget={(id) => setTarget(id)} />)}
          {sim.no_migration_needed.length > 0 && (
            <section className="panel"><h3>In scope, no migration needed ({sim.no_migration_needed.length})</h3>
              <ul className="plain">{sim.no_migration_needed.map((x) => (
                <li key={x.fid}><a href={`#/finding/${x.fid}`}>{x.fid}</a> {x.algorithm} <code>{where(x.file, x.line)}</code> <span className="dim">{x.reason}</span></li>))}</ul>
            </section>)}
          <details className="panel"><summary>Crypto-agility practices</summary><ul>{sim.crypto_agility.map((c) => <li key={c}>{c}</li>)}</ul></details>
          <p className="fine">{sim.statement}</p>
        </>)}
      {!node && graph && options.algorithms.length === 0 && (
        <div className="panel empty-state"><h3>Nothing to simulate</h3><p className="dim">This scan has no cryptographic findings to migrate.</p></div>)}
    </div>
  );
}
