import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { KeyboardEvent, PointerEvent as ReactPointerEvent } from "react";
import { api, type BlastRadius, type Evidence, type GraphData, type GraphNode, type NodeType } from "./api";
import { edgePath, fitTransform, layoutGraph, matches, type PlacedNode } from "./graphLayout";
import { Band, Badge, Kpi, where } from "./ui";

const TYPE_LABEL: Record<NodeType, string> = {
  service: "Service", file: "File", finding: "Finding", algorithm: "Algorithm", library: "Library",
};
const SELECTABLE: NodeType[] = ["algorithm", "library", "finding", "file"];
const MIN_K = 0.1, MAX_K = 2.5;
const LARGE = 600;
/** Above this many nodes only what intersects the viewport (plus a margin) is rendered. */
const CULL_ABOVE = 300;
const CULL_MARGIN = 200;

type View = { x: number; y: number; k: number };

function nodeSubtitle(n: GraphNode): string {
  if (n.type === "file") return `${n.finding_count ? `${n.finding_count} finding(s)` : "imports affected code"}${n.service ? ` · ${n.service}` : ""}`;
  if (n.type === "finding") return `${n.file}:${n.line}`;
  if (n.type === "algorithm") return `${n.finding_count} finding(s)${n.quantum_vulnerable ? " · quantum-vulnerable" : ""}`;
  if (n.type === "library") return `${n.finding_count} finding(s) · imported by ${n.importing_files} file(s)`;
  return n.metadata_file ? `from ${n.metadata_file}` : "repository default";
}

function EvidenceList({ items }: { items: Evidence[] }) {
  if (!items.length) return null;
  return (
    <ul className="evidence">
      {items.map((e, i) => (
        <li key={`${e.file}:${e.line}:${i}`}><code className="loc">{where(e.file, e.line)}</code> <code>{e.text}</code></li>
      ))}
    </ul>
  );
}

export default function DependencyGraph({ scanId, initialNode }: { scanId: string; initialNode?: string }) {
  const [data, setData] = useState<GraphData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showFindings, setShowFindings] = useState(false);
  const [types, setTypes] = useState<Record<NodeType, boolean>>({ service: true, file: true, finding: true, algorithm: true, library: true });
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<string | null>(initialNode ?? null);
  const [br, setBr] = useState<BlastRadius | null>(null);
  const [brError, setBrError] = useState<string | null>(null);
  const [brLoading, setBrLoading] = useState(false);
  const [focusOnly, setFocusOnly] = useState(false);
  const [view, setView] = useState<View>({ x: 0, y: 0, k: 1 });
  const [size, setSize] = useState({ w: 1000, h: 620 });
  const [focusId, setFocusId] = useState<string | null>(initialNode ?? null);
  const box = useRef<HTMLDivElement>(null);
  const drag = useRef<{ x: number; y: number; vx: number; vy: number } | null>(null);

  useEffect(() => {
    let live = true;
    setData(null); setError(null);
    api.graph(scanId).then((d) => { if (live) setData(d); }).catch((e: Error) => { if (live) setError(e.message); });
    return () => { live = false; };
  }, [scanId]);

  const byId = useMemo(() => new Map((data?.nodes ?? []).map((n) => [n.id, n] as const)), [data]);
  const selNode = selected ? byId.get(selected) ?? null : null;

  // Blast radius for the selected node (algorithms, libraries, findings, files).
  useEffect(() => {
    setBr(null); setBrError(null);
    if (!selNode || !SELECTABLE.includes(selNode.type)) { setFocusOnly(false); return; }
    let live = true;
    setBrLoading(true);
    api.blastRadius(scanId, selNode.id)
      .then((r) => { if (live) setBr(r); })
      .catch((e: Error) => { if (live) setBrError(e.message); })
      .finally(() => { if (live) setBrLoading(false); });
    return () => { live = false; };
  }, [scanId, selNode]);

  const impact = useMemo(() => {
    const direct = new Set<string>(), confirmed = new Set<string>(), inferred = new Set<string>(), related = new Set<string>();
    if (!br || !data) return { direct, confirmed, inferred, related };
    br.direct.forEach((d) => direct.add(d.node));
    br.indirect.forEach((d) => (d.confidence === "confirmed" ? confirmed : inferred).add(d.node));
    related.add(br.node.id);
    br.findings.forEach((f) => related.add(f.id));
    for (const e of data.edges) {                                 // algorithms/libraries/services touched by the impact
      if (related.has(e.source) && e.type === "USES") related.add(e.target);
      if (e.type === "CONTAINS" && e.source.startsWith("service:") && (direct.has(e.target) || confirmed.has(e.target) || inferred.has(e.target))) related.add(e.source);
    }
    return { direct, confirmed, inferred, related };
  }, [br, data]);

  const focus = useMemo(() => {
    if (!focusOnly || !br) return null;
    return new Set([...impact.direct, ...impact.confirmed, ...impact.inferred, ...impact.related]);
  }, [focusOnly, br, impact]);

  const layout = useMemo(() => (data ? layoutGraph(data, { showFindings, types, query, focus }) : null), [data, showFindings, types, query, focus]);
  const placed = useMemo(() => new Map((layout?.nodes ?? []).map((n) => [n.id, n] as const)), [layout]);

  // Track the canvas size (for fit, culling and keeping the focused node in view).
  useEffect(() => {
    const measure = () => { const el = box.current; if (el && el.clientWidth) setSize({ w: el.clientWidth, h: el.clientHeight }); };
    measure();
    window.addEventListener("resize", measure);
    return () => window.removeEventListener("resize", measure);
  }, [data]);

  // Viewport culling for large graphs: render only nodes/edges that intersect the visible area.
  const culled = useMemo(() => {
    if (!layout) return { nodes: [] as PlacedNode[], edges: [] as NonNullable<typeof layout>["edges"] };
    if (layout.nodes.length <= CULL_ABOVE) return { nodes: layout.nodes, edges: layout.edges };
    const x0 = -view.x / view.k - CULL_MARGIN, y0 = -view.y / view.k - CULL_MARGIN;
    const x1 = x0 + size.w / view.k + 2 * CULL_MARGIN, y1 = y0 + size.h / view.k + 2 * CULL_MARGIN;
    const inView = (n: PlacedNode) => n.x + n.w >= x0 && n.x <= x1 && n.y + n.h >= y0 && n.y <= y1;
    const nodes = layout.nodes.filter((n) => inView(n) || n.id === selected || n.id === focusId);
    const keep = new Set(nodes.map((n) => n.id));
    const edges = layout.edges.filter((e) => {
      if (keep.has(e.source) || keep.has(e.target)) return true;
      const s = placed.get(e.source), t = placed.get(e.target);   // long edge crossing the view
      return !!s && !!t && Math.max(s.y, t.y) >= y0 && Math.min(s.y, t.y) <= y1 && Math.max(s.x, t.x) >= x0 && Math.min(s.x, t.x) <= x1;
    });
    return { nodes, edges };
  }, [layout, view, size, selected, focusId, placed]);

  // Roving tabindex: exactly one node is in the Tab order; arrow keys move between nodes.
  const columns = useMemo(() => {
    const cols = new Map<number, PlacedNode[]>();
    for (const n of layout?.nodes ?? []) cols.set(n.col, [...(cols.get(n.col) ?? []), n]);
    for (const c of cols.values()) c.sort((a, b) => a.y - b.y);
    return cols;
  }, [layout]);
  const neighbours = useMemo(() => {
    const m = new Map<string, Set<string>>();
    for (const e of layout?.edges ?? []) {
      m.set(e.source, (m.get(e.source) ?? new Set()).add(e.target));
      m.set(e.target, (m.get(e.target) ?? new Set()).add(e.source));
    }
    return m;
  }, [layout]);
  const tabStop = focusId && placed.has(focusId) ? focusId
    : selected && placed.has(selected) ? selected
    : (layout?.nodes.find((n) => n.type === "algorithm") ?? layout?.nodes[0])?.id ?? null;

  const viewport = () => ({ w: box.current?.clientWidth || 1000, h: box.current?.clientHeight || 620 });
  const fit = useCallback(() => {
    if (!layout) return;
    const { w, h } = viewport();
    setView(fitTransform(layout, w, h, MIN_K, 1.2));
  }, [layout]);
  // Re-fit when the set of shown nodes changes (not on every search keystroke: search only highlights).
  useEffect(() => { fit(); }, [data, showFindings, types, focus]);   // eslint-disable-line react-hooks/exhaustive-deps

  const zoomAt = (factor: number, cx?: number, cy?: number) => setView((v) => {
    const { w, h } = viewport();
    const px = cx ?? w / 2, py = cy ?? h / 2;
    const k = Math.min(MAX_K, Math.max(MIN_K, v.k * factor));
    return { k, x: px - ((px - v.x) * k) / v.k, y: py - ((py - v.y) * k) / v.k };
  });

  // Wheel zoom needs a non-passive listener to prevent page scrolling.
  useEffect(() => {
    const el = box.current;
    if (!el) return;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const r = el.getBoundingClientRect();
      zoomAt(e.deltaY < 0 ? 1.15 : 1 / 1.15, e.clientX - r.left, e.clientY - r.top);
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  }, [data]);                                   // the canvas exists only once the graph has loaded

  const onPointerDown = (e: ReactPointerEvent<HTMLDivElement>) => {
    if ((e.target as Element).closest("[data-node]")) return;      // clicks on nodes select, they do not pan
    drag.current = { x: e.clientX, y: e.clientY, vx: view.x, vy: view.y };
    (e.currentTarget as HTMLElement).setPointerCapture?.(e.pointerId);
  };
  const onPointerMove = (e: ReactPointerEvent<HTMLDivElement>) => {
    const d = drag.current;
    if (d) setView((v) => ({ ...v, x: d.vx + e.clientX - d.x, y: d.vy + e.clientY - d.y }));
  };
  const onPointerUp = () => { drag.current = null; };
  const onCanvasKey = (e: KeyboardEvent<HTMLDivElement>) => {
    if ((e.target as Element).closest("[data-node]")) return;
    const step = 60;
    const moves: Record<string, () => void> = {
      "+": () => zoomAt(1.2), "=": () => zoomAt(1.2), "-": () => zoomAt(1 / 1.2), "0": fit,
      ArrowLeft: () => setView((v) => ({ ...v, x: v.x + step })), ArrowRight: () => setView((v) => ({ ...v, x: v.x - step })),
      ArrowUp: () => setView((v) => ({ ...v, y: v.y + step })), ArrowDown: () => setView((v) => ({ ...v, y: v.y - step })),
    };
    if (moves[e.key]) { e.preventDefault(); moves[e.key](); }
  };

  const moveFocus = (id: string) => {
    setFocusId(id);
    const n = placed.get(id);
    if (n) setView((v) => {                                     // keep the focused node on screen
      const sx = n.x * v.k + v.x, sy = n.y * v.k + v.y;
      if (sx >= 0 && sy >= 0 && sx + n.w * v.k <= size.w && sy + n.h * v.k <= size.h) return v;
      return { ...v, x: size.w / 2 - (n.x + n.w / 2) * v.k, y: size.h / 2 - (n.y + n.h / 2) * v.k };
    });
    requestAnimationFrame(() => {
      const el = [...(box.current?.querySelectorAll("[data-node]") ?? [])].find((x) => x.getAttribute("data-node") === id);
      (el as SVGGElement | undefined)?.focus();
    });
  };
  const step = (from: string, key: string): string | null => {
    const n = placed.get(from);
    if (!n) return null;
    const col = columns.get(n.col) ?? [];
    const i = col.findIndex((x) => x.id === from);
    if (key === "ArrowDown") return col[i + 1]?.id ?? null;
    if (key === "ArrowUp") return col[i - 1]?.id ?? null;
    if (key === "Home") return col[0]?.id ?? null;
    if (key === "End") return col[col.length - 1]?.id ?? null;
    if (key === "ArrowRight" || key === "ArrowLeft") {
      const dir = key === "ArrowRight" ? 1 : -1;
      const order = [...columns.keys()].sort((a, b) => a - b);
      const next = order[order.indexOf(n.col) + dir];
      if (next === undefined) return null;
      const cands = columns.get(next) ?? [];
      const linked = cands.filter((c) => neighbours.get(from)?.has(c.id));   // prefer a connected node
      const pool = linked.length ? linked : cands;
      return pool.reduce((best, c) => (Math.abs(c.y - n.y) < Math.abs(best.y - n.y) ? c : best), pool[0])?.id ?? null;
    }
    return null;
  };

  const select = (id: string) => {
    setSelected(id); setFocusOnly(false);
    try { history.replaceState(null, "", `#/graph/${encodeURIComponent(id)}`); } catch { /* sandboxed: link sharing only */ }
  };
  const nodeKey = (id: string) => (e: KeyboardEvent<SVGGElement>) => {
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setFocusId(id); select(id); return; }
    const next = step(id, e.key);
    if (["ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight", "Home", "End"].includes(e.key)) {
      e.preventDefault();
      e.stopPropagation();
      if (next) moveFocus(next);
    }
  };

  const results = useMemo(() => (data && query.trim() ? data.nodes.filter((n) => matches(n, query)).slice(0, 50) : []), [data, query]);

  if (error) return <div className="panel"><p className="error" role="alert">Could not load the dependency graph: {error}</p></div>;
  if (!data || !layout) return <p className="dim" role="status">Building the dependency graph…</p>;
  if (data.nodes.length === 0) {
    return (
      <div className="panel empty-state">
        <h3>No cryptographic dependencies found</h3>
        <p className="dim">The scan found no executable cryptographic usage, so there is nothing to map. Comment and documentation mentions are not graph evidence.</p>
        {data.limitations.length > 0 && <ul className="fine">{data.limitations.map((l) => <li key={l}>{l}</li>)}</ul>}
      </div>);
  }

  const st = data.stats;
  const stateOf = (n: PlacedNode) =>
    !br ? "" : impact.direct.has(n.id) ? "direct" : impact.confirmed.has(n.id) ? "indirect" : impact.inferred.has(n.id) ? "inferred"
      : impact.related.has(n.id) ? "related" : "dim";

  return (
    <div className="graph-page">
      <div className="kpis">
        <Kpi value={st.crypto_files} label="files using crypto" hint="Files with a detection or an import of a cryptographic library" />
        <Kpi value={st.dependent_files} label="dependent files" hint="Files that import crypto-using files (transitively)" />
        <Kpi value={st.by_type.algorithm} label="algorithms" />
        <Kpi value={st.by_type.library} label="libraries" />
        <Kpi value={st.import_edges} label="internal imports" hint="Repository-internal import relationships on paths to crypto code" />
        <Kpi value={st.inferred_edges} label="inferred edges" tone={st.inferred_edges ? "var(--band-review)" : undefined}
             hint="Ambiguous or wildcard imports: plausible, not proven" />
      </div>

      {!st.imports_available && (
        <div className="callout warn" role="alert"><b>Direct usage only.</b> {data.limitations[0]}</div>)}

      <div className="panel filters graph-tools" role="toolbar" aria-label="Graph controls">
        <label className="fld grow">Search nodes
          <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="file, algorithm, library, finding id…" />
        </label>
        <fieldset className="types">
          <legend>Show</legend>
          {(Object.keys(TYPE_LABEL) as NodeType[]).filter((t) => t !== "finding").map((t) => (
            <label key={t}><input type="checkbox" checked={types[t]} onChange={(e) => setTypes((o) => ({ ...o, [t]: e.target.checked }))} /> {TYPE_LABEL[t]}s</label>
          ))}
          <label><input type="checkbox" checked={showFindings} onChange={(e) => setShowFindings(e.target.checked)} /> Individual findings</label>
        </fieldset>
        <div className="row">
          <button className="btn" onClick={() => zoomAt(1.2)} aria-label="Zoom in">+</button>
          <button className="btn" onClick={() => zoomAt(1 / 1.2)} aria-label="Zoom out">−</button>
          <button className="btn" onClick={fit}>Fit to screen</button>
          <button className="btn" disabled={!br} aria-pressed={focusOnly} onClick={() => setFocusOnly((f) => !f)}>
            {focusOnly ? "Show whole graph" : "Show only blast radius"}</button>
        </div>
      </div>

      {results.length > 0 && (
        <div className="panel search-results">
          <h3>{results.length === 50 ? "First 50 matches" : `${results.length} match(es)`}</h3>
          <ul>{results.map((n) => (
            <li key={n.id}><button className="linklike" onClick={() => select(n.id)}>
              <span className={`tchip t-${n.type}`}>{TYPE_LABEL[n.type]}</span> {n.label}</button></li>))}</ul>
        </div>)}
      {layout.nodes.length > LARGE && !focus && !query && (
        <p className="fine" role="note">Large graph ({layout.nodes.length} nodes). Search, hide node types, or select a node and use
          “Show only blast radius” to focus.</p>)}

      <div className="graph-wrap">
        <div ref={box} className="graph-canvas" tabIndex={0} role="application"
             aria-label="Cryptographic dependency graph. Tab focuses a node; arrow keys move between nodes (left/right follows connections), Enter selects. On the background, arrow keys pan, plus and minus zoom, 0 fits."
             onPointerDown={onPointerDown} onPointerMove={onPointerMove} onPointerUp={onPointerUp} onPointerLeave={onPointerUp}
             onKeyDown={onCanvasKey}>
          <svg width="100%" height="100%" className={br ? "has-selection" : ""}>
            <defs>
              <marker id="qmc-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 0 L 10 5 L 0 10 z" className="arrowhead" />
              </marker>
            </defs>
            <g transform={`translate(${view.x},${view.y}) scale(${view.k})`}>
              {culled.edges.map((e) => {
                const s = placed.get(e.source), t = placed.get(e.target);
                if (!s || !t) return null;
                const hot = br && (impact.direct.has(e.source) || impact.confirmed.has(e.source) || impact.inferred.has(e.source)
                  || impact.related.has(e.source)) && (impact.direct.has(e.target) || impact.confirmed.has(e.target)
                  || impact.inferred.has(e.target) || impact.related.has(e.target));
                return <path key={e.id} d={edgePath(e, s, t)} data-edge={e.id}
                             className={`edge e-${e.type.split(" ")[0].toLowerCase()} ${e.confidence} ${hot ? "hot" : ""}`}
                             markerEnd={e.arc ? "url(#qmc-arrow)" : undefined}><title>{`${e.type} (${e.confidence})`}</title></path>;
              })}
              {culled.nodes.map((n) => {
                const chars = Math.floor((n.w - 16) / 7);
                const label = n.label.length > chars ? "…" + n.label.slice(-(chars - 1)) : n.label;
                const vuln = n.type === "algorithm" ? n.quantum_vulnerable : n.type === "finding" ? n.quantum_vulnerable : (n.vulnerable_count ?? 0) > 0;
                return (
                  <g key={n.id} data-node={n.id} transform={`translate(${n.x},${n.y})`} tabIndex={n.id === tabStop ? 0 : -1} role="button"
                     aria-label={`${TYPE_LABEL[n.type]} ${n.label}. ${nodeSubtitle(n)}`} aria-pressed={selected === n.id}
                     className={`node t-${n.type} ${stateOf(n)} ${selected === n.id ? "sel" : ""} ${n.match ? "match" : ""} ${vuln ? "vuln" : ""} ${n.type === "file" && !n.crypto ? "dependent" : ""}`}
                     onClick={() => { setFocusId(n.id); select(n.id); }} onKeyDown={nodeKey(n.id)} onFocus={() => setFocusId(n.id)}>
                    <rect width={n.w} height={n.h} rx={6} />
                    {(n.max_band || n.band) && <rect className="bandbar" width={4} height={n.h} rx={2}
                                                   style={{ fill: `var(--band-${(n.max_band || n.band || "").toLowerCase() === "informational" ? "info" : (n.max_band || n.band || "").toLowerCase()})` }} />}
                    <text x={10} y={n.h / 2 + 4}>{label}</text>
                    <title>{`${TYPE_LABEL[n.type]}: ${n.label}\n${nodeSubtitle(n)}`}</title>
                  </g>);
              })}
            </g>
          </svg>
          <ul className="legend graph-legend" aria-label="Legend">
            {(Object.keys(TYPE_LABEL) as NodeType[]).map((t) => <li key={t}><i className={`sw t-${t}`} />{TYPE_LABEL[t]}</li>)}
            <li><i className="ln confirmed" />confirmed</li><li><i className="ln inferred" />inferred</li>
            {br && <><li><i className="sw st-direct" />direct</li><li><i className="sw st-indirect" />indirect</li></>}
          </ul>
        </div>

        <aside className="panel graph-details" aria-live="polite" aria-label="Selected node details">
          {!selNode && (
            <div>
              <h3>Select a node</h3>
              <p className="dim">Choose an algorithm, library, finding or file to see which files use it directly, which files depend
                on them through imports, and the evidence for every relationship.</p>
              <ul className="fine">{data.limitations.map((l) => <li key={l}>{l}</li>)}</ul>
            </div>)}
          {selNode && <NodeDetails node={selNode} br={br} loading={brLoading} error={brError} onSelect={select} data={data} />}
        </aside>
      </div>
    </div>
  );
}

function NodeDetails({ node, br, loading, error, onSelect, data }: {
  node: GraphNode; br: BlastRadius | null; loading: boolean; error: string | null; onSelect: (id: string) => void; data: GraphData;
}) {
  const label = TYPE_LABEL[node.type];
  if (node.type === "service") {
    const files = data.edges.filter((e) => e.type === "CONTAINS" && e.source === node.id).map((e) => e.target);
    return (
      <div>
        <p className="eyebrow">{label}</p><h3>{node.label}</h3>
        <p className="fine">{node.metadata_file ? `Defined by ${node.metadata_file}` : "No service.yaml: repository default component"}</p>
        <p>{files.length} file(s) in the graph belong to this component. Select an algorithm, library, finding or file for a blast radius.</p>
        <ul className="plain">{files.map((f) => <li key={f}><button className="linklike" onClick={() => onSelect(f)}>{f.slice(5)}</button></li>)}</ul>
      </div>);
  }
  return (
    <div>
      <p className="eyebrow">{label}</p>
      <h3 className="breakall">{node.label}</h3>
      {node.type === "finding" && (
        <p><Band band={node.band ?? null} qmp={node.qmp} /> {node.hndl && <Badge tone="hndl">HNDL</Badge>}{" "}
          <a href={`#/finding/${node.fid}`}>Open finding detail →</a></p>)}
      {SELECTABLE.includes(node.type) && (
        <p><a className="btn small" href={`#/simulate/${encodeURIComponent(node.id)}`}>Simulate migration of this {label.toLowerCase()}</a></p>)}
      {node.type === "algorithm" && node.quantum_vulnerable && <p><Badge tone="warn">quantum-vulnerable</Badge></p>}
      <Relationships node={node} data={data} onSelect={onSelect} />
      {loading && <p className="dim" role="status">Computing blast radius…</p>}
      {error && <p className="error" role="alert">{error}</p>}
      {br && br.node.id === node.id && <BlastPanel br={br} onSelect={onSelect} />}
    </div>
  );
}

function BlastPanel({ br, onSelect }: { br: BlastRadius; onSelect: (id: string) => void }) {
  const s = br.summary;
  const total = Object.values(br.severity).reduce((a, b) => a + b, 0) || 1;
  return (
    <section aria-label="Blast radius">
      <h4>Blast radius</h4>
      <div className="br-kpis">
        <div><b>{s.direct_files}</b><span>direct files</span></div>
        <div><b>{s.indirect_confirmed}</b><span>indirect (confirmed)</span></div>
        <div><b>{s.indirect_inferred}</b><span>indirect (inferred)</span></div>
        <div><b>{s.components}</b><span>components</span></div>
        <div><b>{s.findings}</b><span>findings</span></div>
        <div><b>{s.hndl}</b><span>HNDL</span></div>
      </div>
      {s.findings > 0 && (
        <div className="stack small" role="img" aria-label={`Severity: ${Object.entries(br.severity).map(([b, n]) => `${b} ${n}`).join(", ")}`}>
          {Object.entries(br.severity).filter(([, n]) => n > 0).map(([b, n]) => (
            <div key={b} style={{ width: `${(n / total) * 100}%`, background: `var(--band-${b === "Informational" ? "info" : b.toLowerCase()})` }}
                 title={`${b}: ${n}`}>{n}</div>))}
        </div>)}
      {(br.components.direct.length > 0 || br.components.indirect.length > 0) && (
        <p className="fine">Components: {br.components.direct.join(", ") || "-"}{br.components.indirect.length > 0 && ` · via imports: ${br.components.indirect.join(", ")}`}</p>)}

      {br.migration.by_rule.length > 0 && (
        <>
          <h4>Potential migration impact</h4>
          <ul className="plain">{br.migration.by_rule.map((r) => (
            <li key={`${r.rule_id}-${r.direction}`}><code>{r.rule_id ?? "-"}</code> {r.direction || "no direction"} · {r.findings} finding(s) in {r.files} file(s)</li>))}
          </ul>
          <p className="fine">Change {br.migration.files_to_change} file(s) directly; re-test {br.migration.files_to_retest} dependent file(s).
            {br.migration.complexity_values.length > 0 && ` Migration-complexity factor(s): ${br.migration.complexity_values.join(", ")}.`} {br.migration.note}</p>
        </>)}

      <h4>Directly affected ({br.direct.length})</h4>
      <p className="fine">{br.meaning.direct}</p>
      <ul className="impact">{br.direct.map((d) => (
        <li key={d.node}>
          <button className="linklike" onClick={() => onSelect(d.node)}>{d.file}</button> <span className="dim">{d.service}</span>
          {d.reasons.map((r, i) => <div key={i} className="reason"><span>{r.reason}</span><EvidenceList items={r.evidence} /></div>)}
        </li>))}
      </ul>

      <h4>Indirectly affected ({br.indirect.length})</h4>
      <p className="fine">{br.meaning.indirect}</p>
      {br.indirect.length === 0 && <p className="dim">None found.</p>}
      <ul className="impact">{br.indirect.map((d) => (
        <li key={d.node}>
          <button className="linklike" onClick={() => onSelect(d.node)}>{d.file}</button>{" "}
          <Badge tone={d.confidence === "confirmed" ? undefined : "warn"}>{d.confidence}</Badge> <span className="dim">depth {d.depth} · {d.service}</span>
          <ol className="chain">{d.path.map((p) => (
            <li key={p.edge}><span className="dim">{p.from.slice(5)} imports {p.to.slice(5)}</span>
              {p.confidence === "inferred" && <> <Badge tone="warn">inferred</Badge> <span className="fine">{p.basis}</span></>}
              <EvidenceList items={p.evidence} /></li>))}
          </ol>
        </li>))}
      </ul>

      {br.findings.length > 0 && (
        <>
          <h4>Related findings ({br.findings.length})</h4>
          <table className="tbl"><tbody>{br.findings.map((f) => (
            <tr key={f.id}><td><Band band={f.band ?? null} qmp={f.qmp} /></td>
              <td><a href={`#/finding/${f.fid}`}>{f.fid}</a> <b>{f.algorithm}</b></td>
              <td><code>{where(f.file ?? "", f.line ?? 0)}</code></td></tr>))}</tbody></table>
        </>)}

      {br.limitations.length > 0 && (
        <div className="callout" role="note"><b>Limitations</b><ul>{br.limitations.map((l) => <li key={l}>{l}</li>)}</ul></div>)}
      <p className="fine"><b>Confirmed:</b> {br.meaning.confirmed} <b>Inferred:</b> {br.meaning.inferred}</p>
    </section>
  );
}

const REL_LABEL: Record<string, [string, string]> = {          // [outgoing, incoming]
  IMPORTS: ["Imports", "Imported by"], USES: ["Uses", "Used by"], CONTAINS: ["Contains", "Contained in"],
};
const MAX_REL = 40;

/** Every edge touching the node, grouped by relationship and direction, with confidence and the first evidence. */
function Relationships({ node, data, onSelect }: { node: GraphNode; data: GraphData; onSelect: (id: string) => void }) {
  const byId = useMemo(() => new Map(data.nodes.map((n) => [n.id, n] as const)), [data]);
  const groups = useMemo(() => {
    const g = new Map<string, { other: string; confidence: string; basis: string; evidence: Evidence[] }[]>();
    for (const e of data.edges) {
      const out = e.source === node.id, inn = e.target === node.id;
      if (!out && !inn) continue;
      const key = `${REL_LABEL[e.type]?.[out ? 0 : 1] ?? e.type}`;
      g.set(key, [...(g.get(key) ?? []), { other: out ? e.target : e.source, confidence: e.confidence, basis: e.basis, evidence: e.evidence }]);
    }
    return [...g.entries()].sort(([a], [b]) => (a < b ? -1 : 1));
  }, [data, node.id]);
  if (!groups.length) return null;
  return (
    <details className="relationships">
      <summary>Relationships ({groups.reduce((n, [, v]) => n + v.length, 0)})</summary>
      {groups.map(([label, items]) => (
        <div key={label}>
          <h5>{label} ({items.length})</h5>
          <ul className="plain">{items.slice(0, MAX_REL).map((it) => (
            <li key={it.other}>
              <button className="linklike" onClick={() => onSelect(it.other)}>{byId.get(it.other)?.label ?? it.other}</button>{" "}
              {it.confidence === "inferred" && <Badge tone="warn">inferred</Badge>} <span className="fine">{it.basis}</span>
              {it.evidence[0] && <EvidenceList items={[it.evidence[0]]} />}
            </li>))}
            {items.length > MAX_REL && <li className="fine">… {items.length - MAX_REL} more (use search or focus mode)</li>}
          </ul>
        </div>))}
    </details>
  );
}
