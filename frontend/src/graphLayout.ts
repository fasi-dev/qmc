/**
 * Deterministic layered layout for the cryptographic dependency graph (no layout library, no randomness).
 *
 * Columns, left to right:  services | files | findings (optional) | algorithms | libraries
 * File -> file IMPORTS edges are drawn as arcs on the left of the file column.
 * With findings hidden (the default, to keep large scans readable), file -> algorithm/library edges are derived
 * from the findings they contain; each derived edge keeps the ids of the edges it stands for, so nothing is invented.
 */
import type { Confidence, GraphData, GraphEdge, GraphNode, NodeType } from "./api";

export type LayoutOptions = {
  showFindings: boolean;
  types: Record<NodeType, boolean>;
  query: string;
  /** When set, only these node ids are shown (e.g. a blast radius). */
  focus?: Set<string> | null;
};
export type PlacedNode = GraphNode & { x: number; y: number; w: number; h: number; col: number; match: boolean };
export type PlacedEdge = {
  id: string; type: GraphEdge["type"] | "USES (via findings)"; source: string; target: string; confidence: Confidence;
  arc: boolean; via: string[];
};
export type Layout = { nodes: PlacedNode[]; edges: PlacedEdge[]; width: number; height: number; hidden: number };

export const COLUMN: Record<NodeType, number> = { service: 0, file: 1, finding: 2, algorithm: 3, library: 4 };
export const NODE_W: Record<NodeType, number> = { service: 170, file: 270, finding: 190, algorithm: 150, library: 170 };
export const NODE_H = 28;
const GAP_Y = 10, GAP_X = 90, PAD = 40, ARC_ROOM = 90;
const BANDS = ["Critical", "High", "Review", "Informational"];

const bandRank = (b?: string | null) => (b && BANDS.includes(b) ? BANDS.indexOf(b) : BANDS.length);
const cmp = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

export function matches(n: GraphNode, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return false;
  return [n.label, n.path, n.algorithm, n.rule_id, n.service, n.fid].some((v) => typeof v === "string" && v.toLowerCase().includes(q));
}

export function layoutGraph(g: GraphData, opt: LayoutOptions): Layout {
  const visible = (n: GraphNode) =>
    opt.types[n.type] && (n.type !== "finding" || opt.showFindings) && (!opt.focus || opt.focus.has(n.id));
  const shown = g.nodes.filter(visible);
  const shownIds = new Set(shown.map((n) => n.id));

  // ---- column ordering (stable, meaningful): services by name; files by service then crypto-first then path; ...
  const order = new Map<string, number>();
  const services = shown.filter((n) => n.type === "service").sort((a, b) => cmp(a.label, b.label));
  services.forEach((n, i) => order.set(n.label, i));
  const fileKey = (n: GraphNode) => [order.get(n.service ?? "") ?? 1e6, n.crypto ? 0 : 1, n.label] as const;
  const files = shown.filter((n) => n.type === "file").sort((a, b) => {
    const x = fileKey(a), y = fileKey(b);
    return x[0] - y[0] || x[1] - y[1] || cmp(x[2], y[2]);
  });
  const fileIndex = new Map(files.map((f, i) => [f.path ?? f.label, i] as const));
  const findings = shown.filter((n) => n.type === "finding").sort((a, b) =>
    (fileIndex.get(a.file ?? "") ?? 1e6) - (fileIndex.get(b.file ?? "") ?? 1e6) || (a.line ?? 0) - (b.line ?? 0) || cmp(a.id, b.id));
  const algorithms = shown.filter((n) => n.type === "algorithm").sort((a, b) =>
    bandRank(a.max_band) - bandRank(b.max_band) || Number(!!b.quantum_vulnerable) - Number(!!a.quantum_vulnerable) || cmp(a.label, b.label));
  const libraries = shown.filter((n) => n.type === "library").sort((a, b) => cmp(a.label, b.label));
  const cols: GraphNode[][] = [services, files, opt.showFindings ? findings : [], algorithms, libraries];

  // ---- coordinates: each column centred vertically on the tallest one
  const colHeight = (c: GraphNode[]) => c.length * (NODE_H + GAP_Y) - GAP_Y;
  const tallest = Math.max(NODE_H, ...cols.map(colHeight));
  const xs: number[] = [];
  let x = PAD;
  cols.forEach((c, i) => {
    if (i === 1 && files.length) x += ARC_ROOM;                       // room for import arcs left of the files
    xs.push(x);
    const w = c.length ? NODE_W[c[0].type] : 0;
    if (c.length) x += w + GAP_X;
  });
  const placed: PlacedNode[] = [];
  cols.forEach((c, ci) => {
    const top = PAD + (tallest - colHeight(c)) / 2;
    c.forEach((n, i) => placed.push({ ...n, x: xs[ci], y: top + i * (NODE_H + GAP_Y), w: NODE_W[n.type], h: NODE_H,
                                      col: COLUMN[n.type], match: matches(n, opt.query) }));
  });

  // ---- edges: real edges between shown nodes; derived file->algorithm/library edges when findings are hidden
  const edges: PlacedEdge[] = [];
  const derived = new Map<string, PlacedEdge>();
  const findingFile = new Map<string, string>();
  for (const e of g.edges) if (e.type === "CONTAINS" && e.target.startsWith("finding:")) findingFile.set(e.target, e.source);
  for (const e of g.edges) {
    if (shownIds.has(e.source) && shownIds.has(e.target)) {
      edges.push({ id: e.id, type: e.type, source: e.source, target: e.target, confidence: e.confidence,
                   arc: e.type === "IMPORTS" && e.target.startsWith("file:"), via: [e.id] });
    } else if (!opt.showFindings && e.type === "USES" && e.source.startsWith("finding:")) {
      const file = findingFile.get(e.source);
      if (!file || !shownIds.has(file) || !shownIds.has(e.target)) continue;
      if (opt.focus && !opt.focus.has(e.source)) continue;         // focus mode: only the selected findings count
      const id = `DERIVED:${file}->${e.target}`;
      const d = derived.get(id) ?? { id, type: "USES (via findings)", source: file, target: e.target, confidence: "confirmed", arc: false, via: [] };
      d.via.push(e.id);
      derived.set(id, d);
    }
  }
  // An IMPORTS edge file->library and a derived USES edge for the same pair are the same visual line: keep both ids.
  for (const d of [...derived.values()].sort((a, b) => cmp(a.id, b.id))) {
    const twin = edges.find((e) => e.type === "IMPORTS" && e.source === d.source && e.target === d.target);
    if (twin) twin.via.push(...d.via);
    else edges.push(d);
  }
  edges.sort((a, b) => cmp(a.id, b.id));
  const width = x - GAP_X + PAD;
  return { nodes: placed, edges, width: Math.max(width, 400), height: tallest + 2 * PAD, hidden: g.nodes.length - shown.length };
}

/** Path geometry for an edge (pure; used by the SVG renderer and by tests). */
export function edgePath(e: PlacedEdge, s: PlacedNode, t: PlacedNode): string {
  if (e.arc) {                                                          // file -> file: arc on the left of the column
    const y1 = s.y + s.h / 2, y2 = t.y + t.h / 2;
    const bulge = Math.min(ARC_ROOM - 10, 20 + Math.abs(y2 - y1) / 6);
    return `M ${s.x} ${y1} C ${s.x - bulge} ${y1}, ${t.x - bulge} ${y2}, ${t.x} ${y2}`;
  }
  const [a, b] = s.x <= t.x ? [s, t] : [t, s];
  const x1 = a.x + a.w, y1 = a.y + a.h / 2, x2 = b.x, y2 = b.y + b.h / 2;
  const mx = (x1 + x2) / 2;
  return `M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`;
}

/** Transform that fits the whole layout into a viewport (scale clamped to the zoom range). */
export function fitTransform(l: Layout, vw: number, vh: number, min = 0.1, max = 1.5): { x: number; y: number; k: number } {
  const k = Math.max(min, Math.min(max, Math.min(vw / l.width, vh / l.height)));
  return { k, x: (vw - l.width * k) / 2, y: (vh - l.height * k) / 2 };
}
