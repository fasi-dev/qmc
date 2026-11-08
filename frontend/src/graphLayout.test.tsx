/** Pure layout tests for the dependency graph (no backend, no DOM). */
import { describe, expect, it } from "vitest";
import type { GraphData, GraphEdge, GraphNode, NodeType } from "./api";
import { edgePath, fitTransform, layoutGraph, matches } from "./graphLayout";

const ALL: Record<NodeType, boolean> = { service: true, file: true, finding: true, algorithm: true, library: true };
const E = (type: GraphEdge["type"], source: string, target: string, confidence: "confirmed" | "inferred" = "confirmed"): GraphEdge =>
  ({ id: `${type}:${source}->${target}`, type, source, target, confidence, basis: "test", evidence: [], evidence_count: 0 });

function sample(): GraphData {
  const nodes: GraphNode[] = [
    { id: "service:api", type: "service", label: "api" },
    { id: "file:src/auth.py", type: "file", label: "src/auth.py", path: "src/auth.py", service: "api", crypto: true, finding_count: 1, max_band: "Critical" },
    { id: "file:src/routes.py", type: "file", label: "src/routes.py", path: "src/routes.py", service: "api", crypto: false, finding_count: 0 },
    { id: "finding:CRYPTO-001", type: "finding", label: "CRYPTO-001 ECDSA", fid: "CRYPTO-001", file: "src/auth.py", line: 3, band: "Critical", quantum_vulnerable: true },
    { id: "algorithm:ECDSA", type: "algorithm", label: "ECDSA", quantum_vulnerable: true, max_band: "Critical", finding_count: 1 },
    { id: "algorithm:SHA-256", type: "algorithm", label: "SHA-256", max_band: "Informational", finding_count: 0 },
    { id: "library:cryptography", type: "library", label: "cryptography", finding_count: 1, importing_files: 1 },
  ];
  const edges = [
    E("CONTAINS", "service:api", "file:src/auth.py"), E("CONTAINS", "service:api", "file:src/routes.py"),
    E("CONTAINS", "file:src/auth.py", "finding:CRYPTO-001"), E("USES", "finding:CRYPTO-001", "algorithm:ECDSA"),
    E("USES", "finding:CRYPTO-001", "library:cryptography"), E("IMPORTS", "file:src/auth.py", "library:cryptography"),
    E("IMPORTS", "file:src/routes.py", "file:src/auth.py", "inferred"),
  ];
  return { version: 1, nodes, edges, limitations: [], stats: {} as GraphData["stats"] };
}

describe("layoutGraph", () => {
  it("is deterministic and independent of input order", () => {
    const a = layoutGraph(sample(), { showFindings: false, types: ALL, query: "" });
    const s = sample();
    s.nodes.reverse(); s.edges.reverse();
    const b = layoutGraph(s, { showFindings: false, types: ALL, query: "" });
    expect(JSON.stringify(b)).toBe(JSON.stringify(a));
  });

  it("places node types in fixed columns and crypto files before dependents", () => {
    const l = layoutGraph(sample(), { showFindings: true, types: ALL, query: "" });
    const at = (id: string) => l.nodes.find((n) => n.id === id)!;
    expect(at("service:api").x < at("file:src/auth.py").x).toBe(true);
    expect(at("file:src/auth.py").x < at("finding:CRYPTO-001").x).toBe(true);
    expect(at("finding:CRYPTO-001").x < at("algorithm:ECDSA").x).toBe(true);
    expect(at("algorithm:ECDSA").x < at("library:cryptography").x).toBe(true);
    expect(at("file:src/auth.py").y < at("file:src/routes.py").y).toBe(true);
    expect(at("algorithm:ECDSA").y < at("algorithm:SHA-256").y).toBe(true);        // worse band first
  });

  it("derives file->algorithm edges from hidden findings without inventing any", () => {
    const l = layoutGraph(sample(), { showFindings: false, types: ALL, query: "" });
    expect(l.nodes.some((n) => n.type === "finding")).toBe(false);
    const d = l.edges.find((e) => e.id === "DERIVED:file:src/auth.py->algorithm:ECDSA")!;
    expect(d.via).toEqual(["USES:finding:CRYPTO-001->algorithm:ECDSA"]);
    // the library is reached by an import AND by a finding: one visual edge carrying both pieces of evidence
    const lib = l.edges.filter((e) => e.source === "file:src/auth.py" && e.target === "library:cryptography");
    expect(lib.length).toBe(1);
    expect(lib[0].via.sort()).toEqual(["IMPORTS:file:src/auth.py->library:cryptography", "USES:finding:CRYPTO-001->library:cryptography"]);
    expect(l.edges.some((e) => e.target === "algorithm:SHA-256")).toBe(false);     // no finding uses it: no edge
  });

  it("keeps inferred confidence and draws file imports as arcs", () => {
    const l = layoutGraph(sample(), { showFindings: false, types: ALL, query: "" });
    const imp = l.edges.find((e) => e.id === "IMPORTS:file:src/routes.py->file:src/auth.py")!;
    expect(imp.confidence).toBe("inferred");
    expect(imp.arc).toBe(true);
    const s = l.nodes.find((n) => n.id === imp.source)!, t = l.nodes.find((n) => n.id === imp.target)!;
    expect(edgePath(imp, s, t).startsWith(`M ${s.x} `)).toBe(true);               // leaves from the left edge
  });

  it("filters by type and by focus set", () => {
    const noLib = layoutGraph(sample(), { showFindings: false, types: { ...ALL, library: false }, query: "" });
    expect(noLib.nodes.some((n) => n.type === "library")).toBe(false);
    expect(noLib.edges.some((e) => e.target.startsWith("library:"))).toBe(false);
    const focus = new Set(["file:src/auth.py", "algorithm:ECDSA", "finding:CRYPTO-001"]);
    const f = layoutGraph(sample(), { showFindings: false, types: ALL, query: "", focus });
    expect(f.nodes.map((n) => n.id).sort()).toEqual(["algorithm:ECDSA", "file:src/auth.py"]);
    expect(f.hidden).toBe(5);
  });

  it("search marks matches without changing positions", () => {
    const a = layoutGraph(sample(), { showFindings: false, types: ALL, query: "" });
    const b = layoutGraph(sample(), { showFindings: false, types: ALL, query: "routes" });
    expect(b.nodes.filter((n) => n.match).map((n) => n.id)).toEqual(["file:src/routes.py"]);
    expect(b.nodes.map((n) => [n.id, n.x, n.y])).toEqual(a.nodes.map((n) => [n.id, n.x, n.y]));
    expect(matches(sample().nodes[3], "crypto-001")).toBe(true);
  });

  it("handles large graphs quickly and fits them to the viewport", () => {
    const g = sample();
    for (let i = 0; i < 3000; i++) {
      g.nodes.push({ id: `file:gen/f${i}.py`, type: "file", label: `gen/f${i}.py`, path: `gen/f${i}.py`, service: "api", crypto: false });
      g.edges.push(E("IMPORTS", `file:gen/f${i}.py`, i ? `file:gen/f${i - 1}.py` : "file:src/auth.py"));
    }
    const t0 = Date.now();
    const l = layoutGraph(g, { showFindings: false, types: ALL, query: "" });
    expect(Date.now() - t0 < 2000).toBe(true);
    const fit = fitTransform(l, 1000, 600, 0.0001, 1.5);                          // unclamped: must fit entirely
    expect(l.height * fit.k <= 600 + 1e-6 && l.width * fit.k <= 1000 + 1e-6).toBe(true);
    expect(fitTransform(l, 1000, 600).k).toBe(0.1);                               // clamped to the minimum zoom
  });

  it("empty graph produces an empty, valid layout", () => {
    const l = layoutGraph({ version: 1, nodes: [], edges: [], limitations: [], stats: {} as GraphData["stats"] },
                          { showFindings: false, types: ALL, query: "" });
    expect(l.nodes.length).toBe(0);
    expect(l.width > 0 && l.height > 0).toBe(true);
  });
});
