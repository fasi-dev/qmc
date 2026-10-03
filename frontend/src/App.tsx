import { useCallback, useEffect, useState } from "react";
import { API, api, type Summary } from "./api";
import Dashboard from "./Dashboard";
import FindingDetail from "./FindingDetail";
import Inventory from "./Inventory";
import Planner from "./Planner";
import ScannerPanel from "./ScannerPanel";

const NAV = [
  { id: "dashboard", label: "Dashboard" }, { id: "scanner", label: "Repository Scanner" }, { id: "inventory", label: "Crypto Inventory" }, { id: "planner", label: "Migration Planner" },
] as const;
const LATER = ["Dependency Graph", "PQC Lab", "AI Copilot", "Report"];

function useRoute(): string[] {
  const [h, setH] = useState(location.hash);
  useEffect(() => { const f = () => setH(location.hash); window.addEventListener("hashchange", f); return () => window.removeEventListener("hashchange", f); }, []);
  const parts = h.replace(/^#\/?/, "").split("/").filter(Boolean);
  return parts.length ? parts : ["dashboard"];
}

export default function App() {
  const [scanId, setScanId] = useState<string | null>(() => localStorage.getItem("qmc.scanId"));
  const [summary, setSummary] = useState<Summary | null>(null);
  const [health, setHealth] = useState<"ok" | "down" | "…">("…");
  const [error, setError] = useState<string | null>(null);
  const route = useRoute();

  useEffect(() => { fetch(`${API}/api/health`).then((r) => setHealth(r.ok ? "ok" : "down")).catch(() => setHealth("down")); }, []);
  const load = useCallback((id: string) => api.summary(id).then((s) => { setSummary(s); setError(null); }).catch((e: Error) => {
    if (/not found/i.test(e.message)) { localStorage.removeItem("qmc.scanId"); setScanId(null); setSummary(null); } else setError(e.message);
  }), []);
  useEffect(() => { if (scanId) void load(scanId); }, [scanId, load]);

  const onDone = (s: Summary) => { localStorage.setItem("qmc.scanId", s.scan.id); setScanId(s.scan.id); setSummary(s); };
  const page = route[0];

  let body;
  if (page === "scanner") body = <ScannerPanel onDone={onDone} current={summary} />;
  else if (!scanId) body = (
    <div className="panel empty-state">
      <h3>No scan yet</h3>
      <p className="dim">Load the bundled Acme Payments repository, or upload your own archive, to see your cryptographic inventory and quantum exposure.</p>
      <a className="btn primary" href="#/scanner">Scan a repository</a>
    </div>);
  else if (page === "inventory") body = <Inventory scanId={scanId} />;
  else if (page === "planner") body = <Planner scanId={scanId} />;
  else if (page === "finding" && route[1]) body = <FindingDetail scanId={scanId} fid={route[1]} />;
  else body = summary ? <Dashboard s={summary} /> : <p className="dim">Loading…</p>;

  const title = page === "finding" ? "Finding detail" : NAV.find((n) => n.id === page)?.label ?? "Dashboard";
  return (
    <div className="shell">
      <aside className="nav">
        <h1 className="brand">Quantum Migration Copilot</h1>
        <p className="tag">Discover your cryptography. Understand your quantum exposure. Plan your migration.</p>
        <nav aria-label="Main">
          {NAV.map((n) => <a key={n.id} href={`#/${n.id}`} className={page === n.id || (n.id === "inventory" && page === "finding") ? "navitem on" : "navitem"}>{n.label}</a>)}
          {LATER.map((l) => <span key={l} className="navitem soon" title="Planned: not part of this build">{l}<small>soon</small></span>)}
        </nav>
        <p className="engine" role="status">Backend: {health === "ok" ? "connected" : health === "down" ? "unreachable" : "connecting…"}</p>
      </aside>
      <main className="main">
        <h2 className="page">{title}</h2>
        {error && <p className="error" role="alert">{error}</p>}
        {health === "down" && <p className="error" role="alert">Cannot reach the backend at {API}. Start it with <code>uvicorn app.main:app --port 8000</code> in <code>backend/</code>.</p>}
        {body}
        <footer className="honesty">Static-analysis estimates. Not a certification. Quantum-vulnerable means vulnerable to a future quantum computer, not broken today.</footer>
      </main>
    </div>
  );
}
