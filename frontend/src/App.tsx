import { useEffect, useState } from "react";
import ScannerPanel from "./ScannerPanel";

const API = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

// Screens from 10_UI_ARCHITECTURE_AND_DEMO.md section 1. `phase` = build phase that fills it in.
const SCREENS = [
  { id: "dashboard", label: "Dashboard", phase: 4 },
  { id: "scanner", label: "Repository Scanner", phase: 2 },
  { id: "inventory", label: "Crypto Inventory", phase: 4 },
  { id: "graph", label: "Dependency Graph", phase: 6 },
  { id: "planner", label: "Migration Planner", phase: 7 },
  { id: "lab", label: "PQC Lab", phase: 8 },
  { id: "copilot", label: "AI Copilot", phase: 9 },
  { id: "report", label: "Report", phase: 10 },
] as const;

type Health = { status: string; engine_version: string; copilot_mode: string };

export default function App() {
  const [active, setActive] = useState<string>("dashboard");
  const [health, setHealth] = useState<Health | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch(`${API}/api/health`)
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
      .then(setHealth)
      .catch((e) => setError(String(e.message ?? e)));
  }, []);

  const screen = SCREENS.find((s) => s.id === active)!;

  return (
    <div className="shell">
      <aside className="nav">
        <h1 className="brand">Quantum Migration Copilot</h1>
        <nav aria-label="Main">
          {SCREENS.map((s) => (
            <button
              key={s.id}
              className={s.id === active ? "navitem on" : "navitem"}
              onClick={() => setActive(s.id)}
            >
              {s.label}
            </button>
          ))}
        </nav>
        <p className="engine" role="status">
          {health
            ? `Engine ${health.engine_version} connected`
            : error
            ? "Backend unreachable"
            : "Connecting to backend…"}
        </p>
      </aside>

      <main className="main">
        <h2>{screen.label}</h2>
        {screen.id === "scanner" ? (
          <ScannerPanel />
        ) : (
          <p className="empty">
            This screen is built in phase {screen.phase}. Nothing has been scanned yet.
          </p>
        )}
        {error && (
          <p className="error">
            Could not reach the backend at {API} ({error}). Start it with
            <code> uvicorn app.main:app --port 8000</code> from <code>backend/</code>.
          </p>
        )}
        <footer className="honesty">
          Static-analysis estimates. Not a certification.
        </footer>
      </main>
    </div>
  );
}
