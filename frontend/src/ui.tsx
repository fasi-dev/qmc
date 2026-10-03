import type { ReactNode } from "react";

export const BAND_COLOR: Record<string, string> = {
  Critical: "var(--band-critical)", High: "var(--band-high)", Review: "var(--band-review)", Informational: "var(--band-info)",
};

export function Band({ band, qmp }: { band: string | null; qmp?: number | null }) {
  if (!band) return <span className="chip chip-none" title="Comment or documentation mention: not scored">not scored</span>;
  return (
    <span className="chip" style={{ background: BAND_COLOR[band] }} title="Quantum Migration Priority band (internal prototype methodology)">
      {band}{qmp != null ? ` · ${qmp}` : ""}
    </span>
  );
}
export const Badge = ({ children, tone }: { children: ReactNode; tone?: "hndl" | "warn" | "pqc" | "dim" }) =>
  <span className={`badge ${tone ? "badge-" + tone : ""}`}>{children}</span>;

export function Kpi({ value, label, tone, hint }: { value: ReactNode; label: string; tone?: string; hint?: string }) {
  return (
    <div className="kpi" title={hint}>
      <div className="kpi-v" style={tone ? { color: tone } : undefined}>{value}</div>
      <div className="kpi-l">{label}</div>
    </div>
  );
}
export const pretty = (s: string) => s.replace(/_/g, " ");
export const where = (file: string, line: number) => `${file}:${line}`;

/** Tiny dependency-free highlighter (strings, comments, a few keywords) for evidence snippets. */
export function Highlighted({ line }: { line: string }) {
  const re = /(#.*$|\/\/.*$)|("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')|\b(import|from|def|class|return|new|const|let|var|public|private|static|void|package|try|catch|server|ssl_[a-z_]+|FROM|COPY|ADD)\b/g;
  const out: ReactNode[] = [];
  let last = 0; let m: RegExpExecArray | null; let k = 0;
  while ((m = re.exec(line)) !== null) {
    if (m.index > last) out.push(line.slice(last, m.index));
    out.push(<span key={k++} className={m[1] ? "tk-c" : m[2] ? "tk-s" : "tk-k"}>{m[0]}</span>);
    last = m.index + m[0].length;
    if (m[0].length === 0) re.lastIndex++;
  }
  out.push(line.slice(last));
  return <>{out}</>;
}
