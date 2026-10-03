import { useState } from "react";
import { api, type Summary } from "./api";

type Step = "idle" | "ingest" | "scan" | "done" | "error";
const STEPS: [Step, string][] = [["ingest", "Safe ingestion (validate, extract, redact)"], ["scan", "Scan, risk scoring, build inventory"], ["done", "Done"]];

export default function ScannerPanel({ onDone, current }: { onDone: (s: Summary) => void; current: Summary | null }) {
  const [step, setStep] = useState<Step>("idle");
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<Summary | null>(null);
  const busy = step === "ingest" || step === "scan";

  async function run(fn: () => Promise<Summary>, first: Step = "ingest") {
    setError(null); setResult(null); setStep(first);
    try {
      const s = await fn();
      setResult(s); setStep("done"); onDone(s);
    } catch (e) { setError((e as Error).message); setStep("error"); }
  }
  const upload = (file: File) => {
    if (file.size > 100 * 1024 * 1024) { setError(`This file is ${(file.size / 1048576).toFixed(0)} MB. The limit is 100 MB.`); setStep("error"); return; }
    return run(async () => {
      const up = await api.upload(file);
      setStep("scan");
      return api.analyze(up.scan_id);
    });
  };
  const hits = result?.scan.analysis?.rule_hits ?? {};

  return (
    <section aria-labelledby="up-h">
      <div className="panel">
        <h3 id="up-h">Scan a repository</h3>
        <p className="dim">Upload a .zip / .tar.gz archive (max 100 MB), or load the bundled fictional <b>Acme Payments</b> repository.
          Uploaded code is never executed; archives are validated and secrets are redacted before analysis.</p>
        <div className="row">
          <button className="btn primary" disabled={busy} onClick={() => run(() => api.demo())}>Load Acme Payments demo</button>
          <label className={`btn ${busy ? "disabled" : ""}`}>
            Upload archive…
            <input type="file" hidden disabled={busy} accept=".zip,.tar,.gz,.tgz,.bz2,.xz" aria-label="Repository archive"
                   onChange={(e) => { const f = e.target.files?.[0]; if (f) void upload(f); e.target.value = ""; }} />
          </label>
        </div>
        {step !== "idle" && (
          <ol className="steps" aria-live="polite">
            {STEPS.map(([k, label], i) => {
              const order = ["ingest", "scan", "done"]; const at = order.indexOf(step === "error" ? "ingest" : step);
              const state = step === "error" ? (i === 0 ? "bad" : "") : i < at || step === "done" ? "ok" : i === at ? "now" : "";
              return <li key={k} className={state}>{label}</li>;
            })}
          </ol>
        )}
        {error && <p className="error" role="alert">{error}</p>}
      </div>

      {result && (
        <div className="panel result" role="status">
          <h3>Scan complete</h3>
          <p><b>{result.totals.crypto_findings}</b> crypto findings · <b>{result.totals.quantum_vulnerable}</b> quantum-vulnerable ·{" "}
            <b>{result.totals.critical}</b> critical · <b>{result.totals.high_confidence}</b> high-confidence ·{" "}
            {result.scan.ingestion.stats.redaction_count} secret value(s) redacted · {result.scan.ingestion.stats.skipped_count} file(s) skipped</p>
          <div className="row">
            <a className="btn primary" href="#/dashboard">View dashboard</a>
            <a className="btn" href="#/inventory">Open inventory</a>
          </div>
          <details>
            <summary>Rules that fired ({Object.keys(hits).length})</summary>
            <ul className="ticker">{Object.entries(hits).map(([r, n]) => <li key={r}><code>{r}</code> × {n}</li>)}</ul>
          </details>
        </div>
      )}
      {!result && current && <p className="fine">Current scan: <b>{current.scan.repo_name}</b> ({current.totals.crypto_findings} findings). <a href="#/dashboard">Open dashboard</a></p>}
      <p className="fine">Static-analysis estimates. Not a certification.</p>
    </section>
  );
}
