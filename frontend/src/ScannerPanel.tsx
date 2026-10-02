import { useState } from "react";

const API = import.meta.env.VITE_API_URL ?? "http://localhost:8000";
const MAX_BYTES = 100 * 1024 * 1024; // mirrors the server default; the server is authoritative

type Manifest = {
  scan_id: string;
  archive_type: string;
  stats: { file_count: number; total_bytes: number; skipped_count: number; redaction_count: number; service_count: number };
  services: { service: string | null; root: string; missing_fields: string[]; invalid_fields: string[] }[];
  skipped: { path: string; reason: string }[];
  warnings: string[];
};

export default function ScannerPanel() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<Manifest | null>(null);

  async function upload(file: File) {
    setError(null);
    setResult(null);
    if (file.size > MAX_BYTES) {
      setError(`This file is ${(file.size / 1048576).toFixed(0)} MB. The limit is 100 MB.`);
      return;
    }
    setBusy(true);
    try {
      const r = await fetch(`${API}/api/scans?filename=${encodeURIComponent(file.name)}`, {
        method: "POST",
        headers: { "Content-Type": "application/octet-stream" },
        body: file,
      });
      const body = await r.json();
      if (!r.ok) setError(body?.error?.message ?? `Upload failed (HTTP ${r.status}).`);
      else setResult(body);
    } catch {
      setError(`Could not reach the backend at ${API}. Check that it is running.`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-labelledby="up-h">
      <h3 id="up-h">Upload a repository archive</h3>
      <p className="empty">
        Accepts .zip, .tar, .tar.gz, .tar.bz2 or .tar.xz up to 100 MB. Files are checked and
        extracted as inert data. Uploaded code is never executed.
      </p>
      <input
        type="file"
        accept=".zip,.tar,.gz,.tgz,.bz2,.xz"
        disabled={busy}
        aria-label="Repository archive"
        onChange={(e) => e.target.files?.[0] && upload(e.target.files[0])}
      />
      {busy && <p role="status">Checking and extracting…</p>}
      {error && <p className="error" role="alert">{error}</p>}
      {result && (
        <div className="result" role="status">
          <p>
            <strong>Ingested {result.stats.file_count} files</strong> ({(result.stats.total_bytes / 1024).toFixed(0)} KB,
            detected as {result.archive_type}). Scan ID <code>{result.scan_id}</code>.
          </p>
          <ul>
            <li>{result.stats.service_count} service metadata file(s) found
              {result.services.map((s) => (
                <span key={s.root}> — {s.service ?? "unnamed"}
                  {s.missing_fields.length + s.invalid_fields.length > 0 &&
                    ` (missing/invalid: ${[...s.missing_fields, ...s.invalid_fields].join(", ")})`}</span>
              ))}
            </li>
            <li>{result.stats.redaction_count} secret value(s) redacted in the stored copy (heuristic; not exhaustive)</li>
            <li>{result.stats.skipped_count} file(s) skipped (binary or over 5 MB)</li>
          </ul>
          {result.warnings.map((w) => <p key={w} className="error">{w}</p>)}
          <p className="empty">Scanning is added in the next build phase. Nothing has been analysed yet.</p>
        </div>
      )}
    </section>
  );
}
