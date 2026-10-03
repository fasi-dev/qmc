// Starts the real FastAPI backend (temp data dir) so UI tests exercise real scanner/risk output.
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export default async function setup() {
  const py = process.env.QMC_PYTHON ?? (existsSync("../.venv/bin/python") ? "../.venv/bin/python" : "python3");
  const data = mkdtempSync(join(tmpdir(), "qmc-ui-"));
  const proc = spawn(py, ["-m", "uvicorn", "app.main:app", "--port", "8031"], {
    cwd: "../backend", env: { ...process.env, QMC_DATA_DIR: data }, stdio: "ignore",
  });
  for (let i = 0; i < 60; i++) {
    try { if ((await fetch("http://127.0.0.1:8031/api/health")).ok) break; } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 250));
    if (i === 59) { proc.kill(); throw new Error("backend did not start for UI tests"); }
  }
  return async () => { proc.kill(); rmSync(data, { recursive: true, force: true }); };
}
