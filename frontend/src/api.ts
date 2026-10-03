export const API: string = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

export type Card = {
  id: string; file: string; line_start: number; algorithm: string; operation: string; service: string;
  confidence_level: string; quantum_vulnerable: boolean; already_pqc: boolean; band: string | null; qmp: number | null;
  hndl: boolean; hndl_severity: string | null; primitive: string; context: string; rule_id: string;
  comment_only: boolean; test_path: boolean; suppressed: boolean; evidence: string; rank: number; badges: string[];
};
export type ServiceRow = {
  service: string; findings: number; quantum_vulnerable: number; already_pqc: number; critical: number; high: number; hndl: number;
  data_classification: string | null; business_criticality: string | null; internet_exposed: boolean | null;
  data_lifetime_years: number | null; metadata_missing: boolean; migration_status: string;
};
export type Summary = {
  scan: { id: string; created_at: string; filename: string; repo_name: string; status: string;
          analysis: { as_of: string; engine_version: string; files_scanned: Record<string, number>; rule_hits: Record<string, number>;
                      files_skipped: { file: string; reason: string }[] } | null;
          ingestion: { archive_type: string; stats: { file_count: number; redaction_count: number; skipped_count: number }; warnings: string[] } };
  totals: { crypto_findings: number; quantum_vulnerable: number; already_pqc: number; high_confidence: number; critical: number;
            hndl_elevated: number; services: number; comment_or_doc_mentions: number; suppressed: number; test_path: number };
  by_band: Record<string, number>; by_primitive: Record<string, number>; by_algorithm: Record<string, number>;
  services: ServiceRow[]; top_findings: Card[]; qmp_label: string; limitations: string;
};
export type Factor = { value: number; weight: number; label: string; why: string; source: string };
export type Risk = {
  qmp: number; raw: number; band: string; band_uncapped: string; cap_reason: string | null; role: string | null;
  hndl: { flag: boolean; severity?: string; text?: string }; badges: string[]; formula: string; label: string;
  factors: Record<"QE" | "DS" | "IE" | "BC" | "MC", Factor>;
};
export type Finding = {
  id: string; rule_id: string; rule_version: string; engine_version: string; file: string; line_start: number; line_end: number;
  algorithm: string; primitive: string; operation: string; library: string | null; api: string | null; context: string; service: string;
  evidence: string; confidence: number; confidence_level: string; quantum_vulnerable: boolean; already_pqc: boolean;
  metadata: { key_size: number | null; comment_only: boolean; in_dead_code: boolean; test_path: boolean };
};
export type Plan = {
  rule_id: string | null; current: string; direction: string; standard: string | null; no_pqc_mapping: boolean; human_review: boolean;
  human_review_note?: string | null; complexity: number | null; note?: string | null; why?: string | null; caveats: string[];
  interoperability?: string | null; steps: string[]; honesty: string[]; crypto_agility: string[];
};
export type PlanRow = Omit<Plan, "honesty" | "crypto_agility"> & {
  id: string; rank: number; band: string | null; qmp: number | null; hndl: boolean; service: string; file: string; line_start: number;
  algorithm: string; operation: string; role: string | null; confidence_level: string;
};
export type Detail = {
  migration: Plan | null;
  finding: Finding; risk: Risk | null; rank: number; band: string | null; qmp: number | null; suppressed: boolean;
  suppression: { reason: string; author: string; at: string } | null; qmp_label: string;
  snippet: { start_line: number; highlight_start: number; highlight_end: number; lines: string[] } | null;
};
export type Facets = { algorithm: string[]; primitive: string[]; service: string[]; band: string[]; confidence_level: string[] };

async function j<T>(path: string, init?: RequestInit): Promise<T> {
  let r: Response;
  try { r = await fetch(API + path, init); } catch { throw new Error(`Cannot reach the backend at ${API}. Is it running?`); }
  const body = await r.json().catch(() => null);
  if (!r.ok) {
    const d = body?.detail;
    throw new Error(body?.error?.message ?? (typeof d === "string" ? d : `Request failed (HTTP ${r.status})`));
  }
  return body as T;
}

export const api = {
  demo: () => j<Summary>("/api/demo/acme", { method: "POST" }),
  upload: (file: File) => j<{ scan_id: string; stats: { file_count: number } }>(`/api/scans?filename=${encodeURIComponent(file.name)}`,
    { method: "POST", headers: { "Content-Type": "application/octet-stream" }, body: file }),
  analyze: (id: string) => j<Summary>(`/api/scans/${id}/analyze`, { method: "POST" }),
  summary: (id: string) => j<Summary>(`/api/scans/${id}/summary`),
  findings: (id: string, qs: string) => j<{ findings: Card[]; count: number; total_all: number; facets: Facets }>(`/api/scans/${id}/findings?${qs}`),
  csvUrl: (id: string, qs: string) => `${API}/api/scans/${id}/findings.csv?${qs}`,
  migration: (id: string) => j<{ rows: PlanRow[]; crypto_agility: string[]; honesty: string[]; qmp_label: string }>(`/api/scans/${id}/migration`),
  finding: (id: string, fid: string) => j<Detail>(`/api/scans/${id}/findings/${fid}`),
  suppress: (id: string, fid: string, reason: string) => j<Detail>(`/api/scans/${id}/findings/${fid}/suppress`,
    { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ reason, author: "demo-user" }) }),
  unsuppress: (id: string, fid: string) => j<Detail>(`/api/scans/${id}/findings/${fid}/suppress`, { method: "DELETE" }),
};
