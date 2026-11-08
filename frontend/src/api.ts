export const API: string = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

// ---- per-scan access tokens -------------------------------------------------------------------------------
// The backend returns an access token once, when a scan is created, and requires it (X-QMC-Scan-Token) on every
// later request for that scan. Tokens are kept in this browser only (localStorage), keyed by scan id.
const TOKENS_KEY = "qmc.tokens";
const memoryTokens: Record<string, string> = {};   // fallback when localStorage is unavailable
const SCAN_IN_PATH = /\/api\/scans\/([0-9a-f-]{36})/;

function loadTokens(): Record<string, string> {
  try { return JSON.parse(localStorage.getItem(TOKENS_KEY) ?? "{}") as Record<string, string>; } catch { return {}; }
}
export function rememberToken(scanId: string, token: string | undefined): void {
  if (!token) return;
  const t = loadTokens(); t[scanId] = token;
  try { localStorage.setItem(TOKENS_KEY, JSON.stringify(t)); } catch { /* storage unavailable: token lives for this page only */ }
  memoryTokens[scanId] = token;
}
export function forgetToken(scanId: string): void {
  const t = loadTokens(); delete t[scanId]; delete memoryTokens[scanId];
  try { localStorage.setItem(TOKENS_KEY, JSON.stringify(t)); } catch { /* ignore */ }
}
function authHeaders(path: string): Record<string, string> {
  const m = SCAN_IN_PATH.exec(path);
  if (!m) return {};
  const token = memoryTokens[m[1]] ?? loadTokens()[m[1]];
  return token ? { "X-QMC-Scan-Token": token } : {};
}

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
  scan_warnings?: string[];
  readiness?: { available: boolean; level?: string; label?: string; blockers?: number; top_recommendation?: string | null };
  dependency_graph?: { available: boolean; imports_available?: boolean; crypto_files?: number; dependent_files?: number;
                       import_edges?: number; inferred_edges?: number };
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
// ---- dependency graph (GET /api/scans/{id}/graph, /graph/blast-radius) ------------------------------------
export type NodeType = "service" | "file" | "finding" | "algorithm" | "library";
export type Confidence = "confirmed" | "inferred";
export type Evidence = { file: string; line: number; text: string; kind: string; spec?: string; rule_id?: string };
export type GraphNode = {
  id: string; type: NodeType; label: string;
  // file
  path?: string; language?: string | null; service?: string; finding_count?: number; vulnerable_count?: number;
  max_band?: string | null; crypto?: boolean;
  // finding
  fid?: string; file?: string; line?: number; algorithm?: string; operation?: string; band?: string | null; qmp?: number | null;
  hndl?: boolean; quantum_vulnerable?: boolean; already_pqc?: boolean; confidence?: string; rule_id?: string;
  migration_rule?: string | null; migration_direction?: string | null; complexity?: number | null;
  // algorithm / library / service
  primitive?: string; importing_files?: number; metadata_file?: string | null;
};
export type GraphEdge = {
  id: string; type: "CONTAINS" | "USES" | "IMPORTS"; source: string; target: string; confidence: Confidence;
  basis: string; evidence: Evidence[]; evidence_count: number;
};
export type GraphStats = {
  nodes: number; edges: number; by_type: Record<NodeType, number>; crypto_files: number; dependent_files: number;
  import_edges: number; inferred_edges: number; library_imports: number; internal_imports: number; unresolved_imports: number;
  imports_available: boolean;
};
export type GraphData = { version: number; nodes: GraphNode[]; edges: GraphEdge[]; stats: GraphStats; limitations: string[] };
export type PathStep = { edge: string; from: string; to: string; confidence: Confidence; basis: string; evidence: Evidence[] };
export type BlastRadius = {
  node: GraphNode;
  summary: { direct_files: number; indirect_files: number; indirect_confirmed: number; indirect_inferred: number; components: number;
             findings: number; quantum_vulnerable: number; hndl: number; max_depth: number; depth_capped: boolean };
  direct: { node: string; file: string; service: string; confidence: Confidence; reasons: { reason: string; confidence: Confidence; evidence: Evidence[] }[] }[];
  indirect: { node: string; file: string; service: string; depth: number; confidence: Confidence; path: PathStep[] }[];
  components: { direct: string[]; indirect: string[] };
  findings: GraphNode[];
  severity: Record<string, number>;
  migration: { by_rule: { rule_id: string | null; direction: string | null; findings: number; files: number }[];
               complexity_values: number[]; files_to_change: number; files_to_retest: number; note: string };
  limitations: string[];
  meaning: Record<"direct" | "indirect" | "confirmed" | "inferred", string>;
};

// ---- PQC readiness (GET /api/scans/{id}/readiness) ---------------------------------------------------------
export type ReadinessEvidence = { fid: string; file: string; line: number; text: string; algorithm: string; band: string | null; service: string; rule_id: string };
export type ReadinessStatus = "blocker" | "action" | "review" | "positive" | "partial" | "not_detected" | "info";
export type ReadinessCategory = {
  id: string; title: string; status: ReadinessStatus; summary: string; count: number; files: number; services: string[];
  algorithms: Record<string, number>; evidence: ReadinessEvidence[]; references: string[]; note?: string;
  hubs?: { file: string; imported_by: string[] }[]; hndl?: number;
};
export type Readiness = {
  version: number; level: { id: string; label: string; rule: string }; level_rules: { id: string; label: string; rule: string }[];
  counts: Record<string, number>; categories: ReadinessCategory[];
  blockers: { id: string; title: string; why: string; evidence: ReadinessEvidence[]; services: string[]; references: string[] }[];
  recommendations: { priority: number; title: string; action: string; references: string[]; evidence: ReadinessEvidence[];
                     evidence_total: number; services: string[]; simulate: string | null; libraries?: string[];
                     hubs?: { file: string; imported_by: string[] }[] }[];
  libraries: { library: string; findings: number; vulnerable_findings: number; files: number; pqc_support: string | null;
               references: string[]; status: "known" | "not_verified"; note: string }[];
  analyzed: { files_scanned: Record<string, number>; engine_version: string | null; scan_status: string | null; skipped_files: number;
              skipped_by_reason: Record<string, number>; import_relationships: boolean; services_with_metadata: string[];
              excluded: Record<string, number> };
  not_analyzed: string[]; limitations: string[]; references: Record<string, { title: string; url: string }>; statement: string;
};

// ---- migration simulator (GET /api/scans/{id}/simulate?node=&target=) -------------------------------------
export type SimTarget = { id: string; name: string; family: string; standard: string; refs: string[]; sizes: Record<string, number>; note: string };
export type SimTrack = {
  id: string; title: string;
  findings: { fid: string; file: string; line: number; algorithm: string; operation: string; band: string | null; qmp: number | null;
              hndl: boolean; service: string; evidence: string; confidence: string; test_path: boolean }[];
  current: { algorithms: Record<string, number>; operations: Record<string, number>; apis: string[]; libraries: string[];
             key_sizes: number[]; sizes: Record<string, Record<string, string>> };
  target: SimTarget | null; target_options: { id: string; name: string; standard: string }[];
  affected: { direct_files: string[]; components: string[]; indirect_files: BlastRadius["indirect"]; indirect_confirmed: number;
              indirect_inferred: number; hndl: number };
  rules: { rule_id: string; name: string; direction: string | null; steps: string[]; findings: number }[];
  integration_changes: { operation: string; change: string; why: string;
                         call_sites: { fid: string; file: string; line: number; text: string; api: string | null }[] }[];
  compatibility: string[]; libraries: { library: string; pqc_support: string | null; references: string[]; status: string }[];
  references: string[];
  architecture: { total_files?: number; shown_files?: number; truncated?: boolean; current: { nodes: GraphNode[]; edges: GraphEdge[] }; proposed: { nodes: (GraphNode & { proposed?: boolean })[]; edges: GraphEdge[] }; note: string };
  limitations: string[];
};
export type Simulation = {
  version: number; selection: GraphNode; target_requested: string | null;
  summary: { findings_in_scope: number; tracks: number; direct_files: number; indirect_files: number; indirect_inferred: number;
             components: number; no_migration_needed: number };
  tracks: SimTrack[]; no_migration_needed: { fid: string; file: string; line: number; algorithm: string; reason: string }[];
  blast_radius: { summary: BlastRadius["summary"]; components: BlastRadius["components"]; limitations: string[] };
  crypto_agility: string[]; references: Record<string, { title: string; url: string }>; statement: string;
};

export type Facets = { algorithm: string[]; primitive: string[]; service: string[]; band: string[]; confidence_level: string[] };

async function j<T>(path: string, init?: RequestInit): Promise<T> {
  let r: Response;
  const headers = { ...authHeaders(path), ...(init?.headers as Record<string, string> | undefined) };
  try { r = await fetch(API + path, { ...init, headers }); } catch { throw new Error(`Cannot reach the backend at ${API}. Is it running?`); }
  const body = await r.json().catch(() => null);
  if (!r.ok) {
    const d = body?.detail;
    throw new Error(body?.error?.message ?? (typeof d === "string" ? d : `Request failed (HTTP ${r.status})`));
  }
  return body as T;
}

/** Authenticated download (report / CSV): links cannot send the token header, so fetch the file and save it. */
async function download(path: string, filename: string): Promise<void> {
  let r: Response;
  try { r = await fetch(API + path, { headers: authHeaders(path) }); } catch { throw new Error(`Cannot reach the backend at ${API}. Is it running?`); }
  if (!r.ok) {
    const body = await r.json().catch(() => null);
    throw new Error(body?.error?.message ?? `Download failed (HTTP ${r.status})`);
  }
  const url = URL.createObjectURL(await r.blob());
  const a = document.createElement("a");
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export const api = {
  demo: async () => {
    const s = await j<Summary & { access_token?: string }>("/api/demo/acme", { method: "POST" });
    rememberToken(s.scan.id, s.access_token);
    return s as Summary;
  },
  upload: async (file: File) => {
    const up = await j<{ scan_id: string; access_token?: string; stats: { file_count: number } }>(`/api/scans?filename=${encodeURIComponent(file.name)}`,
      { method: "POST", headers: { "Content-Type": "application/octet-stream" }, body: file });
    rememberToken(up.scan_id, up.access_token);
    return up;
  },
  analyze: (id: string) => j<Summary>(`/api/scans/${id}/analyze`, { method: "POST" }),
  summary: (id: string) => j<Summary>(`/api/scans/${id}/summary`),
  findings: (id: string, qs: string) => j<{ findings: Card[]; count: number; total_all: number; facets: Facets }>(`/api/scans/${id}/findings?${qs}`),
  downloadCsv: (id: string, qs: string) => download(`/api/scans/${id}/findings.csv?${qs}`, `qmc-findings-${id.slice(0, 8)}.csv`),
  downloadReport: (id: string) => download(`/api/scans/${id}/report.md`, `qmc-report-${id.slice(0, 8)}.md`),
  migration: (id: string) => j<{ rows: PlanRow[]; crypto_agility: string[]; honesty: string[]; qmp_label: string }>(`/api/scans/${id}/migration`),
  finding: (id: string, fid: string) => j<Detail>(`/api/scans/${id}/findings/${fid}`),
  suppress: (id: string, fid: string, reason: string) => j<Detail>(`/api/scans/${id}/findings/${fid}/suppress`,
    { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ reason, author: "demo-user" }) }),
  unsuppress: (id: string, fid: string) => j<Detail>(`/api/scans/${id}/findings/${fid}/suppress`, { method: "DELETE" }),
  graph: (id: string) => j<GraphData>(`/api/scans/${id}/graph`),
  readiness: (id: string) => j<Readiness>(`/api/scans/${id}/readiness`),
  simulate: (id: string, node: string, target?: string | null) =>
    j<Simulation>(`/api/scans/${id}/simulate?node=${encodeURIComponent(node)}${target ? `&target=${encodeURIComponent(target)}` : ""}`),
  blastRadius: (id: string, node: string) =>
    j<BlastRadius>(`/api/scans/${id}/graph/blast-radius?node=${encodeURIComponent(node)}`),
};
