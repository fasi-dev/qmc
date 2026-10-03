import { Fragment, useEffect, useState } from "react";
import { api, type PlanRow } from "./api";
import { Band, Badge, pretty } from "./ui";

export default function Planner({ scanId }: { scanId: string }) {
  const [data, setData] = useState<Awaited<ReturnType<typeof api.migration>> | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [svc, setSvc] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  useEffect(() => { api.migration(scanId).then(setData).catch((e: Error) => setError(e.message)); }, [scanId]);
  if (error) return <p className="error" role="alert">{error}</p>;
  if (!data) return <p className="dim">Loading…</p>;
  const services = [...new Set(data.rows.map((r) => r.service))].sort();
  const rows: PlanRow[] = data.rows.filter((r) => !svc || r.service === svc);

  return (
    <div>
      <div className="callout" role="note">
        <b>Candidate directions, not certifications.</b> These recommendations come from deterministic migration rules and require human security review.
        Key establishment maps to ML-KEM (FIPS 203); signatures map to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205); AES, hashes and MACs have no PQC mapping.
      </div>
      <div className="row">
        <label className="fld">Service
          <select value={svc} onChange={(e) => setSvc(e.target.value)}><option value="">All services</option>{services.map((s) => <option key={s}>{s}</option>)}</select>
        </label>
        <span className="fine">{rows.length} rows, ordered by priority. Click a row for caveats and steps.</span>
      </div>
      <table className="tbl inv">
        <thead><tr><th>Priority</th><th>Current crypto</th><th>Role</th><th>PQC candidate</th><th>Service</th><th>Complexity</th><th>Next step</th></tr></thead>
        <tbody>
          {rows.map((r) => (
            <Fragment key={r.id}>
              <tr className="click" onClick={() => setOpen(open === r.id ? null : r.id)}>
                <td><Band band={r.band} qmp={r.qmp} /></td>
                <td><b>{r.algorithm}</b> <span className="dim">{pretty(r.operation)}</span><br /><code className="fine">{r.file}:{r.line_start}</code></td>
                <td>{r.role ?? "—"}</td>
                <td className={r.no_pqc_mapping ? "dim" : ""}>{r.direction}{r.rule_id && <span className="dim"> · {r.rule_id}</span>}</td>
                <td>{r.service}</td>
                <td>{r.complexity ?? "—"}</td>
                <td>{r.steps[0] ?? "—"} {r.human_review && <Badge tone="warn">human review</Badge>}</td>
              </tr>
              {open === r.id && (
                <tr className="detailrow"><td colSpan={7}>
                  {r.note && <p className="callout">{r.note}</p>}
                  {r.why && <p><b>Why:</b> {r.why}</p>}
                  {r.caveats.length > 0 && <><b>Caveats</b><ul>{r.caveats.map((c) => <li key={c}>{c}</li>)}</ul></>}
                  {r.interoperability && <p><b>Interoperability:</b> {r.interoperability}</p>}
                  {r.steps.length > 0 && <><b>Steps</b><ol>{r.steps.map((s) => <li key={s}>{s}</li>)}</ol></>}
                  {r.human_review_note && <p className="fine">Human review {r.human_review_note}</p>}
                  <a href={`#/finding/${r.id}`}>Open finding →</a>
                </td></tr>
              )}
            </Fragment>
          ))}
        </tbody>
      </table>
      <section className="panel">
        <h3>Crypto-agility recommendations (included in every plan)</h3>
        <ol>{data.crypto_agility.map((c) => <li key={c}>{c}</li>)}</ol>
        <h3>Honesty notes</h3>
        <ul>{data.honesty.map((c) => <li key={c}>{c}</li>)}</ul>
      </section>
    </div>
  );
}
