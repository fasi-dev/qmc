import { useEffect, useState } from "react";
import { api, type Detail } from "./api";
import { Band, Badge, Highlighted, pretty } from "./ui";

export default function FindingDetail({ scanId, fid }: { scanId: string; fid: string }) {
  const [d, setD] = useState<Detail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => { setD(null); api.finding(scanId, fid).then(setD).catch((e: Error) => setError(e.message)); }, [scanId, fid]);
  if (error) return <p className="error" role="alert">{error} <a href="#/inventory">Back to inventory</a></p>;
  if (!d) return <p className="dim">Loading…</p>;
  const { finding: f, risk: r, snippet: sn } = d;

  async function toggleSuppress() {
    try {
      if (d?.suppressed) setD(await api.unsuppress(scanId, fid));
      else {
        const reason = window.prompt("Why is this a false positive? (required; recorded with your name and time)");
        if (reason && reason.trim()) setD(await api.suppress(scanId, fid, reason.trim()));
      }
    } catch (e) { setError((e as Error).message); }
  }
  const copy = () => { void navigator.clipboard?.writeText(`${f.file}:${f.line_start}  ${f.evidence}`); setCopied(true); setTimeout(() => setCopied(false), 1500); };

  return (
    <div>
      <p className="crumb"><a href="#/inventory">← Inventory</a></p>
      <div className="panel head">
        <div>
          <h2>{f.algorithm} <span className="dim">{pretty(f.operation)}</span></h2>
          <p className="dim">{f.service} · <code>{f.file}:{f.line_start}</code> · {f.id}</p>
        </div>
        <div className="head-r">
          <Band band={d.band} qmp={d.qmp} />
          {r?.hndl.flag && <Badge tone="hndl">HNDL {r.hndl.severity}</Badge>}
          {f.already_pqc && <Badge tone="pqc">post-quantum</Badge>}
          {d.suppressed && <Badge tone="dim">suppressed</Badge>}
        </div>
      </div>

      {r?.hndl.flag && <div className="callout hndl" role="note">{r.hndl.text}</div>}
      {d.suppression && <div className="callout">Marked false positive by <b>{d.suppression.author}</b>: {d.suppression.reason}. Excluded from default views and scores; kept in the record.</div>}

      <div className="grid2">
        <section className="panel">
          <h3>Evidence</h3>
          {sn ? (
            <pre className="code" aria-label="Source snippet">{sn.lines.map((ln, i) => {
              const no = sn.start_line + i; const hot = no >= sn.highlight_start && no <= sn.highlight_end;
              return <div key={no} className={hot ? "ln hot" : "ln"}><span className="no">{no}</span><span><Highlighted line={ln} /></span></div>;
            })}</pre>
          ) : <p className="dim">Source snippet unavailable.</p>}
          <dl className="kv">
            <dt>Evidence string</dt><dd><code>{f.evidence}</code></dd>
            <dt>Location</dt><dd>{f.file}, lines {f.line_start}{f.line_end !== f.line_start && `–${f.line_end}`}</dd>
            <dt>Rule</dt><dd><code>{f.rule_id}</code> v{f.rule_version} · engine {f.engine_version}</dd>
            <dt>Library / API</dt><dd>{f.library ?? "—"} / {f.api ?? "—"}</dd>
            <dt>Role / context</dt><dd>{r?.role ?? "—"} / {f.context}</dd>
            {f.metadata.key_size != null && <><dt>Key size</dt><dd>{f.metadata.key_size} bits</dd></>}
          </dl>
          <div className="row">
            <button className="btn" onClick={copy}>{copied ? "Copied" : "Copy evidence"}</button>
            <button className="btn" onClick={() => void toggleSuppress()}>{d.suppressed ? "Restore finding" : "Mark false positive"}</button>
          </div>
        </section>

        <section className="panel">
          <h3>Confidence</h3>
          <p><b>{f.confidence_level}</b> ({f.confidence.toFixed(2)}){f.metadata.comment_only && " · comment/doc mention only (never above Low)"}</p>
          <p className="fine">High ≥ 0.90: resolved API call. Medium 0.50–0.89: partial context or config directive. Low &lt; 0.50: comments and docs.
            {f.confidence_level !== "high" && " Requires human review."}</p>
          <h3>Why this priority</h3>
          {r ? (
            <>
              {(["QE", "DS", "IE", "BC", "MC"] as const).map((k) => {
                const x = r.factors[k]; const max = { QE: 4, DS: 4, IE: 3, BC: 3, MC: 3 }[k];
                return (
                  <div className="factor" key={k}>
                    <div className="factor-h"><span>{k} · {x.label}</span><b>{x.value}<span className="dim"> / {max}</span></b></div>
                    <div className={`bar ${k === "MC" ? "neg" : ""}`}><i style={{ width: `${(x.value / max) * 100}%` }} /></div>
                    <p className="fine">{x.why} <span className="dim">[{x.source}]</span></p>
                  </div>);
              })}
              <p className="calc"><code>{r.formula}</code><br />raw = {r.raw} → QMP <b>{r.qmp}</b> → <b>{r.band_uncapped}</b>{r.band !== r.band_uncapped && <> → shown as <b>{r.band}</b></>}</p>
              {r.cap_reason && <p className="fine">{r.cap_reason}</p>}
              <p>{r.badges.map((b) => <Badge key={b} tone={b.startsWith("metadata") ? "warn" : "dim"}>{b}</Badge>)}</p>
              <p className="fine">{r.label}</p>
            </>
          ) : <p className="dim">Comment and documentation mentions are not scored: there is no executable evidence.</p>}
        </section>
      </div>
      <p className="fine">Static-analysis estimate from deterministic rules. Not a security certification.</p>
    </div>
  );
}
