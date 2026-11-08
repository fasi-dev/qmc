/** PQC Readiness + Migration Simulator pages end-to-end against the real backend (vitest.global.ts). */
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
import App from "./App";

const BACKEND = "http://127.0.0.1:8031";
afterEach(() => cleanup());

describe("PQC readiness and migration simulator", () => {
  beforeAll(async () => {
    localStorage.clear();
    const s = await (await fetch(`${BACKEND}/api/demo/acme`, { method: "POST" })).json();
    localStorage.setItem("qmc.scanId", s.scan.id);
    localStorage.setItem("qmc.tokens", JSON.stringify({ [s.scan.id]: s.access_token }));
  });

  it("readiness shows the rule-based level, evidence-backed blockers and ordered recommendations", async () => {
    window.location.hash = "#/readiness";
    render(<App />);
    expect(await screen.findByRole("heading", { name: "Not ready: critical blockers" }, { timeout: 15000 })).toBeTruthy();
    const blockers = screen.getByRole("heading", { name: "Critical blockers" }).closest("section")!;
    expect(within(blockers).getByText("Harvest-now-decrypt-later exposure", { exact: false })).toBeTruthy();
    expect(blockers.textContent).toMatch(/src\/payments\/keys\.py:\d+/);              // file:line evidence
    const recs = screen.getByRole("heading", { name: "Prioritized recommendations" }).closest("section")!;
    const prios = [...recs.querySelectorAll(".prio")].map((p) => Number(p.textContent!.slice(1)));
    expect(prios).toEqual([...prios].sort((a, b) => a - b));
    expect(within(recs).getAllByRole("link", { name: "Simulate migration" })[0].getAttribute("href")).toBe(`#/simulate/${encodeURIComponent("algorithm:ECDH")}`);
    expect(document.body.textContent).not.toMatch(/\d+\s?%/);                          // no percentage score anywhere
    expect(document.body.textContent).toMatch(/No finding here does not mean the application is quantum-safe/);
    expect(screen.getByRole("heading", { name: "Cryptographic libraries" })).toBeTruthy();
    expect(screen.getByText(/How the level is decided/)).toBeTruthy();
  });

  it("workflow strip links the analysis steps", async () => {
    window.location.hash = "#/readiness";
    render(<App />);
    const flow = await screen.findByRole("navigation", { name: "Analysis workflow" });
    expect([...flow.querySelectorAll("li")].map((l) => l.textContent!.replace(/^\d/, ""))).toEqual(
      ["Scan", "Findings", "Dependency graph", "PQC readiness", "Migration simulator", "Report"]);
    expect(within(flow).getByRole("link", { current: "step" }).textContent).toMatch(/PQC readiness/);
  });

  it("simulator: ECDSA -> ML-DSA with dependents, call sites, sizes; target can be changed", async () => {
    window.location.hash = `#/simulate/${encodeURIComponent("algorithm:ECDSA")}`;
    render(<App />);
    const track = (await screen.findByRole("heading", { name: "Digital signatures" }, { timeout: 15000 })).closest("section")!;
    const select = within(track).getByLabelText("Target") as HTMLSelectElement;
    expect(select.value).toBe("ML-DSA-65");
    expect(track.textContent).toMatch(/3,309 bytes/);                                   // FIPS 204 signature size
    expect(track.textContent).toMatch(/src\/api\/app\.py/);                             // transitive dependent from the graph
    expect(track.textContent).toMatch(/src\/auth\.py:\d+/);                             // call site evidence
    expect(within(track).getAllByRole("img", { name: /architecture/ }).length).toBe(2);
    fireEvent.change(select, { target: { value: "SLH-DSA-SHA2-128s" } });
    await waitFor(() => expect(screen.getByRole("heading", { name: "Digital signatures" }).closest("section")!.textContent).toMatch(/7,856 bytes/),
                  { timeout: 15000 });
    expect(window.location.hash).toBe(`#/simulate/${encodeURIComponent("algorithm:ECDSA")}/SLH-DSA-SHA2-128s`);
    expect(document.body.textContent).toMatch(/does not change code and does not confirm compatibility/);
  });

  it("simulator: undetermined role proposes no target", async () => {
    window.location.hash = `#/simulate/${encodeURIComponent("file:scripts/gen_test_keys.py")}`;
    render(<App />);
    const track = (await screen.findByRole("heading", { name: "Public-key usage with undetermined role" }, { timeout: 15000 })).closest("section")!;
    expect(within(track).queryByLabelText("Target")).toBeNull();
    expect(track.textContent).toMatch(/role must be decided first/);
  });

  it("finding detail links into the graph and the simulator", async () => {
    const id = localStorage.getItem("qmc.scanId")!;
    const token = JSON.parse(localStorage.getItem("qmc.tokens")!)[id];
    const list = await (await fetch(`${BACKEND}/api/scans/${id}/findings`, { headers: { "X-QMC-Scan-Token": token } })).json();
    const fid: string = list.findings[0].id;                                           // a scored code finding
    window.location.hash = `#/finding/${fid}`;
    render(<App />);
    const sim = await screen.findByRole("link", { name: "Simulate migration" }, { timeout: 15000 });
    expect(sim.getAttribute("href")).toBe(`#/simulate/${encodeURIComponent(`finding:${fid}`)}`);
    expect(screen.getByRole("link", { name: "Show in dependency graph" }).getAttribute("href")).toBe(`#/graph/${encodeURIComponent(`finding:${fid}`)}`);
  });

  it("dashboard leads with the readiness level", async () => {
    window.location.hash = "#/dashboard";
    render(<App />);
    expect(await screen.findByRole("link", { name: "Open readiness assessment" }, { timeout: 15000 })).toBeTruthy();
    expect(screen.getByRole("heading", { name: "Not ready: critical blockers" })).toBeTruthy();
  });
});
