/** Real end-to-end UI test: React app in jsdom talking to a real backend (see vitest.global.ts). */
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import App from "./App";

const go = (h: string) => { window.location.hash = h; };
afterEach(() => cleanup());

describe("demo flow: scan -> dashboard -> inventory -> finding detail", () => {
  beforeAll(() => { localStorage.clear(); });

  it("shows an empty state before any scan", async () => {
    go("#/dashboard");
    render(<App />);
    expect(await screen.findByText("No scan yet")).toBeTruthy();
    await waitFor(() => expect(screen.getByText(/Backend: connected/)).toBeTruthy());
  });

  it("loads Acme Payments through real ingestion + scan + risk scoring", async () => {
    go("#/scanner");
    render(<App />);
    fireEvent.click(await screen.findByText("Load Acme Payments demo"));
    expect(await screen.findByText("Scan complete", {}, { timeout: 20000 })).toBeTruthy();
    expect(screen.getByText(/crypto findings/)).toBeTruthy();
    expect(screen.getByText(/Rules that fired/)).toBeTruthy();
    expect(localStorage.getItem("qmc.scanId")).toMatch(/^[0-9a-f-]{36}$/);
  });

  it("dashboard shows real KPIs, band distribution, ranked findings and services", async () => {
    go("#/dashboard");
    render(<App />);
    expect(await screen.findByText("crypto assets found")).toBeTruthy();
    expect(screen.getByText("quantum-vulnerable")).toBeTruthy();
    expect(screen.getByText("elevated HNDL risk")).toBeTruthy();
    const top = await screen.findByText("Highest-priority findings");
    const table = top.closest("section")!.querySelector("table")!;
    const first = within(table).getAllByRole("row")[1];
    expect(first.textContent).toMatch(/Critical · 20/);
    expect(first.textContent).toMatch(/ECDH/);
    expect(first.textContent).toMatch(/HNDL elevated/);
    expect(screen.getByText("Services and migration status")).toBeTruthy();
    expect(screen.getByText("settlement-worker")).toBeTruthy();
    expect(document.body.textContent).toMatch(/not a security certification/i);
    expect(document.body.textContent).toMatch(/Static-analysis estimates\. Not a certification\./);
  });

  it("inventory lists findings, filters by band and searches evidence", async () => {
    go("#/inventory");
    render(<App />);
    await waitFor(() => expect(document.querySelectorAll("table.inv tbody tr.click").length).toBeGreaterThan(10));
    const bandSel = screen.getByLabelText("Priority") as HTMLSelectElement;
    await waitFor(() => expect(bandSel.options.length).toBeGreaterThan(1));
    fireEvent.change(bandSel, { target: { value: "Critical" } });
    await waitFor(() => {
      const rows = [...document.querySelectorAll("table.inv tbody tr.click")];
      expect(rows.length).toBeGreaterThan(0);
      expect(rows.every((r) => /Critical/.test(r.textContent ?? ""))).toBe(true);
    });
    fireEvent.change(bandSel, { target: { value: "" } });
    fireEvent.change(screen.getByPlaceholderText(/file, algorithm/), { target: { value: "x25519" } });
    await waitFor(() => expect(document.querySelectorAll("table.inv tbody tr.click").length).toBe(1));
    expect(document.querySelector("table.inv tbody")!.textContent).toMatch(/keys\.py/);
    // hidden-by-default test path appears only when asked for
    fireEvent.change(screen.getByPlaceholderText(/file, algorithm/), { target: { value: "gen_test_keys" } });
    await waitFor(() => expect(screen.getByText(/No findings match/)).toBeTruthy());
    fireEvent.click(screen.getByLabelText("test paths"));
    await waitFor(() => expect(document.querySelector("table.inv tbody")!.textContent).toMatch(/gen_test_keys/));
  });

  it("finding detail shows evidence snippet, factor breakdown, HNDL and false-positive action", async () => {
    go("#/inventory");
    render(<App />);
    fireEvent.change(await screen.findByPlaceholderText(/file, algorithm/), { target: { value: "x25519" } });
    await waitFor(() => expect(document.querySelectorAll("table.inv tbody tr.click").length).toBe(1));
    fireEvent.click(document.querySelector("table.inv tbody tr.click")!);
    expect(await screen.findByText("Evidence")).toBeTruthy();
    const code = await screen.findByLabelText("Source snippet");
    expect(code.textContent).toMatch(/X25519PrivateKey\.generate\(\)/);
    expect(code.querySelector(".ln.hot")).toBeTruthy();
    for (const k of ["QE · Quantum exposure", "DS · Data sensitivity", "IE · Internet exposure", "BC · Business criticality", "MC · Migration complexity"]) {
      expect(screen.getByText(new RegExp(k))).toBeTruthy();
    }
    expect(document.body.textContent).toMatch(/harvest-now-decrypt-later/i);
    expect(document.body.textContent).toMatch(/QMP\s*20/);
    expect(screen.getByText(/internal prototype prioritization methodology/)).toBeTruthy();
    expect(screen.getByText("Mark false positive")).toBeTruthy();
  });

  it("marking a false positive records it, hides it from default views, and can be restored", async () => {
    vi.spyOn(window, "prompt").mockReturnValue("demo: confirmed unused");
    go("#/inventory");
    render(<App />);
    fireEvent.change(await screen.findByPlaceholderText(/file, algorithm/), { target: { value: "x25519" } });
    await waitFor(() => expect(document.querySelectorAll("table.inv tbody tr.click").length).toBe(1));
    fireEvent.click(document.querySelector("table.inv tbody tr.click")!);
    fireEvent.click(await screen.findByText("Mark false positive"));
    expect(await screen.findByText(/Marked false positive by/)).toBeTruthy();
    expect(screen.getByText("Restore finding")).toBeTruthy();
    fireEvent.click(screen.getByText("← Inventory"));
    fireEvent.change(await screen.findByPlaceholderText(/file, algorithm/), { target: { value: "x25519" } });
    await waitFor(() => expect(screen.getByText(/No findings match/)).toBeTruthy());
    fireEvent.click(screen.getByLabelText("suppressed"));
    await waitFor(() => expect(document.querySelectorAll("table.inv tbody tr.click").length).toBe(1));
    fireEvent.click(document.querySelector("table.inv tbody tr.click")!);
    fireEvent.click(await screen.findByText("Restore finding"));
    await waitFor(() => expect(screen.getByText("Mark false positive")).toBeTruthy());
  });

  it("finding detail shows the deterministic migration candidate (role-aware, human review)", async () => {
    go("#/inventory");
    render(<App />);
    fireEvent.change(await screen.findByPlaceholderText(/file, algorithm/), { target: { value: "x25519" } });
    await waitFor(() => expect(document.querySelectorAll("table.inv tbody tr.click").length).toBe(1));
    fireEvent.click(document.querySelector("table.inv tbody tr.click")!);
    expect(await screen.findByText("Migration candidate")).toBeTruthy();
    expect(document.body.textContent).toMatch(/ML-KEM \(FIPS 203\)/);
    expect(document.body.textContent).toMatch(/KEM -> KDF -> symmetric/);
    expect(document.body.textContent).toMatch(/Requires human review/);
  });

  it("migration planner: KE -> ML-KEM, signatures -> ML-DSA/SLH-DSA, AES/SHA have no PQC mapping", async () => {
    go("#/planner");
    render(<App />);
    await waitFor(() => expect(document.querySelectorAll("table.inv tbody tr.click").length).toBeGreaterThan(8));
    const text = document.querySelector("table.inv tbody")!.textContent ?? "";
    expect(text).toMatch(/ML-KEM \(FIPS 203\)/);
    expect(text).toMatch(/ML-DSA \(FIPS 204\) or SLH-DSA \(FIPS 205\)/);
    expect(text).toMatch(/No PQC migration required/);
    const aes = [...document.querySelectorAll("table.inv tbody tr.click")].find((r) => /AES/.test(r.textContent ?? ""))!;
    expect(aes.textContent).not.toMatch(/ML-KEM|ML-DSA/);
    fireEvent.click(document.querySelector("table.inv tbody tr.click")!);
    expect(document.querySelector(".detailrow")).toBeTruthy();
    expect(screen.getByText(/Candidate directions, not certifications/)).toBeTruthy();
    expect(screen.getByText(/Crypto-agility recommendations/)).toBeTruthy();
  });
});
