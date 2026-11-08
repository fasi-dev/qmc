/** Dependency graph page end-to-end against the real backend started by vitest.global.ts (real scanner output). */
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
import App from "./App";

const BACKEND = "http://127.0.0.1:8031";
afterEach(() => cleanup());

const node = (id: string) =>
  ([...document.querySelectorAll("[data-node]")].find((el) => el.getAttribute("data-node") === id) ?? null) as SVGGElement | null;

describe("dependency graph", () => {
  beforeAll(async () => {
    localStorage.clear();
    const r = await fetch(`${BACKEND}/api/demo/acme`, { method: "POST" });
    const s = await r.json();
    localStorage.setItem("qmc.scanId", s.scan.id);
    localStorage.setItem("qmc.tokens", JSON.stringify({ [s.scan.id]: s.access_token }));
  });

  it("renders real nodes with accessible names and a legend", async () => {
    window.location.hash = "#/graph";
    render(<App />);
    await waitFor(() => expect(node("algorithm:ECDSA")).toBeTruthy(), { timeout: 15000 });
    expect(screen.getByRole("link", { name: "Dependency Graph" })).toBeTruthy();
    const ecdsa = node("algorithm:ECDSA")!;
    expect(ecdsa.getAttribute("role")).toBe("button");
    // roving tabindex: exactly one node is in the Tab order
    expect(document.querySelectorAll('[data-node][tabindex="0"]').length).toBe(1);
    expect(ecdsa.getAttribute("aria-label")).toMatch(/Algorithm ECDSA\. \d+ finding\(s\) · quantum-vulnerable/);
    expect(node("file:src/api/app.py")).toBeTruthy();                               // a dependent (import-only) file
    expect(node("file:README.md")).toBeNull();                                      // doc mentions are not graph evidence
    expect(screen.getByLabelText("Legend").textContent).toMatch(/confirmed.*inferred/);
    expect(screen.getByText("dependent files")).toBeTruthy();
  });

  it("keyboard selection shows the evidence-backed blast radius (direct + transitive)", async () => {
    window.location.hash = "#/graph";
    render(<App />);
    await waitFor(() => expect(node("algorithm:ECDSA")).toBeTruthy(), { timeout: 15000 });
    fireEvent.keyDown(node("algorithm:ECDSA")!, { key: "Enter" });
    const panel = await screen.findByRole("region", { name: "Blast radius" }, { timeout: 15000 });
    expect(within(panel).getByText(/Directly affected \(\d+\)/)).toBeTruthy();
    expect(panel.textContent).toMatch(/src\/auth\.py/);
    const indirect = within(panel).getByText("src/api/app.py").closest("li")!;
    expect(indirect.textContent).toMatch(/confirmed/);
    expect(indirect.textContent).toMatch(/depth 2/);
    expect(indirect.textContent).toMatch(/src\/api\/routes\.py:2/);                 // import evidence, file:line
    expect(panel.textContent).toMatch(/does not prove/);                            // honest meaning of "indirect"
    expect(window.location.hash).toBe(`#/graph/${encodeURIComponent("algorithm:ECDSA")}`);   // shareable link
    expect(node("algorithm:ECDSA")!.getAttribute("aria-pressed")).toBe("true");
    expect(node("file:src/api/app.py")!.getAttribute("class")).toMatch(/\bindirect\b/);
  });

  it("focus mode shows only the blast radius; search lists and selects matches", async () => {
    window.location.hash = `#/graph/${encodeURIComponent("algorithm:ECDH")}`;
    render(<App />);
    await screen.findByRole("region", { name: "Blast radius" }, { timeout: 15000 });
    fireEvent.click(screen.getByRole("button", { name: "Show only blast radius" }));
    await waitFor(() => expect(node("file:src/api/routes.py")).toBeNull());         // routes.py does not import keys.py
    expect(node("file:src/payments/keys.py")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Show whole graph" }));
    await waitFor(() => expect(node("file:src/api/routes.py")).toBeTruthy());
    fireEvent.change(screen.getByPlaceholderText(/file, algorithm, library/), { target: { value: "refunds" } });
    const results = (await screen.findByText(/match\(es\)/)).closest(".search-results") as HTMLElement;
    const match = within(results).getByRole("button", { name: /src\/payments\/refunds\.py/ });
    expect(node("file:src/payments/refunds.py")!.getAttribute("class")).toMatch(/\bmatch\b/);
    fireEvent.click(match);
    await waitFor(() => expect(screen.getByRole("heading", { name: "src/payments/refunds.py" })).toBeTruthy());
  });

  it("arrow keys move focus between nodes; left/right follows connections", async () => {
    window.location.hash = "#/graph";
    render(<App />);
    await waitFor(() => expect(node("algorithm:ECDSA")).toBeTruthy(), { timeout: 15000 });
    const start = document.querySelector('[data-node][tabindex="0"]') as SVGGElement;
    start.focus();
    fireEvent.keyDown(start, { key: "ArrowDown" });
    await waitFor(() => expect(document.querySelector('[data-node][tabindex="0"]')).not.toBe(start));
    const second = document.querySelector('[data-node][tabindex="0"]') as SVGGElement;
    expect(second.getAttribute("data-node")).toMatch(/^algorithm:/);                 // same column
    fireEvent.keyDown(second, { key: "ArrowLeft" });                                 // into the file column, via an edge
    await waitFor(() => expect(document.querySelector('[data-node][tabindex="0"]')!.getAttribute("data-node")).toMatch(/^file:/));
    const file = document.querySelector('[data-node][tabindex="0"]') as SVGGElement;
    fireEvent.keyDown(file, { key: "Enter" });
    expect(await screen.findByText(/^Relationships \(\d+\)$/, {}, { timeout: 15000 })).toBeTruthy();
  });

  it("zoom and fit controls change the view transform", async () => {
    window.location.hash = "#/graph";
    render(<App />);
    await waitFor(() => expect(node("algorithm:ECDSA")).toBeTruthy(), { timeout: 15000 });
    const g = () => document.querySelector(".graph-canvas svg > g")!.getAttribute("transform");
    const before = g();
    fireEvent.click(screen.getByRole("button", { name: "Zoom in" }));
    await waitFor(() => expect(g()).not.toBe(before));
    fireEvent.click(screen.getByRole("button", { name: "Fit to screen" }));
    await waitFor(() => expect(g()).toBe(before));
  });

  it("shows an error state when the scan is not accessible", async () => {
    localStorage.setItem("qmc.tokens", "{}");
    window.location.hash = "#/graph";
    render(<App />);
    expect(await screen.findByText("No scan yet", {}, { timeout: 15000 })).toBeTruthy();   // token gone: treated as no access
  });
});
