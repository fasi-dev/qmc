# Cryptographic dependency graph and blast radius

*Implemented on `feature/dependency-graph` (engine 0.4.0; resolution refined in the following commits). Spec: `docs/knowledge-pack/08_DEPENDENCY_GRAPH.md`;
deviations are listed at the end.*

## What it answers

For any algorithm, library, finding or file: which files use it **directly**, which files **depend on** those
files through imports (transitively), which components (services) are involved, which findings and severities are
in scope, which migration rules apply, and **the evidence for every relationship**.

## Where the relationships come from

| Edge | Meaning | Source of evidence | Confidence |
|---|---|---|---|
| `service CONTAINS file` | file belongs to a component | nearest `service.yaml` (else repository default) | confirmed |
| `file CONTAINS finding` | detection in this file | the finding (rule id, line, evidence) | confirmed |
| `finding USES algorithm` | API call uses this algorithm | the finding | confirmed |
| `finding USES library` | API call belongs to this library | the finding | confirmed |
| `file IMPORTS library` | import statement of a known crypto library | `file:line` of the import | confirmed |
| `file IMPORTS file` | import statically resolved to exactly one repository file | `file:line` of the import | confirmed |
| `file IMPORTS file` | ambiguous match (several candidates, or a bare name outside the importer's directory) or Java wildcard `import a.b.*` | `file:line` + candidate count | **inferred** |

Imports are extracted by the scanner (`scanner/qmc_scanner/imports.py`): Python with `ast`, Java and JS/TS with the
existing comment/string-aware lexer (imports in comments and strings are ignored; code inside template-literal
interpolations is code). Nothing is executed, imported or installed.

Resolution rules:
* Python: relative imports from the importing package; absolute imports by module-path suffix, decided per module
  (unique = resolved, several = ambiguous; a bare top-level name only resolves in the importer's directory).
  `from a.b import sub, attr` targets both `a/b/sub.py` and the module `a.b`.
* JS/TS: relative specifiers with extension, `index.*` and TS-ESM `.js -> .ts` resolution; bare specifiers through
  the nearest `tsconfig.json` / `jsconfig.json` `compilerOptions.paths` and `baseUrl` (TypeScript match priority;
  `extends` is not followed). Import clauses longer than 600 characters are not matched.
* Java: imports by fully-qualified class path (static imports drop the member; `a.b.*` is a wildcard = inferred);
  **same-package type references** (no import needed in Java) from masked code, shadowed by an explicit single-type
  import of the same simple name; at most 5,000 distinct type names per file (exceeding it is reported).

Only files on a path to cryptographic usage are included (files with findings, files importing a crypto
library, and their transitive importers). Unrelated files are left out, which keeps the graph focused.

## Blast radius

* **Direct**: files containing the selected usage (or importing the selected library), each with its reasons and
  evidence.
* **Indirect**: reverse import closure from the direct files (breadth-first, cycle-safe, capped at 25 levels; hitting
  the cap is reported). An indirect file **depends on** affected code; static imports do **not** prove that the
  cryptographic code path is called.
* **Confirmed vs inferred**: an indirect file is confirmed only if a chain of confirmed edges reaches it; otherwise it
  is inferred (reachable only through an ambiguous or wildcard import).
* Also returned: components (direct / via imports), related findings, severity distribution, HNDL count, migration
  rules from `07` with finding/file counts, the migration-complexity factor values, and limitations. **No effort,
  time or percentage estimates** are produced.

## Known limits (shown in the UI and report)

Dynamic imports with computed names, runtime import machinery, reflection, dependency injection, TS/webpack path
aliases, Java same-package references (no import statement), calls across services or network APIs, and code not in
the uploaded archive. Unresolved relative imports are counted and reported. Comment/doc mentions and findings marked
as false positives are excluded (and counted).

## UI

Layered SVG layout (`frontend/src/graphLayout.ts`, deterministic, no graph library). Zoom/pan/fit, search with a
match list, type filters, focus on the blast radius, shareable `#/graph/<node>` links. Above 300 nodes only what
intersects the viewport is rendered. Keyboard: one node is in the Tab order (roving tabindex); arrow keys move within
a column (Up/Down/Home/End) or to a connected node in the adjacent column (Left/Right); Enter selects. Node details
list every relationship with its confidence and evidence, and link to the Migration Simulator.

## API

    GET /api/scans/{id}/graph                         -> {version, nodes, edges, stats, limitations}
    GET /api/scans/{id}/graph/blast-radius?node=<id>  -> {node, summary, direct, indirect, components, findings,
                                                          severity, migration, limitations, meaning}

Both need `X-QMC-Scan-Token`. Node ids look like `algorithm:ECDH`, `library:cryptography`, `finding:CRYPTO-007`,
`file:src/auth.py`. Errors: 404 unknown scan/node, 422 invalid id or a non-selectable node (services), 409 scan not
analyzed. Paths are repository-relative; no server paths are returned. Graphs are cached per scan state (analysis
run + suppression state).

## Storage and compatibility

Import records are stored in a new nullable JSON column `scans.graph`, added automatically by the existing
additive schema upgrade (`app/db.py:upgrade_schema`). No data is changed or deleted. Scans analyzed before this
feature have `graph = NULL`: they still get a graph of direct usage, with an explicit "re-scan to see indirect
impact" limitation.

## Try it on a real scan

1. Start backend + frontend (README), open **Repository Scanner -> Load Acme Payments demo**.
2. Open **Dependency Graph**. Select **ECDSA** (click or Tab + Enter): direct `src/auth.py` and
   `src/java/TokenSigner.java`; indirect `src/api/routes.py` (depth 1) and `src/api/app.py` (depth 2, via
   `src/api/routes.py:2` and `src/api/app.py:2`).
3. Select **ECDH**: no indirect files (nothing imports `src/payments/keys.py`). Toggle **Show only blast radius**.
4. Select the AES finding in `src/payments/settle.py` (enable *Individual findings*): `refunds.py`, `routes.py`,
   `app.py` depend on it.
5. Upload your own repository archive and repeat; the report (Download report) has the same data in section 8.

## Deviations from `08_DEPENDENCY_GRAPH.md` (and why)

* **No NetworkX / React Flow / Cytoscape.** Graph algorithms are BFS over adjacency lists; the UI is a plain SVG
  renderer with a deterministic layered layout. No new runtime dependencies and no lockfile churn.
* **No `CALLS` edges.** A call graph needs cross-file name resolution that the scanner does not do reliably;
  imports are the strongest relationship it can establish without guessing.
* **No protocol, data-asset or downstream-package counts.** There is no evidence source for them yet (no
  dependency-manifest parsing, no data-flow); they are not shown rather than invented.
* **One JSON column instead of `nodes`/`edges` tables.** The graph is derived data, rebuilt (and cached) from
  findings + stored import records, so suppressions are always reflected.
* **No server-side 2-hop pagination / 2000-node cap.** The graph contains only crypto-relevant files; the UI offers
  type filters, search and blast-radius focus for large scans instead of silently truncating. Measured on a synthetic
  10,000-file repository (1,000 crypto files, 28k imports): 13k nodes / 47k edges, graph build + scan 2.8 s,
  blast radius 80-130 ms, simulation 0.3 s; the 20 MB graph JSON is gzip-compressed on the wire (~20x). Above 300
  nodes the canvas renders only nodes in view, and the blast-radius panel lists the first 150 entries per list
  until "Show all" (headings always give the full counts).
