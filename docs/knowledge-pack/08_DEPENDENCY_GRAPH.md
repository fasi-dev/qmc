# 08_DEPENDENCY_GRAPH.md

Dependency-aware analysis: the bridge between *findings* and *migration impact*.

## 1. Purpose

Answer the user's real question: **"Why does this crypto finding matter?"**

Example chain the graph must render:

```
Payment API (service)
  └─CONTAINS→ src/auth.py (file)
      └─CALLS→ sign_token() (function)
          └─USES_CRYPTO→ ECDSA (primitive, CRYPTO-007)
              └─SIGNS→ JWT (protocol)
                  └─AUTHENTICATES→ customer sessions (data/asset)
```

## 2. Node types

| Node type | Key properties |
|---|---|
| `repository` | name, url/commit hash (if known) |
| `application` | name, owner |
| `service` | owner, data_classification, business_criticality, internet_exposed, data_lifetime_years |
| `module` | package/module name |
| `file` | path, language |
| `function` | name, enclosing file |
| `library_package` | name, version (from manifests where parsed) |
| `cryptographic_primitive` | algorithm, primitive category, quantum_vulnerable |
| `finding` | reference to full finding record (`05` schema) |
| `protocol` | TLS, SSH, JWT, … |
| `certificate` | subject hint, expiry (parsed PEM blocks) |
| `data_asset` | classification, lifetime |

## 3. Edge types

`CONTAINS`, `IMPORTS`, `CALLS`, `USES_CRYPTO`, `USES_PROTOCOL`, `DEPENDS_ON`,
`PROTECTS`, `SIGNS`, `VERIFIES`, `AUTHENTICATES`, `CONNECTS_TO`.

Edge derivation (static, best-effort):
- `CONTAINS`: filesystem/module structure.
- `IMPORTS`: import statements (AST) + manifest dependencies (`DEPENDS_ON` for packages).
- `CALLS`: intra-repo call edges from AST (enclosing-function resolution).
- `USES_CRYPTO`: finding → enclosing function/file/service.
- `USES_PROTOCOL` / `CONNECTS_TO`: from config (nginx upstreams, TLS server blocks, env URLs).
- `SIGNS`/`VERIFIES`/`AUTHENTICATES`/`PROTECTS`: from finding operation + context metadata (`05` §8).

## 4. Storage & serving

- Backend: **NetworkX** (in-memory) built per scan; persisted edge list to SQLite tables
  `nodes(id, scan_id, type, props_json)`, `edges(scan_id, src, dst, type, props_json)`.
- API: `GET /scans/{id}/graph?focus=CRYPTO-007` → subgraph (2-hop neighborhood).
- Frontend: **React Flow** (or Cytoscape) with node coloring by primitive category and
  border color by QMP band.

## 5. Migration Blast Radius

For a given finding/primitive, estimate the scope of a migration touching it:

```
blast_radius(primitive P) =
  directly_affected:    services where USES_CRYPTO edges reach P
  dependent_modules:    modules CALLS/IMPORTS-reaching those services' crypto call sites
  protocols:            distinct protocols on USES_PROTOCOL edges of affected services
  data_assets:          data assets on PROTECTS/AUTHENTICATES paths through P
  downstream_packages:  library_package nodes DEPENDS_ON-reachable from affected services
```

Rendered as five counts + a subgraph view. Example output:

```
Blast radius of ECDH (payment-api):
  directly affected services: 2  (payment-api, settlement-worker)
  dependent modules:          5
  protocols:                  TLS 1.2, gRPC-internal
  data assets:                cardholder sessions, settlement records
  downstream packages:        internal-sdk, crypto-utils
```

## 6. Honesty statement (rendered in UI and report)

> "The dependency graph and blast radius are **estimates derived from static analysis**.
> Dynamic dispatch, external services, runtime configuration, and incomplete manifests
> mean the true enterprise dependency map may be larger. Treat these views as migration
> planning aids, not exhaustive inventories — validate with your teams."

## 7. Performance

- Acme Payments graph (~200 nodes, ~600 edges) must render in < 2 s and lay out client-side.
- Graph endpoints paginate: default 2-hop expansion; full-graph mode caps at 2000 nodes.
