# QMC demo script (5-8 minutes)

All numbers below come from the REAL scanner and risk engine on the bundled fictional **Acme Payments** repository
(`sample-repos/acme-payments`). Nothing is mocked. Re-run `pytest` to confirm them.

**Setup:** `docker compose up --build` (or see README "Run locally"), open http://localhost:5173.

| # | Screen / action | What to say | What the audience sees (real output) |
|---|---|---|---|
| 1 | **Repository Scanner** -> "Load Acme Payments demo" | "Upload a repo. It is validated, extracted as inert data, secrets redacted. Uploaded code is never executed." | Steps light up; "Scan complete": 19 crypto findings, 10 quantum-vulnerable, 5 critical; "Rules that fired" ticker |
| 2 | **Dashboard** | "Where is our cryptography, and what is exposed?" | KPIs: 19 assets, 10 quantum-vulnerable, 5 critical, 3 elevated HNDL, 3 services, 1 already post-quantum. Bands: Critical 5 / Review 8 / Informational 6 |
| 3 | **Crypto Inventory**, filter *Quantum: vulnerable only* | "This is more than 'RSA detected'. Every row has file, line, evidence and confidence." | Rows with algorithm, operation, service, `file:line`, confidence |
| 4 | Open the top finding (**ECDH key agreement, payment-api**) | "Evidence snippet, five transparent risk factors, and a separate harvest-now-decrypt-later flag." | Snippet with highlighted line; QE 4, DS 4, IE 3, BC 3, MC 2 -> raw 22 -> **QMP 20 Critical**; **HNDL elevated** (10-year data) |
| 5 | Inventory with *test paths* ticked, open `scripts/gen_test_keys.py` | "Same RSA, very different priority. Context matters." | **Review, QMP 9** vs **Critical 20** for payment-api. Dev script lives in a low-sensitivity, internal service |
| 6 | Open the **SHA-1** finding (settlement-worker) and the **AES-256-GCM** finding | "Honest classification: SHA-1 is a classical hygiene issue; AES is not quantum-vulnerable." | SHA-1 capped at **Review** ("classical hygiene"); AES **Informational**, "no PQC migration required" |
| 7 | **Migration Planner** | "Role-aware, deterministic rules. Never 'RSA -> ML-KEM' blindly." | ECDH -> ML-KEM (FIPS 203) with hybrid steps; ECDSA -> ML-DSA / SLH-DSA; AES / SHA / HMAC: no PQC mapping; undetermined roles go to manual review |
| 8 | Back on Dashboard -> **Download report (Markdown)** | "Evidence-backed report with limitations." | Executive summary, inventory, evidence + factor tables, roadmap, **limitations**, rule versions |
| 9 | Close | "Discover your cryptography. Understand your quantum exposure. Plan your migration." | |

## Honest talking points (say these, judges like them)
- Static analysis only; low/medium-confidence findings require human review. Comment/doc mentions are Low and never counted as vulnerable.
- QMP is an internal prototype methodology: not NIST, not CVSS, not a certification. RSA/ECC are quantum-vulnerable to a *future* computer, not broken today.
- The scanner, risk engine and migration rules contain **no AI**. (The AI Copilot is not part of this build.)
- Every Critical in payment-api is expected: the 06 formula scores any high-confidence public-key use in a highly-sensitive, internet-facing, critical service at 15+.

## Not in this build (say so if asked)
Dependency graph / blast radius, PQC Lab (liboqs), AI Copilot, PDF report. See README "Status".
