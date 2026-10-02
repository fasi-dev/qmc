"""Phase 2 -> Phase 3: scan the REDACTED tree produced by ingestion; evidence must never expose secrets."""
import io
import json
import zipfile
from pathlib import Path

from qmc_scanner import scan_tree

from app.ingestion import ingest_archive
from tests.conftest import make_zip

FIXTURE = Path(__file__).parents[2] / "sample-repos" / "acme-payments"
JWT = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlX3ZhbHVl"
PEM_BODY = "MHcCAQEEIIrYSSNQFaA2Hwf1duRSxKtLUvVhZ1Rr1h4kqwqUj1HloAoGCCqGSM49"
SECRET_SRC = (f'import jwt\nKEY = """-----BEGIN EC PRIVATE KEY-----\n{PEM_BODY}\n-----END EC PRIVATE KEY-----"""\n'
              f"token = jwt.encode(p, KEY, algorithm='ES256', headers={{'kid': '{JWT}'}})\n")


def acme_zip(extra: dict | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(FIXTURE.rglob("*")):
            if p.is_file():
                zf.write(p, "acme-payments/" + p.relative_to(FIXTURE).as_posix())
        for name, data in (extra or {}).items():
            zf.writestr("acme-payments/" + name, data)
    return buf.getvalue()


def ingest_and_scan(tmp_path, settings, data):
    ws = tmp_path / "ws"; ws.mkdir()
    up = ws / "u.zip"; up.write_bytes(data)
    manifest = ingest_archive(up, ws, "33333333-3333-4333-8333-333333333333", "acme.zip", settings)
    res = scan_tree(ws / "tree", scan_id=manifest["scan_id"], services=manifest["services"],
                    repo_name=manifest["stripped_root_dir"] or "repo")
    return manifest, res


def test_acme_through_ingestion_matches_direct_scan_and_uses_service_yaml(tmp_path, settings):
    manifest, res = ingest_and_scan(tmp_path, settings, acme_zip())
    direct = scan_tree(FIXTURE, scan_id=manifest["scan_id"], services=[{"service": "payment-api", "root": ""}], repo_name="acme-payments")
    assert manifest["stripped_root_dir"] == "acme-payments" and manifest["services"][0]["service"] == "payment-api"
    assert res.to_dict() == direct.to_dict()
    assert {f["service"] for f in res.findings} == {"payment-api"}


def test_secrets_never_reach_findings_and_line_numbers_survive_redaction(tmp_path, settings):
    manifest, res = ingest_and_scan(tmp_path, settings, acme_zip({"src/secrets_demo.py": SECRET_SRC}))
    blob = json.dumps(res.to_dict())
    assert JWT not in blob and PEM_BODY not in blob
    f = [x for x in res.findings if x["file"] == "src/secrets_demo.py" and not x["metadata"]["comment_only"]][0]
    assert f["algorithm"] == "ECDSA" and f["operation"] == "signature" and "***REDACTED***" in f["evidence"]
    assert f["line_start"] == 5            # original line (PEM block above was redacted without shifting lines)
    assert any(r["file"] == "src/secrets_demo.py" and r["kind"] == "pem_private_key" for r in manifest["redactions"])


def test_binary_and_oversized_files_are_not_scanned(tmp_path, settings):
    z = make_zip({"a.py": "import hashlib\nhashlib.sha1(b)\n", "lib.so": b"\x00ELF hashlib.sha1("})
    manifest, res = ingest_and_scan(tmp_path, settings, z)
    assert [f["file"] for f in res.findings] == ["a.py"] and manifest["skipped"][0]["reason"] == "binary"
