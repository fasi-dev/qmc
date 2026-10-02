import json

from qmc_scanner.cli import main
from tests.conftest import write_tree


def test_cli_json_and_manifest(tmp_path, capsys):
    root = write_tree(tmp_path / "t", {"a/x.py": "import hashlib\nhashlib.sha1(b)\n"})
    mf = tmp_path / "m.json"
    mf.write_text(json.dumps({"services": [{"service": "svc", "root": "a"}], "stripped_root_dir": "acme"}))
    assert main([str(root), "--manifest", str(mf), "--scan-id", "abc"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["scan_id"] == "abc" and out["findings"][0]["service"] == "svc" and out["status"] == "complete"


def test_cli_summary_and_errors(tmp_path, capsys):
    root = write_tree(tmp_path / "t", {"x.py": "import hashlib\nhashlib.sha1(b)\n"})
    assert main([str(root), "--summary"]) == 0
    assert "CRYPTO-001" in capsys.readouterr().out
    assert main([str(tmp_path / "missing")]) == 2
