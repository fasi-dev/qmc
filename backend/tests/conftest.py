import dataclasses
import io
import re
import tarfile
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings, get_settings
from app.main import app


@pytest.fixture
def settings(tmp_path) -> Settings:
    """Small limits so adversarial archives stay tiny and tests stay fast."""
    return dataclasses.replace(
        Settings(), data_dir=tmp_path / "data",
        max_archive_bytes=2 * 1024 * 1024, max_file_bytes=256 * 1024,
        max_extracted_bytes=2 * 1024 * 1024, max_file_count=100,
        max_compression_ratio=100, ratio_floor_bytes=64 * 1024,
        admin_token=ADMIN_TOKEN, scans_per_window=0,      # rate limit disabled except in tests that enable it
    )


ADMIN_TOKEN = "test-admin-token"
ADMIN = {"X-QMC-Admin-Token": ADMIN_TOKEN}
_SCAN_IN_URL = re.compile(r"/api/scans/([0-9a-f-]{36})")


class TokenClient(TestClient):
    """TestClient that behaves like the frontend: it remembers the access_token returned when a scan is created
    and sends it (X-QMC-Scan-Token) on later requests for that scan. Use `raw_client` to test access control."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.tokens: dict[str, str] = {}

    def request(self, method, url, *a, **kw):
        m = _SCAN_IN_URL.search(str(url))
        if m and m.group(1) in self.tokens:
            headers = dict(kw.pop("headers", None) or {})
            headers.setdefault("X-QMC-Scan-Token", self.tokens[m.group(1)])
            kw["headers"] = headers
        r = super().request(method, url, *a, **kw)
        if r.headers.get("content-type", "").startswith("application/json"):
            try:
                body = r.json()
            except ValueError:
                body = None
            if isinstance(body, dict) and body.get("access_token"):
                sid = body.get("scan_id") or (body.get("scan") or {}).get("id")
                if sid:
                    self.tokens[sid] = body["access_token"]
        return r


@pytest.fixture
def client(settings):
    app.dependency_overrides[get_settings] = lambda: settings
    yield TokenClient(app)
    app.dependency_overrides.clear()


@pytest.fixture
def raw_client(settings):
    app.dependency_overrides[get_settings] = lambda: settings
    yield TestClient(app)
    app.dependency_overrides.clear()


# ---- archive builders -------------------------------------------------------
def make_zip(entries: dict[str, bytes | str], *, compress=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compress) as zf:
        for name, data in entries.items():
            zi = zipfile.ZipInfo(name)  # raw ZipInfo: keeps '..', '/', backslashes as-is
            zi.compress_type = compress
            zf.writestr(zi, data)
    return buf.getvalue()


def make_tar(members: list[tuple[tarfile.TarInfo, bytes | None]], mode="w") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as tf:
        for ti, data in members:
            tf.addfile(ti, io.BytesIO(data) if data is not None else None)
    return buf.getvalue()


def tar_file(name: str, data: bytes, mode=0o644) -> tuple[tarfile.TarInfo, bytes]:
    ti = tarfile.TarInfo(name)
    ti.size = len(data)
    ti.mode = mode
    return ti, data


def tar_special(name: str, typ: bytes, linkname: str = "") -> tuple[tarfile.TarInfo, None]:
    ti = tarfile.TarInfo(name)
    ti.type = typ
    ti.linkname = linkname
    return ti, None


def write_archive(tmp_path: Path, data: bytes, name="upload.bin") -> Path:
    p = tmp_path / name
    p.write_bytes(data)
    return p
