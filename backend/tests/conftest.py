import dataclasses
import io
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
    )


@pytest.fixture
def client(settings):
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
