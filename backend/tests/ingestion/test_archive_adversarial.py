"""Adversarial ingestion tests: zip-slip, symlinks, bombs, limits, malformed input, no-execution."""
import gzip
import io
import os
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

from app.ingestion import IngestionError, ingest_archive
from app.ingestion.archive import detect_archive_type, sanitize_member_path
from tests.conftest import make_tar, make_zip, tar_file, tar_special, write_archive


_n = iter(range(10_000))


def run(tmp_path, settings, data: bytes, name="u.bin"):
    ws = tmp_path / f"ws{next(_n)}"
    ws.mkdir()
    return ingest_archive(write_archive(ws, data, name), ws, "00000000-0000-4000-8000-000000000000", name, settings), ws


def rejects(tmp_path, settings, data, code):
    with pytest.raises(IngestionError) as ei:
        run(tmp_path, settings, data)
    allowed = {code} if isinstance(code, str) else set(code)
    assert ei.value.code in allowed, ei.value.code
    return ei.value


def assert_nothing_escaped(tmp_path):
    """No file created anywhere outside <tmp>/ws/tree"""
    for p in tmp_path.rglob("*"):
        assert "evil" not in p.name or "tree" in p.parts, f"escaped: {p}"


# ---------------------------------------------------------------- happy path
def test_valid_zip_extracts_and_flattens_single_root(tmp_path, settings):
    z = make_zip({"acme/": b"", "acme/src/a.py": "x = 1\n", "acme/service.yaml": "service: s\n"})
    m, ws = run(tmp_path, settings, z)
    assert m["archive_type"] == "zip" and m["stripped_root_dir"] == "acme"
    assert {f["path"] for f in m["files"]} == {"src/a.py", "service.yaml"}
    assert (ws / "tree" / "src" / "a.py").read_text() == "x = 1\n"


@pytest.mark.parametrize("mode,kind", [("w", "tar"), ("w:gz", "tar.gz"), ("w:bz2", "tar.bz2"), ("w:xz", "tar.xz")])
def test_valid_tar_variants(tmp_path, settings, mode, kind):
    t = make_tar([tar_file("src/a.py", b"x = 1\n")], mode=mode)
    m, ws = run(tmp_path, settings, t)
    assert m["archive_type"] == kind and m["stats"]["file_count"] == 1


# ---------------------------------------------------------------- magic bytes
def test_type_decided_by_magic_not_extension(tmp_path, settings):
    ws = tmp_path / "w"; ws.mkdir()
    p = write_archive(ws, b"just some text, not an archive", "evil.zip")
    with pytest.raises(IngestionError) as ei:
        detect_archive_type(p)
    assert ei.value.code == "unsupported_archive_type" and ei.value.status_code == 415


def test_zip_content_with_txt_name_is_still_zip(tmp_path, settings):
    m, _ = run(tmp_path, settings, make_zip({"a.py": "1"}), name="notes.txt")
    assert m["archive_type"] == "zip"


@pytest.mark.parametrize("blob", [b"\x89PNG\r\n\x1a\n" + b"0" * 600, b"MZ" + b"\x00" * 600, b"%PDF-1.7" + b"0" * 600,
                                  b"\x7fELF" + b"\x00" * 600, b"Rar!\x1a\x07\x00" + b"0" * 600])
def test_non_archive_magic_rejected(tmp_path, settings, blob):
    rejects(tmp_path, settings, blob, "unsupported_archive_type")


# ---------------------------------------------------------------- zip-slip / path traversal
@pytest.mark.parametrize("name", ["../evil.txt", "a/../../evil.txt", "a/b/../../../evil.txt", "/etc/evil",
                                  "C:\\evil.txt", "c:/evil.txt", "..\\evil.txt", "\\\\server\\share\\evil", "a/\nevil"])
def test_zip_slip_rejected(tmp_path, settings, name):
    rejects(tmp_path, settings, make_zip({"ok.py": "1", name: "pwn"}), "unsafe_path")
    assert_nothing_escaped(tmp_path)


def test_zip_slip_validated_before_any_write(tmp_path, settings):
    ws = tmp_path / "wsx"; ws.mkdir()
    p = write_archive(ws, make_zip({"good.py": "1", "../evil.txt": "x"}))
    with pytest.raises(IngestionError):
        ingest_archive(p, ws, "00000000-0000-4000-8000-000000000000", "u", settings)
    assert not (ws / "tree" / "good.py").exists()  # zip pass-1 validation: nothing written


@pytest.mark.parametrize("name", ["../evil.txt", "/abs/evil.txt", "a/../../evil.txt"])
def test_tar_slip_rejected(tmp_path, settings, name):
    rejects(tmp_path, settings, make_tar([tar_file(name, b"pwn")]), "unsafe_path")
    assert_nothing_escaped(tmp_path)


def test_nul_and_control_chars_in_names_rejected():
    for bad in ("a/\x00evil", "a\x01b"):
        with pytest.raises(IngestionError):
            sanitize_member_path(bad, 1024)


def test_sanitize_member_path_unit():
    assert sanitize_member_path("./a//b/./c.py", 1024) == "a/b/c.py"
    assert sanitize_member_path("a\\b.py", 1024) == "a/b.py"
    assert sanitize_member_path("./", 1024) is None
    with pytest.raises(IngestionError):
        sanitize_member_path("a/" + "x" * 300, 1024)


# ---------------------------------------------------------------- symlinks / special files
def test_zip_symlink_rejected(tmp_path, settings):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zi = zipfile.ZipInfo("link"); zi.create_system = 3; zi.external_attr = (0o120777 << 16)
        zf.writestr(zi, "/etc/passwd")
    rejects(tmp_path, settings, buf.getvalue(), "unsafe_entry_type")


@pytest.mark.parametrize("typ,link", [(tarfile.SYMTYPE, "/etc/passwd"), (tarfile.LNKTYPE, "other"),
                                      (tarfile.CHRTYPE, ""), (tarfile.BLKTYPE, ""), (tarfile.FIFOTYPE, "")])
def test_tar_special_entries_rejected(tmp_path, settings, typ, link):
    t = make_tar([tar_file("ok.py", b"1"), tar_special("thing", typ, link)])
    rejects(tmp_path, settings, t, "unsafe_entry_type")


def test_tar_symlink_then_write_through_it_rejected(tmp_path, settings):
    t = make_tar([tar_special("d", tarfile.SYMTYPE, str(tmp_path)), tar_file("d/evil.txt", b"pwn")])
    rejects(tmp_path, settings, t, "unsafe_entry_type")
    assert not (tmp_path / "evil.txt").exists()


def test_duplicate_and_file_dir_conflicts_rejected(tmp_path, settings):
    t = make_tar([tar_file("a", b"1"), tar_file("a/b", b"2")])
    rejects(tmp_path, settings, t, "unsafe_path")
    t = make_tar([tar_file("a.py", b"1"), tar_file("a.py", b"2")])
    rejects(tmp_path, settings, t, "unsafe_path")


def test_encrypted_zip_entry_rejected(tmp_path, settings):
    z = bytearray(make_zip({"a.py": "1"}))
    # set the 'encrypted' general-purpose bit in both local header (offset 6) and central dir
    z[6] |= 1
    cd = z.rfind(b"PK\x01\x02")
    z[cd + 8] |= 1
    rejects(tmp_path, settings, bytes(z), "encrypted_entry")


# ---------------------------------------------------------------- bombs & limits
def test_zip_bomb_rejected_before_extraction(tmp_path, settings):
    z = make_zip({"zeros.txt": b"\x00" * (20 * 1024 * 1024)})
    assert len(z) < 100_000
    # Single-entry ratio check (declared sizes) fires before any byte is written.
    rejects(tmp_path, settings, z, "archive_bomb")
    assert not list(tmp_path.rglob("zeros.txt"))


def test_zip_bomb_many_entries_total_ratio(tmp_path, settings):
    z = make_zip({f"f{i}.txt": b"A" * 60_000 for i in range(60)})  # each 60KB (<floor), total 3.6MB, tiny archive
    assert len(z) < 30_000
    assert 60 * 60_000 > settings.max_extracted_bytes
    rejects(tmp_path, settings, z, "extracted_too_large")


def test_targz_bomb_stops_while_streaming(tmp_path, settings):
    t = make_tar([tar_file("zeros.txt", b"\x00" * (30 * 1024 * 1024))], mode="w:gz")
    assert len(t) < 100_000
    # whichever guard trips first (ratio cap or absolute decompressed-bytes cap) is a valid rejection
    rejects(tmp_path, settings, t, ("archive_bomb", "extracted_too_large"))


def test_skipped_giant_member_in_targz_still_bounded(tmp_path, settings):
    """A member larger than max_file_bytes is skipped, but decompressing it is still counted (CPU-DoS defense)."""
    t = make_tar([tar_file("big.bin", b"\x01" * (40 * 1024 * 1024))], mode="w:xz")
    rejects(tmp_path, settings, t, "archive_bomb")


def test_extracted_total_limit(tmp_path, settings):
    import random
    rnd = random.Random(1)
    blobs = {f"f{i}.txt": bytes(rnd.getrandbits(8) for _ in range(200_000)) for i in range(11)}  # incompressible
    z = make_zip(blobs, compress=zipfile.ZIP_STORED)
    s2 = __import__("dataclasses").replace(settings, max_archive_bytes=10 * 1024 * 1024)
    rejects(tmp_path, s2, z, "extracted_too_large")


def test_file_count_limit_zip_and_tar(tmp_path, settings):
    rejects(tmp_path, settings, make_zip({f"f{i}.py": "1" for i in range(settings.max_file_count + 1)}), "too_many_files")
    t = make_tar([tar_file(f"f{i}.py", b"1") for i in range(settings.max_file_count + 1)])
    rejects(tmp_path, settings, t, "too_many_files")


def test_archive_size_limit(tmp_path, settings):
    import dataclasses, os as _os
    s2 = dataclasses.replace(settings, max_archive_bytes=1000)
    z = make_zip({"a.bin": _os.urandom(5000)}, compress=zipfile.ZIP_STORED)
    rejects(tmp_path, s2, z, "archive_too_large")


def test_oversized_file_is_skipped_not_fatal(tmp_path, settings):
    import random
    big = bytes(random.Random(2).getrandbits(8) for _ in range(settings.max_file_bytes + 10)).replace(b"\x00", b"a")
    z = make_zip({"small.py": "x = 1\n", "big.txt": big}, compress=zipfile.ZIP_STORED)
    m, ws = run(tmp_path, settings, z)
    assert [f["path"] for f in m["files"]] == ["small.py"]
    assert m["skipped"] == [{"path": "big.txt", "reason": "too_large", "size": len(big)}]
    assert not (ws / "tree" / "big.txt").exists()


def test_lying_zip_header_does_not_bypass_limits(tmp_path, settings):
    """Declared size patched far below real size must be rejected, never silently truncated/accepted."""
    data = bytearray(make_zip({"a.txt": b"A" * 5000}, compress=zipfile.ZIP_STORED))
    for sig, off in ((b"PK\x03\x04", 22), (b"PK\x01\x02", 24)):
        i = data.rfind(sig) if sig == b"PK\x01\x02" else data.find(sig)
        data[i + off:i + off + 4] = (10).to_bytes(4, "little")
    rejects(tmp_path, settings, bytes(data), ("malformed_archive", "archive_bomb"))


# ---------------------------------------------------------------- malformed
def test_empty_and_truncated_and_garbage(tmp_path, settings):
    rejects(tmp_path, settings, b"", "unsupported_archive_type")
    good = make_zip({"a.py": "x" * 1000})
    rejects(tmp_path, settings, good[: len(good) // 2], "malformed_archive")
    rejects(tmp_path, settings, b"PK\x03\x04" + b"garbage" * 50, "malformed_archive")
    rejects(tmp_path, settings, b"PK\x05\x06" + b"\x00" * 18, "empty_archive")


def test_malformed_tar_variants(tmp_path, settings):
    good = make_tar([tar_file("a.py", b"x" * 5000)], mode="w:gz")
    rejects(tmp_path, settings, good[: len(good) // 2], "malformed_archive")
    rejects(tmp_path, settings, gzip.compress(b"this is not a tar file" * 100), "malformed_archive")
    rejects(tmp_path, settings, b"BZh9" + b"junk" * 100, "malformed_archive")
    rejects(tmp_path, settings, b"\xfd7zXZ\x00" + b"junk" * 100, "malformed_archive")
    rejects(tmp_path, settings, b"\x1f\x8b" + b"junk" * 100, "malformed_archive")


def test_zip_with_corrupted_entry_data(tmp_path, settings):
    z = bytearray(make_zip({"a.py": "hello world " * 200}, compress=zipfile.ZIP_STORED))
    i = z.find(b"hello"); z[i] ^= 0xFF   # CRC mismatch
    rejects(tmp_path, settings, bytes(z), "malformed_archive")


def test_failed_ingest_via_api_leaves_no_workspace(client, settings):
    r = client.post("/api/scans", content=make_zip({"../evil": "x"}))
    assert r.status_code == 422 and r.json()["error"]["code"] == "unsafe_path"
    scans = settings.scans_dir
    assert not scans.exists() or list(scans.iterdir()) == []


# ---------------------------------------------------------------- never execute / inert files
def test_uploaded_code_is_never_executed_or_executable(tmp_path, settings):
    marker = tmp_path / "PWNED"
    payload = f"import pathlib; pathlib.Path({str(marker)!r}).write_text('x')\n"
    z = make_zip({"setup.py": payload, "conftest.py": payload, "__init__.py": payload, "run.sh": f"touch {marker}\n"})
    before = set(sys.modules)
    m, ws = run(tmp_path, settings, z)
    assert not marker.exists()
    assert set(sys.modules) == before
    for p in (ws / "tree").rglob("*"):
        assert p.stat().st_mode & 0o111 == 0 or p.is_dir()


def test_tar_exec_bits_stripped(tmp_path, settings):
    m, ws = run(tmp_path, settings, make_tar([tar_file("run.sh", b"#!/bin/sh\n", mode=0o4755)]))
    assert (ws / "tree" / "run.sh").stat().st_mode & 0o7111 == 0


def test_nested_archives_not_unpacked(tmp_path, settings):
    inner = make_zip({"deep.py": "1"})
    m, ws = run(tmp_path, settings, make_zip({"inner.zip": inner}))
    assert not list((ws / "tree").rglob("deep.py"))      # inner archive was not opened
    assert [f["path"] for f in m["files"]] == [] and m["skipped"][0]["path"] == "inner.zip"


def test_binary_files_skipped_not_persisted(tmp_path, settings):
    m, ws = run(tmp_path, settings, make_zip({"a.py": "1", "lib.so": b"\x7fELF\x00\x00secret"}))
    assert [f["path"] for f in m["files"]] == ["a.py"]
    assert m["skipped"][0]["reason"] == "binary" and not (ws / "tree" / "lib.so").exists()


# ---------------------------------------------------------------- guards tested in isolation (ratio cap disabled)
def test_tar_absolute_decompressed_cap_independent_of_ratio(tmp_path, settings):
    import dataclasses
    s2 = dataclasses.replace(settings, max_compression_ratio=10_000_000)
    t = make_tar([tar_file("zeros.bin", b"\x00" * (30 * 1024 * 1024))], mode="w:gz")
    rejects(tmp_path, s2, t, "extracted_too_large")


def test_zip_declared_total_cap_independent_of_ratio(tmp_path, settings):
    import dataclasses
    s2 = dataclasses.replace(settings, max_compression_ratio=10_000_000)
    z = make_zip({f"f{i}.txt": b"\x00" * 200_000 for i in range(15)})   # 3MB declared > 2MB cap
    rejects(tmp_path, s2, z, "extracted_too_large")


def test_tar_ratio_cap_independent_of_absolute_cap(tmp_path, settings):
    import dataclasses
    s2 = dataclasses.replace(settings, max_extracted_bytes=10**12)
    t = make_tar([tar_file("zeros.bin", b"\x00" * (30 * 1024 * 1024))], mode="w:gz")
    rejects(tmp_path, s2, t, "archive_bomb")


def test_traversal_blocked_by_second_layer_even_if_name_check_failed(tmp_path, settings, monkeypatch):
    """Defense in depth: the realpath/commonpath containment check stands alone."""
    import app.ingestion.archive as a
    monkeypatch.setattr(a, "sanitize_member_path", lambda name, n: name)   # sabotage layer 1
    rejects(tmp_path, settings, make_zip({"../evil.txt": "x"}), ("unsafe_path", "malformed_archive"))
    assert not list(tmp_path.rglob("evil.txt"))
