"""Archive type detection and bounded, safe extraction (ZIP / TAR / TAR.GZ / TAR.BZ2 / TAR.XZ).

Security properties (see 04_THREAT_MODEL.md section 4):
  * type decided by magic bytes, never by filename/extension
  * entries are NEVER extracted with zipfile.extract/tarfile.extract: we validate each name,
    then write bytes ourselves with O_EXCL|O_NOFOLLOW
  * rejected: absolute paths, drive letters, '..', NUL/control chars, symlinks, hardlinks,
    devices, FIFOs, sparse files, encrypted entries, duplicate paths
  * limits: entry count, per-file size, total extracted size, compression ratio
  * extracted files are written 0600 (never executable); nothing is imported or run
  * nested archives are NOT unpacked (they are ordinary files)
"""
from __future__ import annotations

import bz2
import errno
import gzip
import hashlib
import lzma
import os
import re
import stat
import tarfile
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from ..config import Settings
from .errors import IngestionError
from .redaction import redact_text

_DRIVE = re.compile(r"^[A-Za-z]:")


# ----------------------------------------------------------------------------- detection
def detect_archive_type(path: Path) -> str:
    with open(path, "rb") as f:
        head = f.read(512)
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return "zip"
    if head.startswith(b"\x1f\x8b"):
        return "tar.gz"
    if head.startswith(b"BZh"):
        return "tar.bz2"
    if head.startswith(b"\xfd7zXZ\x00"):
        return "tar.xz"
    if len(head) >= 262 and head[257:262] == b"ustar":
        return "tar"
    raise IngestionError(
        "unsupported_archive_type",
        "Unsupported file type. Upload a .zip, .tar, .tar.gz, .tar.bz2 or .tar.xz archive "
        "(type is checked from file contents, not the filename).",
        415,
    )


# ----------------------------------------------------------------------------- paths
def sanitize_member_path(name: str, max_len: int) -> str | None:
    """Return a normalized relative POSIX path, or None for '.'-like entries. Raises on unsafe names."""
    if any(ord(c) < 32 for c in name):
        raise IngestionError("unsafe_path", "Archive contains an entry name with control characters.")
    n = name.replace("\\", "/")
    if n.startswith("/") or _DRIVE.match(n):
        raise IngestionError("unsafe_path", "Archive contains an absolute path (path traversal attempt).")
    parts = [p for p in n.split("/") if p not in ("", ".")]
    if ".." in parts:
        raise IngestionError("unsafe_path", "Archive contains a '..' path component (path traversal attempt).")
    if not parts:
        return None
    rel = "/".join(parts)
    if len(rel) > max_len or any(len(p) > 255 for p in parts):
        raise IngestionError("path_too_long", "Archive contains an excessively long path.")
    return rel


# ----------------------------------------------------------------------------- records
@dataclass
class FileRecord:
    path: str
    size: int
    sha256: str
    redacted: bool


@dataclass
class SkippedRecord:
    path: str
    reason: str   # "too_large" | "binary"
    size: int


@dataclass
class RedactionRecord:
    file: str
    line_start: int
    line_end: int
    kind: str
    marker: str = "***REDACTED***"


@dataclass
class ExtractionResult:
    files: list[FileRecord] = field(default_factory=list)
    skipped: list[SkippedRecord] = field(default_factory=list)
    redactions: list[RedactionRecord] = field(default_factory=list)
    entry_count: int = 0
    total_bytes: int = 0


# ----------------------------------------------------------------------------- sink
class _Sink:
    """Receives validated entries; enforces limits; redacts; writes inert files."""

    def __init__(self, root: Path, s: Settings, archive_size: int):
        self.root = root
        self.root_real = os.path.realpath(root)
        self.s = s
        self.archive_size = max(archive_size, 1)
        self.res = ExtractionResult()
        self.seen: set[str] = set()

    def count_entry(self) -> None:
        self.res.entry_count += 1
        if self.res.entry_count > self.s.max_file_count:
            raise IngestionError("too_many_files", f"Archive has more than {self.s.max_file_count} entries.")

    def _dest(self, rel: str) -> str:
        dest = os.path.join(self.root_real, *rel.split("/"))
        real = os.path.realpath(dest)
        if os.path.commonpath([self.root_real, real]) != self.root_real:
            raise IngestionError("unsafe_path", "Entry resolves outside the scan workspace.")
        return dest

    def add_dir(self, rel: str) -> None:
        if rel in self.seen:
            raise IngestionError("unsafe_path", "Archive contains conflicting duplicate entries.")
        self.seen.add(rel)
        try:
            os.makedirs(self._dest(rel), mode=0o700, exist_ok=True)
        except (FileExistsError, NotADirectoryError):
            raise IngestionError("unsafe_path", "Archive contains conflicting file/directory entries.")

    def _check_total(self) -> None:
        t = self.res.total_bytes
        if t > self.s.max_extracted_bytes:
            raise IngestionError("extracted_too_large",
                                 f"Extracted content exceeds {self.s.max_extracted_bytes} bytes.")
        if t > self.s.ratio_floor_bytes and t / self.archive_size > self.s.max_compression_ratio:
            raise IngestionError("archive_bomb",
                                 f"Compression ratio exceeds {self.s.max_compression_ratio}:1 (possible archive bomb).")

    def add_file(self, rel: str, fileobj: BinaryIO, declared_size: int | None) -> None:
        if rel in self.seen:
            raise IngestionError("unsafe_path", "Archive contains duplicate or conflicting entries.")
        self.seen.add(rel)
        if declared_size is not None and declared_size > self.s.max_file_bytes:
            self.res.skipped.append(SkippedRecord(rel, "too_large", declared_size))
            return
        # Bounded read: never trust the declared size.
        limit = self.s.max_file_bytes if declared_size is None else declared_size
        chunks, got = [], 0
        while True:
            chunk = fileobj.read(min(65536, limit + 1 - got))
            if not chunk:
                break
            got += len(chunk)
            chunks.append(chunk)
            if got > limit:
                raise IngestionError("archive_bomb", "An entry is larger than its declared size.")
        data = b"".join(chunks)
        self.res.total_bytes += len(data)
        self._check_total()

        if b"\x00" in data[:8192]:
            self.res.skipped.append(SkippedRecord(rel, "binary", len(data)))
            return

        text = data.decode("utf-8", errors="surrogateescape")
        new_text, reds = redact_text(text, rel)
        out = new_text.encode("utf-8", errors="surrogateescape") if reds else data
        for r in reds:
            self.res.redactions.append(RedactionRecord(rel, r.line_start, r.line_end, r.kind))

        dest = self._dest(rel)
        try:
            os.makedirs(os.path.dirname(dest), mode=0o700, exist_ok=True)
            fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except (FileExistsError, NotADirectoryError):
            raise IngestionError("unsafe_path", "Archive contains conflicting entries.")
        except OSError as e:
            if e.errno == errno.ELOOP:
                raise IngestionError("unsafe_path", "Entry would write through a symbolic link.")
            raise IngestionError("workspace_write_failed", "Could not write to the scan workspace.", 500)
        with os.fdopen(fd, "wb") as f:
            f.write(out)
        self.res.files.append(FileRecord(rel, len(out), hashlib.sha256(out).hexdigest(), bool(reds)))


# ----------------------------------------------------------------------------- ZIP
def _extract_zip(path: Path, sink: _Sink, s: Settings) -> None:
    try:
        zf = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError, EOFError, ValueError, NotImplementedError):
        raise IngestionError("malformed_archive", "The ZIP archive is corrupt or unreadable.", 400)
    with zf:
        infos = zf.infolist()
        if len(infos) > s.max_file_count:
            raise IngestionError("too_many_files", f"Archive has more than {s.max_file_count} entries.")
        # ---- Pass 1: validate everything BEFORE writing a single byte ----
        total_declared = 0
        entries: list[tuple[zipfile.ZipInfo, str | None]] = []
        for info in infos:
            rel = sanitize_member_path(info.filename, s.max_path_length)
            if info.flag_bits & 0x1:
                raise IngestionError("encrypted_entry", "Encrypted ZIP entries are not supported.")
            mode_type = stat.S_IFMT(info.external_attr >> 16)
            if mode_type not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise IngestionError("unsafe_entry_type",
                                     "Archive contains a symlink or special file, which is not allowed.")
            if info.file_size > s.ratio_floor_bytes and (
                info.compress_size == 0 or info.file_size / info.compress_size > s.max_compression_ratio
            ):
                raise IngestionError("archive_bomb",
                                     f"An entry exceeds the {s.max_compression_ratio}:1 compression-ratio cap.")
            total_declared += info.file_size
            entries.append((info, rel))
        if total_declared > s.max_extracted_bytes:
            raise IngestionError("extracted_too_large",
                                 f"Archive would extract to more than {s.max_extracted_bytes} bytes.")
        if total_declared > s.ratio_floor_bytes and total_declared / max(sink.archive_size, 1) > s.max_compression_ratio:
            raise IngestionError("archive_bomb",
                                 f"Overall compression ratio exceeds {s.max_compression_ratio}:1 (possible archive bomb).")
        # ---- Pass 2: bounded extraction ----
        for info, rel in entries:
            sink.count_entry()
            if rel is None:
                continue
            if info.is_dir():
                sink.add_dir(rel)
                continue
            try:
                if info.file_size > s.max_file_bytes:
                    sink.add_file(rel, None, info.file_size)  # type: ignore[arg-type]  # skipped, never opened
                else:
                    with zf.open(info) as fh:
                        sink.add_file(rel, fh, info.file_size)
            except (zipfile.BadZipFile, zlib.error, EOFError, NotImplementedError, RuntimeError, OSError):
                raise IngestionError("malformed_archive", "The ZIP archive is corrupt (bad entry data).", 400)


# ----------------------------------------------------------------------------- TAR
class _CountingReader:
    """Wraps a (de)compressed stream and aborts on bomb-like growth. Counts ALL bytes, incl. skipped members."""

    def __init__(self, inner: BinaryIO, s: Settings, archive_size: int):
        self.inner = inner
        self.count = 0
        self.archive_size = max(archive_size, 1)
        self.s = s
        # tar headers/padding add overhead on top of file contents
        self.hard_limit = s.max_extracted_bytes + s.max_file_count * 1024

    def read(self, n: int = -1) -> bytes:
        data = self.inner.read(n)
        self.count += len(data)
        if self.count > self.hard_limit:
            raise IngestionError("extracted_too_large",
                                 f"Archive stream exceeds {self.s.max_extracted_bytes} bytes when decompressed.")
        if self.count > self.s.ratio_floor_bytes and self.count / self.archive_size > self.s.max_compression_ratio:
            raise IngestionError("archive_bomb",
                                 f"Compression ratio exceeds {self.s.max_compression_ratio}:1 (possible archive bomb).")
        return data


def _extract_tar(path: Path, kind: str, sink: _Sink, s: Settings) -> None:
    raw = open(path, "rb")
    try:
        inner: BinaryIO
        if kind == "tar.gz":
            inner = gzip.GzipFile(fileobj=raw)
        elif kind == "tar.bz2":
            inner = bz2.BZ2File(raw)
        elif kind == "tar.xz":
            inner = lzma.LZMAFile(raw)
        else:
            inner = raw
        reader = _CountingReader(inner, s, sink.archive_size)
        try:
            with tarfile.open(fileobj=reader, mode="r|") as tf:  # streaming: no seeking, no random access
                for m in tf:
                    rel = sanitize_member_path(m.name, s.max_path_length)
                    sink.count_entry()
                    if rel is None:
                        continue
                    if m.isdir():
                        sink.add_dir(rel)
                    elif m.isreg() and not m.issparse():
                        fh = tf.extractfile(m)
                        if fh is None:
                            raise IngestionError("malformed_archive", "Unreadable tar member.", 400)
                        sink.add_file(rel, fh, m.size)
                    else:
                        raise IngestionError("unsafe_entry_type",
                                             "Archive contains a symlink, hardlink or special file, which is not allowed.")
        except (tarfile.TarError, EOFError, lzma.LZMAError, zlib.error, ValueError, OSError):
            # IngestionError is not in this list, so our own rejections propagate unchanged.
            raise IngestionError("malformed_archive", "The archive is corrupt, truncated or not a valid tar file.", 400)
    finally:
        raw.close()


def extract_archive(path: Path, kind: str, dest_root: Path, s: Settings) -> ExtractionResult:
    dest_root.mkdir(mode=0o700, parents=True, exist_ok=False)
    sink = _Sink(dest_root, s, path.stat().st_size)
    if kind == "zip":
        _extract_zip(path, sink, s)
    else:
        _extract_tar(path, kind, sink, s)
    if sink.res.entry_count == 0:
        raise IngestionError("empty_archive", "The archive contains no files.", 400)
    return sink.res
