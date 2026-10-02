"""Legacy file digests (kept for compatibility with an old export format)."""
import hashlib


def file_digest(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()
