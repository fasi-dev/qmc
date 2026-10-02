"""Safe repository ingestion (04_THREAT_MODEL.md section 4).

Static handling only: uploaded content is validated, extracted as inert data
(files are written non-executable), redacted, and described in a manifest.
Nothing in this package imports, executes, or evals uploaded code.
"""
from .errors import IngestionError
from .pipeline import ingest_archive, purge_tree, load_manifest, delete_scan

__all__ = ["IngestionError", "ingest_archive", "purge_tree", "load_manifest", "delete_scan"]
