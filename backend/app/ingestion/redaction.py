"""Re-export: the redaction implementation lives in the scanner package so the scanner can
also use it as an evidence guard (defense in depth). See qmc_scanner/redaction.py."""
from qmc_scanner.redaction import MARKER, Redaction, redact_text

__all__ = ["MARKER", "Redaction", "redact_text"]
