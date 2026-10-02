"""Quantum Migration Copilot scanner.

Deterministic, static-only cryptographic discovery. Contains no AI/LLM calls and
never imports or executes scanned code (see docs/knowledge-pack/04_THREAT_MODEL.md).
"""
from ._version import ENGINE_VERSION
from .engine import ScanResult, scan_tree
from .rules import RuleError, load_rules
from .schema import Finding, validate_finding

__all__ = ["ENGINE_VERSION", "scan_tree", "ScanResult", "load_rules", "RuleError", "Finding", "validate_finding"]
