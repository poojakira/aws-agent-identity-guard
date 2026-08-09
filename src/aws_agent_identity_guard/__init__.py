"""AWS Agent Identity Guard."""

from .scanner import Finding, scan_policy_document, scan_trust_policy

__version__ = "0.3.0"

__all__ = ["Finding", "__version__", "scan_policy_document", "scan_trust_policy"]
