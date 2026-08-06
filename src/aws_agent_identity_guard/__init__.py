"""AWS Agent Identity Guard."""

from .scanner import Finding, scan_policy_document, scan_trust_policy

__all__ = ["Finding", "scan_policy_document", "scan_trust_policy"]
