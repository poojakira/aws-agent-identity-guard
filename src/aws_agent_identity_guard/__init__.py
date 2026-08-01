"""AWS Agent Identity Guard."""

from .scanner import Finding, scan_policy_document

__all__ = ["Finding", "scan_policy_document"]
