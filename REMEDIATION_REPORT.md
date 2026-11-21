# Remediation report

Branch codex/local-workbench-20261116. Local fixing source 8e14fa4c9402b7da325502e82fab4368d924888c. Review baseline abe1c0a1e5953b18eae762a5c41f400ff677adb2.

- **IAM-01** The request parser and review engine shared an exception handler. Valid input with a synthetic engine ValueError or TypeError returned HTTP 400. The revised handler gives internal failures a scrubbed HTTP 500 and reports body read timeouts separately.
- **IAM-02** Both files referenced a missing branch-cleanup.json in the evidence archive. HTTP returned 404 and the named object was absent from Git. The links now point to the existing immutable manifest or cleanup record.

Read [documentation parity](DOCUMENTATION_PARITY.md) for the evidence pins. Historical poster figures and images retain their original date and provenance.
