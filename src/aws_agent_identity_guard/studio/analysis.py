"""Bounded input, exact source spans and evidence around the canonical scanners."""

from __future__ import annotations

import ast
import hashlib
import json
import math
import re
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aws_agent_identity_guard import __version__
from aws_agent_identity_guard import scanner as engine
from aws_agent_identity_guard.cli import _build_sarif

MAX_DOCUMENT_BYTES = 32768
MAX_STATEMENTS = 32
MAX_DEPTH = 16
STATIC_RULES = tuple(
    [f"AIG{i:03d}" for i in range(1, 22)] + [f"AIG-TP{i:03d}" for i in range(1, 4)]
)
LIMITATIONS = [
    "Patterns are review signals, not effective permissions or proven exploitability.",
    "Explicit Deny and conditions are counter-evidence; their intersections are not evaluated.",
    "SCPs, boundaries, session/resource policies and condition semantics are unknown.",
    "No AWS call is made. AIG-PB001 requires live role context and is not run here.",
    "No findings means no configured pattern matched; it does not prove least privilege or safety.",
]


class InputError(ValueError):
    """Invalid or unsupported input; messages never echo supplied values."""


def checksum(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def provenance() -> dict[str, Any]:
    source = Path(__file__).resolve()
    root = source.parents[3]
    sha, status = "UNKNOWN", "UNKNOWN"
    try:
        if root / "src/aws_agent_identity_guard/studio/analysis.py" != source:
            raise ValueError("Installed package")

        def git(*args: str) -> str:
            return subprocess.check_output(
                ["git", *args], cwd=root, timeout=2, stderr=subprocess.DEVNULL, text=True
            ).strip()

        if Path(git("rev-parse", "--show-toplevel")).resolve() != root:
            raise ValueError("Unrelated checkout")
        git("ls-files", "--error-unmatch", "src/aws_agent_identity_guard/studio/analysis.py")
        sha = git("rev-parse", "HEAD")
        status = "DIRTY" if git("status", "--porcelain") else "CLEAN"
    except (ValueError, OSError, subprocess.SubprocessError):
        sha, status = "UNKNOWN", "UNKNOWN"
    return {
        "app_version": __version__,
        "source_commit": sha,
        "source_status": status,
        "rule_set_sha256": checksum(Path(engine.__file__).read_bytes()),
        "static_rule_count": len(STATIC_RULES),
        "static_rule_ids": list(STATIC_RULES),
        "live_context_rule_ids_not_run": ["AIG-PB001"],
    }


def rule_inventory() -> tuple[str, ...]:
    """Check the advertised inventory against literal IDs in the actual scanner."""
    parsed = ast.parse(Path(engine.__file__).read_text(encoding="utf-8"))
    found = {
        node.value
        for node in ast.walk(parsed)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and re.fullmatch(r"AIG(?:\d{3}|-TP\d{3})", node.value)
    }
    if found != set(STATIC_RULES):
        raise RuntimeError("Static rule inventory drift; review required")
    return STATIC_RULES


class Document:
    """JSON parser with bounded nesting and structural spans, including duplicate keys."""

    def __init__(self, raw: str, kind: str):
        if not isinstance(raw, str) or not raw.strip():
            raise InputError("A non-empty policy JSON document is required")
        try:
            size = len(raw.encode("utf-8"))
        except UnicodeError as exc:
            raise InputError("Policy text must be valid UTF-8") from exc
        if size > MAX_DOCUMENT_BYTES:
            raise InputError("Each policy is limited to 32768 UTF-8 bytes")
        self.raw, self.kind = raw, kind
        self.spans: dict[tuple, tuple[int, int]] = {}
        self.decoder = json.JSONDecoder(parse_constant=self.reject_constant)
        try:
            value, end = self.parse(self.skip(0), (), 0)
            if self.skip(end) != len(raw):
                raise InputError("Trailing content after policy JSON")
        except InputError:
            raise
        except (ValueError, RecursionError, OverflowError) as exc:
            raise InputError("Malformed or excessively nested policy JSON") from exc
        if not isinstance(value, dict):
            raise InputError("Policy JSON must be an object")
        self.value: dict[str, Any] = value
        self.statements: list[dict[str, Any]] = []
        self.validate()

    @staticmethod
    def reject_constant(_value: str):
        raise InputError("Non-finite JSON numbers are not supported")

    def skip(self, index: int) -> int:
        while index < len(self.raw) and self.raw[index] in " \t\n\r":
            index += 1
        return index

    def parse(self, index: int, path: tuple, depth: int) -> tuple[Any, int]:
        if depth > MAX_DEPTH:
            raise InputError("Policy JSON nesting exceeds 16 levels")
        start = index
        token = self.raw[index : index + 1]
        if token == "{":
            result: Any = {}
            index = self.skip(index + 1)
            if self.raw[index : index + 1] != "}":
                while True:
                    if self.raw[index : index + 1] != '"':
                        raise InputError("Object keys must be JSON strings")
                    key, index = self.decoder.raw_decode(self.raw, index)
                    if len(key) > 4096:
                        raise InputError("Individual object keys are limited to 4096 characters")
                    if key in result:
                        raise InputError("Duplicate JSON object keys are not supported")
                    index = self.skip(index)
                    if self.raw[index : index + 1] != ":":
                        raise InputError("Expected a JSON key/value separator")
                    value, index = self.parse(self.skip(index + 1), (*path, key), depth + 1)
                    result[key] = value
                    index = self.skip(index)
                    if self.raw[index : index + 1] != ",":
                        break
                    index = self.skip(index + 1)
            if self.raw[index : index + 1] != "}":
                raise InputError("Unterminated JSON object")
            index += 1
        elif token == "[":
            result = []
            index = self.skip(index + 1)
            if self.raw[index : index + 1] != "]":
                while True:
                    value, index = self.parse(index, (*path, len(result)), depth + 1)
                    result.append(value)
                    index = self.skip(index)
                    if self.raw[index : index + 1] != ",":
                        break
                    index = self.skip(index + 1)
            if self.raw[index : index + 1] != "]":
                raise InputError("Unterminated JSON array")
            index += 1
        else:
            result, index = self.decoder.raw_decode(self.raw, index)
            if isinstance(result, str) and len(result) > 4096:
                raise InputError("Individual strings are limited to 4096 characters")
            if isinstance(result, float) and not math.isfinite(result):
                raise InputError("Non-finite JSON numbers are not supported")
        self.spans[path] = start, index
        return result, index

    def validate(self) -> None:
        doc = self.value
        if not isinstance(doc, dict) or set(doc) - {"Version", "Id", "Statement"}:
            raise InputError(
                "Policy must be an object with supported Version, Id and Statement fields"
            )
        if doc.get("Version", "2012-10-17") not in ("2012-10-17", "2008-10-17"):
            raise InputError("Unsupported IAM policy language version")
        if "Id" in doc and not isinstance(doc["Id"], str):
            raise InputError("Policy Id must be a string")
        statements = doc.get("Statement")
        self.single = isinstance(statements, dict)
        normalized = [statements] if self.single else statements
        if not isinstance(normalized, list) or not 1 <= len(normalized) <= MAX_STATEMENTS:
            raise InputError("Statement must be one object or a list of 1 to 32 objects")
        for statement in normalized:
            allowed = {
                "Sid",
                "Effect",
                "Action",
                "NotAction",
                "Resource",
                "NotResource",
                "Principal",
                "Condition",
            }
            if not isinstance(statement, dict) or set(statement) - allowed:
                raise InputError("Unsupported statement field or non-object statement")
            if statement.get("Effect") not in ("Allow", "Deny"):
                raise InputError("Every statement requires explicit Effect Allow or Deny")
            if ("Action" in statement) == ("NotAction" in statement):
                raise InputError("Every statement requires exactly one of Action or NotAction")
            self.strings(statement.get("Action", statement.get("NotAction")))
            if "Sid" in statement and not isinstance(statement["Sid"], str):
                raise InputError("Sid must be a string")
            if self.kind == "identity":
                if "Principal" in statement:
                    raise InputError(
                        "Principal belongs in a trust policy, not the supported identity input"
                    )
                if ("Resource" in statement) == ("NotResource" in statement):
                    raise InputError(
                        "Identity statements require exactly one Resource or NotResource"
                    )
                self.strings(statement.get("Resource", statement.get("NotResource")))
            else:
                if (
                    "NotAction" in statement
                    or "Resource" in statement
                    or "NotResource" in statement
                ):
                    raise InputError(
                        "Trust input supports Action and Principal, with implicit role resource"
                    )
                principal = statement.get("Principal")
                if isinstance(principal, dict) and principal:
                    if set(principal) - {"AWS", "Service", "Federated", "CanonicalUser"}:
                        raise InputError("Unsupported principal type")
                    for value in principal.values():
                        self.strings(value)
                elif principal == "*":
                    pass
                else:
                    raise InputError("Trust Principal must be '*' or a supported principal object")
            condition = statement.get("Condition", {})
            if not isinstance(condition, dict):
                raise InputError("Condition must be an operator object")
            for operator, conditions in condition.items():
                if not operator or not isinstance(conditions, dict) or not conditions:
                    raise InputError("Condition operators require non-empty key/value objects")
                for key, values in conditions.items():
                    if not key:
                        raise InputError("Condition keys must not be empty")
                    values = values if isinstance(values, list) else [values]
                    if (
                        not values
                        or len(values) > 64
                        or any(type(v) not in (str, int, float, bool) for v in values)
                    ):
                        raise InputError(
                            "Condition values must be bounded JSON scalar values or lists"
                        )
            self.statements.append(statement)

    @staticmethod
    def strings(value: Any) -> list[str]:
        values = value if isinstance(value, list) else [value]
        if not 1 <= len(values) <= 64 or any(not isinstance(v, str) or not v for v in values):
            raise InputError(
                "Policy action, resource and principal fields require 1 to 64 non-empty strings"
            )
        return values

    def location(self, index: int | None) -> dict:
        path = () if index is None else ("Statement",) if self.single else ("Statement", index)
        start, end = self.spans[path]
        return {
            "source": self.kind + "-policy.json",
            "json_pointer": "/" + "/".join(map(str, path)) if path else "",
            "startLine": self.raw.count("\n", 0, start) + 1,
            "endLine": self.raw.count("\n", 0, max(start, end - 1)) + 1,
            "snippet": self.raw[start:end],
        }


def analyze_documents(policy: str, trust: str = "") -> dict:
    documents = [Document(policy, "identity")]
    if trust.strip():
        documents.append(Document(trust, "trust"))
    findings, runs, statements, graph_nodes, graph_edges = [], [], [], [], []
    for document in documents:
        source = document.kind + "-policy.json"
        found = (
            engine.scan_policy_document(document.value)
            if document.kind == "identity"
            else engine.scan_trust_policy(document.value)
        )
        sarif = _build_sarif(Path(source), found)["runs"][0]
        denies = [
            i for i, statement in enumerate(document.statements) if statement["Effect"] == "Deny"
        ]
        graph_nodes.append({"id": source, "kind": "document", "label": source})
        for index, statement in enumerate(document.statements):
            location = document.location(index)
            statement_id = source + "#" + location["json_pointer"]
            statements.append(
                {
                    "id": statement_id,
                    "index": index,
                    "effect": statement["Effect"],
                    "location": location,
                    "condition": statement.get("Condition", {}),
                }
            )
            graph_nodes.append(
                {
                    "id": statement_id,
                    "kind": "statement",
                    "label": f"Statement {index}: {statement['Effect']}",
                    "location": location,
                }
            )
            graph_edges.append(
                {"from": source, "to": statement_id, "label": "contains", "location": location}
            )
            for field in ("Action", "NotAction", "Resource", "NotResource", "Principal"):
                if field not in statement:
                    continue
                target = statement_id + "/" + field
                graph_nodes.append(
                    {
                        "id": target,
                        "kind": field,
                        "label": json.dumps(statement[field], ensure_ascii=False),
                        "location": location,
                    }
                )
                graph_edges.append(
                    {
                        "from": statement_id,
                        "to": target,
                        "label": field + (" exclusions" if field.startswith("Not") else " pattern"),
                        "effect": statement["Effect"],
                        "conditions_present": bool(statement.get("Condition")),
                        "location": location,
                    }
                )
        for finding, result in zip(found, sarif["results"], strict=True):
            location = document.location(finding.statement_index)
            evidence = {
                **finding.to_dict(),
                "location": location,
                "scope": "static pattern; effective permission UNKNOWN",
                "counter_evidence": {
                    "deny_statement_indices": denies,
                    "conditions_present": bool(
                        finding.statement_index is not None
                        and document.statements[finding.statement_index].get("Condition")
                    ),
                },
                "assumptions": LIMITATIONS[:3],
            }
            evidence["fingerprint"] = checksum(
                json.dumps(
                    {
                        "rule": finding.rule_id,
                        "source": source,
                        "index": finding.statement_index,
                        "severity": finding.severity,
                        "message": finding.message,
                    },
                    sort_keys=True,
                ).encode()
            )
            findings.append(evidence)
            physical = result["locations"][0]["physicalLocation"]
            physical["region"] = {key: location[key] for key in ("startLine", "endLine")}
            result["locations"][0]["logicalLocations"] = [
                {"fullyQualifiedName": location["json_pointer"] or "/"}
            ]
            result["properties"].update(
                {"scope": evidence["scope"], "counterEvidence": evidence["counter_evidence"]}
            )
        sarif["properties"] = {
            "scope": "STATIC_ONLY_CONTEXT_INCOMPLETE",
            "inputSha256": checksum(document.raw.encode()),
        }
        runs.append(sarif)
    return {
        "findings": findings,
        "sources": [
            {"name": d.kind + "-policy.json", "sha256": checksum(d.raw.encode()), "text": d.raw}
            for d in documents
        ],
        "statements": statements,
        "graph": {
            "nodes": graph_nodes,
            "edges": graph_edges,
            "scope": "Supplied relationships only; no effective grants or reachability inferred",
        },
        "sarif": {
            "$schema": (
                "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/"
                "sarif-schema-2.1.0.json"
            ),
            "version": "2.1.0",
            "runs": runs,
        },
    }


def review_change(payload: dict) -> dict:
    if not isinstance(payload, dict) or set(payload) - {
        "policy",
        "trust",
        "before_policy",
        "before_trust",
    }:
        raise InputError("Unsupported request fields")
    if not isinstance(payload.get("policy"), str) or any(
        not isinstance(v, str) for v in payload.values()
    ):
        raise InputError("Policy input fields must be JSON strings")
    if payload.get("before_trust", "").strip() and not payload.get("before_policy", "").strip():
        raise InputError("A before trust policy requires a before identity policy")
    rule_inventory()
    current = analyze_documents(payload["policy"], payload.get("trust", ""))
    before = (
        analyze_documents(payload["before_policy"], payload.get("before_trust", ""))
        if payload.get("before_policy", "").strip()
        else None
    )
    current_ids = {f["fingerprint"]: f for f in current["findings"]}
    before_ids = {f["fingerprint"]: f for f in before["findings"]} if before else {}
    configuration = {
        "mode": "static-identity-and-optional-trust",
        "compare": before is not None,
        "max_document_bytes": MAX_DOCUMENT_BYTES,
        "max_statements": MAX_STATEMENTS,
        "max_depth": MAX_DEPTH,
    }
    metadata = {
        **provenance(),
        "run_id": str(uuid.uuid4()),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "configuration": configuration,
        "configuration_sha256": checksum(json.dumps(configuration, sort_keys=True).encode()),
        "input_sha256": checksum(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()),
    }
    report = {
        **metadata,
        **current,
        "limitations": LIMITATIONS,
        "effective_permissions": "UNKNOWN",
        "delta": {
            "comparison_performed": before is not None,
            "before_count": len(before_ids) if before else None,
            "after_count": len(current_ids),
            "added": [current_ids[key] for key in sorted(current_ids.keys() - before_ids.keys())]
            if before
            else [],
            "removed": [before_ids[key] for key in sorted(before_ids.keys() - current_ids.keys())]
            if before
            else [],
            "interpretation": (
                "Rule/severity/message/statement-position changes; not measured AWS risk reduction"
            ),
        },
        "before_input_sha256": [s["sha256"] for s in before["sources"]] if before else [],
    }
    for run in report["sarif"]["runs"]:
        run["properties"].update(
            {
                key: metadata[key]
                for key in (
                    "run_id",
                    "source_commit",
                    "source_status",
                    "rule_set_sha256",
                    "timestamp_utc",
                    "configuration_sha256",
                    "input_sha256",
                    "app_version",
                )
            }
        )
    lines = [
        "IAM Permission Engineering Studio — static review",
        "Run: " + report["run_id"],
        "Source: " + report["source_commit"] + " (" + report["source_status"] + ")",
        "Engine version: " + __version__,
        "Effective permissions: UNKNOWN",
        "",
        *LIMITATIONS,
        "",
        "Findings:",
    ]
    for finding in report["findings"]:
        loc = finding["location"]
        lines += [
            f"{finding['severity'].upper()} {finding['rule_id']} "
            f"{loc['source']}:{loc['startLine']} {loc['json_pointer']}",
            finding["message"],
            "Remediation: " + finding["remediation"],
            "Counter-evidence: " + json.dumps(finding["counter_evidence"]),
            "Evidence:",
            loc["snippet"],
            "",
        ]
    lines += [
        "Delta: "
        + json.dumps(
            {
                key: report["delta"][key]
                for key in ("comparison_performed", "before_count", "after_count", "interpretation")
            }
        ),
        "Configuration SHA256: " + report["configuration_sha256"],
        "Input SHA256: " + report["input_sha256"],
    ]
    report["human_report"] = "\n".join(lines)
    return report
