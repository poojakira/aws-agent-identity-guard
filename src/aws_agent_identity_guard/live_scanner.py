"""
src/aws_agent_identity_guard/live_scanner.py
──────────────────────────────────────────────────────────────────────────────
Real Boto3-based live AWS account scanner for AI agent IAM identities.

This module scans a live AWS account using IAM and CloudTrail APIs.
It requires AWS credentials with the following read-only permissions:

  iam:ListRoles
  iam:ListUsers
  iam:ListGroups
  iam:GetRole
  iam:GetUser
  iam:ListRolePolicies
  iam:ListAttachedRolePolicies
  iam:GetRolePolicy
  iam:GetPolicy
  iam:GetPolicyVersion
  iam:ListGroupsForUser
  iam:ListUserPolicies
  iam:GetUserPolicy
  iam:ListAttachedUserPolicies
  iam:ListPolicies
  iam:GetAccountAuthorizationDetails (covers the above in one call)
  cloudtrail:LookupEvents (for last-used evidence)
  access-analyzer:ValidatePolicy (optional, for IAM Access Analyzer)

Usage:
    from aws_agent_identity_guard.live_scanner import LiveAccountScanner
    scanner = LiveAccountScanner()
    report = scanner.scan_account()
    # report contains all roles, users, findings, and summary

CLI:
    aws-agent-identity-guard --live-scan --output-format json
    aws-agent-identity-guard --live-scan --output-format sarif --output scan.sarif
    aws-agent-identity-guard --live-scan --role-name my-agent-role
"""
from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from .scanner import Finding, scan_policy_document, scan_trust_policy

logger = logging.getLogger(__name__)

# ── Boto3 import with a clear error message ────────────────────────────────────
try:
    import boto3
    import botocore.exceptions
except ImportError as _boto_err:
    raise ImportError(
        "boto3 is required for live scanning. "
        "Install it with: pip install 'aws-agent-identity-guard[live]'"
    ) from _boto_err


# ── Data models ────────────────────────────────────────────────────────────────

@dataclass
class PolicySummary:
    """A single IAM policy document with its source metadata."""
    policy_name: str
    policy_arn: str | None
    policy_type: str          # "inline_role" | "managed" | "inline_user"
    attached_to: str          # role ARN, user ARN, or group ARN
    document: dict[str, Any]


@dataclass
class RoleSummary:
    """An IAM role with all its attached and inline policies."""
    role_name: str
    role_arn: str
    trust_policy: dict[str, Any]
    policies: list[PolicySummary] = field(default_factory=list)
    permission_boundary_arn: str | None = None
    last_used: str | None = None
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class UserSummary:
    """An IAM user with all its attached and inline policies."""
    user_name: str
    user_arn: str
    policies: list[PolicySummary] = field(default_factory=list)
    last_used: str | None = None
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class AccountScanReport:
    """Full report of a live account scan."""
    account_id: str
    scan_timestamp: str
    region: str
    roles_scanned: int
    users_scanned: int
    findings: list[dict[str, Any]]
    summary: dict[str, int]
    roles: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ── Live scanner ───────────────────────────────────────────────────────────────

class LiveAccountScanner:
    """Boto3-based live AWS IAM scanner.

    Enumerates all IAM roles and users in the account, collects their
    identity and trust policies, and runs the static analysis rules against
    each policy document.

    Parameters
    ----------
    session:
        An existing boto3.Session to use. If None, a default session is
        created using the standard credential chain (env vars, ~/.aws/,
        instance metadata, etc.).
    region:
        AWS region for API calls. Defaults to the session's default region.
    role_name_filter:
        If set, only scan the single role with this name.
    max_roles:
        Safety cap on number of roles to scan. Prevents runaway enumeration
        in large accounts. Default: 500.
    """

    def __init__(
        self,
        session: Any | None = None,
        region: str | None = None,
        role_name_filter: str | None = None,
        max_roles: int = 500,
    ) -> None:
        self._session = session or boto3.Session()
        self._region = region or self._session.region_name or "us-east-1"
        self._iam = self._session.client("iam", region_name=self._region)
        self._sts = self._session.client("sts", region_name=self._region)
        self._role_name_filter = role_name_filter
        self._max_roles = max_roles

    # ── Account identity ───────────────────────────────────────────────────────

    def _get_account_id(self) -> str:
        try:
            return self._sts.get_caller_identity()["Account"]
        except botocore.exceptions.ClientError as exc:
            logger.warning("Could not determine account ID: %s", exc)
            return "unknown"

    # ── Policy document collection ─────────────────────────────────────────────

    def _get_managed_policy_document(self, policy_arn: str) -> dict[str, Any] | None:
        """Fetch the current default version of a managed policy document."""
        try:
            policy_meta = self._iam.get_policy(PolicyArn=policy_arn)["Policy"]
            version_id = policy_meta["DefaultVersionId"]
            version = self._iam.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=version_id,
            )
            return version["PolicyVersion"]["Document"]
        except botocore.exceptions.ClientError as exc:
            logger.warning("Could not fetch policy %s: %s", policy_arn, exc)
            return None

    def _collect_role_policies(self, role_name: str, role_arn: str) -> list[PolicySummary]:
        """Collect all inline and attached managed policies for a role."""
        policies: list[PolicySummary] = []

        # Inline policies
        try:
            paginator = self._iam.get_paginator("list_role_policies")
            for page in paginator.paginate(RoleName=role_name):
                for policy_name in page.get("PolicyNames", []):
                    try:
                        resp = self._iam.get_role_policy(
                            RoleName=role_name,
                            PolicyName=policy_name,
                        )
                        policies.append(PolicySummary(
                            policy_name=policy_name,
                            policy_arn=None,
                            policy_type="inline_role",
                            attached_to=role_arn,
                            document=resp["PolicyDocument"],
                        ))
                    except botocore.exceptions.ClientError as exc:
                        logger.warning("Could not fetch inline policy %s/%s: %s", role_name, policy_name, exc)
        except botocore.exceptions.ClientError as exc:
            logger.warning("Could not list inline policies for role %s: %s", role_name, exc)

        # Attached managed policies
        try:
            paginator = self._iam.get_paginator("list_attached_role_policies")
            for page in paginator.paginate(RoleName=role_name):
                for policy in page.get("AttachedPolicies", []):
                    doc = self._get_managed_policy_document(policy["PolicyArn"])
                    if doc is not None:
                        policies.append(PolicySummary(
                            policy_name=policy["PolicyName"],
                            policy_arn=policy["PolicyArn"],
                            policy_type="managed",
                            attached_to=role_arn,
                            document=doc,
                        ))
        except botocore.exceptions.ClientError as exc:
            logger.warning("Could not list attached policies for role %s: %s", role_name, exc)

        return policies

    def _collect_user_policies(self, user_name: str, user_arn: str) -> list[PolicySummary]:
        """Collect all inline and attached managed policies for a user."""
        policies: list[PolicySummary] = []

        # Inline policies
        try:
            paginator = self._iam.get_paginator("list_user_policies")
            for page in paginator.paginate(UserName=user_name):
                for policy_name in page.get("PolicyNames", []):
                    try:
                        resp = self._iam.get_user_policy(
                            UserName=user_name,
                            PolicyName=policy_name,
                        )
                        policies.append(PolicySummary(
                            policy_name=policy_name,
                            policy_arn=None,
                            policy_type="inline_user",
                            attached_to=user_arn,
                            document=resp["PolicyDocument"],
                        ))
                    except botocore.exceptions.ClientError as exc:
                        logger.warning("Could not fetch inline user policy %s/%s: %s", user_name, policy_name, exc)
        except botocore.exceptions.ClientError as exc:
            logger.warning("Could not list inline user policies for %s: %s", user_name, exc)

        # Attached managed policies
        try:
            paginator = self._iam.get_paginator("list_attached_user_policies")
            for page in paginator.paginate(UserName=user_name):
                for policy in page.get("AttachedPolicies", []):
                    doc = self._get_managed_policy_document(policy["PolicyArn"])
                    if doc is not None:
                        policies.append(PolicySummary(
                            policy_name=policy["PolicyName"],
                            policy_arn=policy["PolicyArn"],
                            policy_type="managed",
                            attached_to=user_arn,
                            document=doc,
                        ))
        except botocore.exceptions.ClientError as exc:
            logger.warning("Could not list attached user policies for %s: %s", user_name, exc)

        return policies

    # ── Role and user enumeration ──────────────────────────────────────────────

    def _enumerate_roles(self) -> list[RoleSummary]:
        """List all IAM roles (or just the filtered one)."""
        roles: list[RoleSummary] = []
        try:
            if self._role_name_filter:
                resp = self._iam.get_role(RoleName=self._role_name_filter)
                role_list = [resp["Role"]]
            else:
                paginator = self._iam.get_paginator("list_roles")
                role_list = []
                for page in paginator.paginate():
                    role_list.extend(page.get("Roles", []))
                    if len(role_list) >= self._max_roles:
                        logger.warning("Role cap (%d) reached — truncating.", self._max_roles)
                        role_list = role_list[: self._max_roles]
                        break
        except botocore.exceptions.ClientError as exc:
            logger.error("Could not enumerate roles: %s", exc)
            return roles

        for role_data in role_list:
            role_name = role_data["RoleName"]
            role_arn = role_data["Arn"]
            trust_policy = role_data.get("AssumeRolePolicyDocument", {})
            boundary_arn = (
                role_data.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn")
            )
            last_used = None
            if "RoleLastUsed" in role_data:
                lu = role_data["RoleLastUsed"].get("LastUsedDate")
                if lu:
                    last_used = lu.isoformat() if hasattr(lu, "isoformat") else str(lu)

            tags_list = role_data.get("Tags", [])
            tags = {t["Key"]: t["Value"] for t in tags_list}

            policies = self._collect_role_policies(role_name, role_arn)
            roles.append(RoleSummary(
                role_name=role_name,
                role_arn=role_arn,
                trust_policy=trust_policy,
                policies=policies,
                permission_boundary_arn=boundary_arn,
                last_used=last_used,
                tags=tags,
            ))

        return roles

    def _enumerate_users(self) -> list[UserSummary]:
        """List all IAM users in the account."""
        users: list[UserSummary] = []
        try:
            paginator = self._iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user_data in page.get("Users", []):
                    user_name = user_data["UserName"]
                    user_arn = user_data["Arn"]
                    tags_resp = []
                    try:
                        tags_resp = self._iam.list_user_tags(UserName=user_name).get("Tags", [])
                    except botocore.exceptions.ClientError:
                        pass
                    tags = {t["Key"]: t["Value"] for t in tags_resp}
                    policies = self._collect_user_policies(user_name, user_arn)
                    users.append(UserSummary(
                        user_name=user_name,
                        user_arn=user_arn,
                        policies=policies,
                        tags=tags,
                    ))
        except botocore.exceptions.ClientError as exc:
            logger.error("Could not enumerate users: %s", exc)

        return users

    # ── Finding generation ─────────────────────────────────────────────────────

    def _scan_role(self, role: RoleSummary) -> list[dict[str, Any]]:
        """Run all static rules against a role's trust policy and identity policies."""
        all_findings: list[dict[str, Any]] = []

        # Trust policy
        for f in scan_trust_policy(role.trust_policy):
            d = f.to_dict()
            d["source"] = "trust_policy"
            d["resource_arn"] = role.role_arn
            d["resource_name"] = role.role_name
            all_findings.append(d)

        # Identity policies
        for policy in role.policies:
            for f in scan_policy_document(policy.document):
                d = f.to_dict()
                d["source"] = "identity_policy"
                d["resource_arn"] = role.role_arn
                d["resource_name"] = role.role_name
                d["policy_name"] = policy.policy_name
                d["policy_arn"] = policy.policy_arn
                d["policy_type"] = policy.policy_type
                all_findings.append(d)

        # Permission boundary note
        if role.permission_boundary_arn is None and any(
            f["severity"] in ("critical", "high") for f in all_findings
        ):
            all_findings.append({
                "rule_id": "AIG-PB001",
                "severity": "medium",
                "message": f"Role {role.role_name} has high/critical findings and no permission boundary.",
                "remediation": "Attach a permission boundary to cap the maximum permissions this role can use.",
                "source": "configuration",
                "resource_arn": role.role_arn,
                "resource_name": role.role_name,
                "policy_name": None,
                "policy_arn": None,
                "policy_type": None,
                "statement_index": None,
            })

        return all_findings

    # ── Main scan entry point ──────────────────────────────────────────────────

    def scan_account(self) -> AccountScanReport:
        """Scan the live AWS account and return a structured report.

        Returns
        -------
        AccountScanReport
            Contains all findings, role summaries, error list, and severity counts.

        Raises
        ------
        botocore.exceptions.NoCredentialsError
            If no valid AWS credentials are configured.
        botocore.exceptions.ClientError
            On unrecoverable AWS API errors (e.g. access denied to iam:ListRoles).
        """
        account_id = self._get_account_id()
        scan_ts = datetime.now(tz=timezone.utc).isoformat()
        all_findings: list[dict[str, Any]] = []
        role_rows: list[dict[str, Any]] = []
        errors: list[str] = []

        logger.info("Scanning account %s (region=%s)", account_id, self._region)

        # Scan roles
        roles = self._enumerate_roles()
        for role in roles:
            findings = self._scan_role(role)
            all_findings.extend(findings)
            role_rows.append({
                "role_name": role.role_name,
                "role_arn": role.role_arn,
                "last_used": role.last_used,
                "permission_boundary": role.permission_boundary_arn,
                "findings_count": len(findings),
                "critical": sum(1 for f in findings if f["severity"] == "critical"),
                "high": sum(1 for f in findings if f["severity"] == "high"),
                "medium": sum(1 for f in findings if f["severity"] == "medium"),
                "tags": role.tags,
            })

        # Scan users
        users = self._enumerate_users()
        for user in users:
            for policy in user.policies:
                for f in scan_policy_document(policy.document):
                    d = f.to_dict()
                    d["source"] = "identity_policy"
                    d["resource_arn"] = user.user_arn
                    d["resource_name"] = user.user_name
                    d["policy_name"] = policy.policy_name
                    d["policy_arn"] = policy.policy_arn
                    d["policy_type"] = policy.policy_type
                    all_findings.append(d)

        severity_counts = {
            "critical": sum(1 for f in all_findings if f["severity"] == "critical"),
            "high": sum(1 for f in all_findings if f["severity"] == "high"),
            "medium": sum(1 for f in all_findings if f["severity"] == "medium"),
            "low": sum(1 for f in all_findings if f["severity"] == "low"),
            "total": len(all_findings),
        }

        return AccountScanReport(
            account_id=account_id,
            scan_timestamp=scan_ts,
            region=self._region,
            roles_scanned=len(roles),
            users_scanned=len(users),
            findings=all_findings,
            summary=severity_counts,
            roles=role_rows,
            errors=errors,
        )

    def scan_role_by_name(self, role_name: str) -> list[dict[str, Any]]:
        """Scan a single named role and return its findings.

        Convenience method for CI/CD pipelines that scan one role per run.

        Parameters
        ----------
        role_name:
            The IAM role name (not ARN).

        Returns
        -------
        list[dict]
            Findings for this role only.
        """
        try:
            resp = self._iam.get_role(RoleName=role_name)
        except botocore.exceptions.ClientError as exc:
            raise ValueError(f"Role {role_name!r} not found or access denied: {exc}") from exc

        role_data = resp["Role"]
        role = RoleSummary(
            role_name=role_name,
            role_arn=role_data["Arn"],
            trust_policy=role_data.get("AssumeRolePolicyDocument", {}),
            policies=self._collect_role_policies(role_name, role_data["Arn"]),
            permission_boundary_arn=(
                role_data.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn")
            ),
        )
        return self._scan_role(role)
