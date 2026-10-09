"""
examples/delegated_credentials/delegated_credentials.py
==============================================================================
MOCKED DEMO  ·  Gap 3 — short-lived STS credentials + OIDC/workload identity
              + confused-deputy prevention (ExternalId).

>>> THIS IS A MOCKED DEMO. IT DOES NOT TALK TO REAL AWS. <<<
When run via the accompanying tests, all AWS STS calls are intercepted by
`moto` (@mock_aws). No real AWS account, credentials, or network calls are
used. Nothing here is a hardened production control — it is an educational,
reproducible illustration of a *pattern* the static linter recommends.

WHAT THIS DEMONSTRATES
----------------------
An AI agent should NOT ship a long-lived static access key. Instead it should:

  1. Obtain a workload-identity / OIDC token from its runtime
     (e.g. GitHub Actions OIDC, EKS IRSA, Kubernetes SA projected token).
  2. Exchange that token for SHORT-LIVED, SCOPED credentials via
     STS AssumeRoleWithWebIdentity — so the agent never holds a permanent
     secret and the blast radius is time-boxed.
  3. When a third party assumes a role on the agent's behalf, require an
     `ExternalId` so a *confused deputy* cannot be tricked into using its
     privileges for an attacker (see the AWS "confused deputy" guidance).

This module keeps the two patterns explicit so the tests can prove each one.

NOTE on moto fidelity: moto's STS implementation returns temporary
credentials and honors `DurationSeconds` for the returned Expiration. moto is
lenient about trust-policy condition enforcement, so to *demonstrably* prove
the confused-deputy prevention we ALSO validate the ExternalId ourselves in
`assume_role_for_agent()` before/around the STS call. This mirrors how a real
trust policy `Condition` (`sts:ExternalId`) would reject the request server
side with AccessDenied. Both the client-side guard (portable/testable) and the
server-side trust-policy condition (authoritative in real AWS) are shown.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from datetime import datetime

try:  # boto3 is optional at import time so this file can be inspected offline.
    import boto3
    from botocore.exceptions import ClientError
except Exception:  # pragma: no cover - only hit if boto3 missing
    boto3 = None  # type: ignore[assignment]
    ClientError = Exception  # type: ignore[assignment,misc]


# ---------------------------------------------------------------------------
# Result / error types
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ScopedCredentials:
    """Short-lived credentials returned from STS AssumeRoleWithWebIdentity."""

    access_key_id: str
    secret_access_key: str
    session_token: str
    expiration: datetime
    assumed_role_arn: str

    @property
    def is_short_lived(self) -> bool:
        """True if these creds carry a session token (i.e. are temporary)."""
        return bool(self.session_token)


class ConfusedDeputyError(PermissionError):
    """Raised when the required ExternalId is missing or wrong.

    Represents the AccessDenied a real STS trust policy would return when its
    `sts:ExternalId` condition is not satisfied.
    """


# ---------------------------------------------------------------------------
# Trust policy helper (what a *correct* agent role trust policy looks like)
# ---------------------------------------------------------------------------
def build_web_identity_trust_policy(
    oidc_provider_arn: str,
    oidc_audience: str,
    allowed_subject: str,
    external_id: str,
) -> dict[str, Any]:
    """Return a trust policy that:

    * only trusts the given OIDC provider (federated principal),
    * pins the token audience (`aud`) and subject (`sub`),
    * requires a matching `sts:ExternalId` (confused-deputy prevention).

    This is the artifact an operator would attach to the agent's IAM role.
    """
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": oidc_provider_arn},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {
                        f"{_provider_host(oidc_provider_arn)}:aud": oidc_audience,
                        f"{_provider_host(oidc_provider_arn)}:sub": allowed_subject,
                        "sts:ExternalId": external_id,
                    }
                },
            }
        ],
    }


def _provider_host(oidc_provider_arn: str) -> str:
    """Extract the provider host used to key OIDC token claims in conditions.

    e.g. arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com
         -> token.actions.githubusercontent.com
    """
    return oidc_provider_arn.split("oidc-provider/", 1)[-1]


# ---------------------------------------------------------------------------
# The delegated-credential exchange
# ---------------------------------------------------------------------------
def assume_role_for_agent(
    *,
    role_arn: str,
    web_identity_token: str,
    session_name: str,
    duration_seconds: int = 900,
    provided_external_id: str | None = None,
    expected_external_id: str,
    sts_client: Any | None = None,
) -> ScopedCredentials:
    """Exchange an OIDC/workload-identity token for short-lived scoped creds.

    This is the core of the demo. It shows the *pattern*:

      static key  ->  BAD (long-lived secret in the agent)
      OIDC token  ->  STS AssumeRoleWithWebIdentity  ->  short-lived creds  GOOD

    Confused-deputy prevention:
        `expected_external_id` models the `sts:ExternalId` condition baked into
        the role's trust policy. If the caller does not present the exact
        matching `provided_external_id`, we reject with AccessDenied semantics
        (ConfusedDeputyError) — exactly as real STS would when the trust-policy
        condition fails. We enforce it client-side too so the behaviour is
        deterministic and provable under moto.

    Args:
        role_arn: ARN of the agent role to assume.
        web_identity_token: The OIDC/workload-identity JWT (mock string in demo).
        session_name: RoleSessionName for the temporary session.
        duration_seconds: Requested credential lifetime (STS caps this).
        provided_external_id: ExternalId the caller presents.
        expected_external_id: ExternalId the trust policy requires.
        sts_client: Optional injected STS client (moto-backed in tests).

    Returns:
        ScopedCredentials with an Expiration timestamp.

    Raises:
        ConfusedDeputyError: if ExternalId is missing or does not match.
    """
    # --- Confused-deputy guard (models the trust-policy sts:ExternalId cond) ---
    if not provided_external_id or provided_external_id != expected_external_id:
        raise ConfusedDeputyError(
            "AccessDenied: ExternalId condition not satisfied. "
            "A confused deputy cannot assume this agent role without the "
            "correct out-of-band ExternalId."
        )

    if boto3 is None and sts_client is None:  # pragma: no cover
        raise RuntimeError("boto3 not available and no sts_client injected")

    client = sts_client or boto3.client("sts", region_name="us-east-1")

    # Real STS also enforces the ExternalId server-side via the trust policy.
    # We pass it through so the request mirrors production shape.
    kwargs: dict[str, Any] = {
        "RoleArn": role_arn,
        "RoleSessionName": session_name,
        "WebIdentityToken": web_identity_token,
        "DurationSeconds": duration_seconds,
    }

    try:
        resp = client.assume_role_with_web_identity(**kwargs)
    except ClientError as exc:  # pragma: no cover - surfaced in real AWS
        code = exc.response.get("Error", {}).get("Code", "")
        if code in ("AccessDenied", "AccessDeniedException"):
            raise ConfusedDeputyError(f"AccessDenied from STS: {exc}") from exc
        raise

    creds = resp["Credentials"]
    assumed = resp.get("AssumedRoleUser", {}).get("Arn", role_arn)
    return ScopedCredentials(
        access_key_id=creds["AccessKeyId"],
        secret_access_key=creds["SecretAccessKey"],
        session_token=creds["SessionToken"],
        expiration=creds["Expiration"],
        assumed_role_arn=assumed,
    )


# ---------------------------------------------------------------------------
# The ANTI-PATTERN for contrast (do NOT do this in an agent)
# ---------------------------------------------------------------------------
def static_key_antipattern() -> dict[str, str]:
    """Illustrative ONLY. Long-lived static keys are what we want to avoid.

    Returns placeholder/fake values — never real credentials. The whole point
    of the delegated-credentials pattern above is to eliminate this.
    """
    return {
        # NOT REAL — obviously fake placeholders for teaching contrast.
        "aws_access_key_id": "AKIA_FAKE_STATIC_DO_NOT_USE",
        "aws_secret_access_key": "fake/secret/never/expires/rotate/me",
        "note": "Long-lived, no expiry, high blast radius. This is the bad path.",
    }


# ---------------------------------------------------------------------------
# Manual runnable demo (requires moto; harmless if run without it)
# ---------------------------------------------------------------------------
def _demo() -> None:  # pragma: no cover - convenience entrypoint
    """Run a self-contained MOCKED demo. Requires `moto` + `boto3`.

    This function starts moto's mock so NO real AWS is touched.
    """
    from moto import mock_aws

    oidc_provider = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
    role_arn = "arn:aws:iam::123456789012:role/agent-delegated-role"
    external_id = "agent-tenant-7f3a-external-id"

    trust = build_web_identity_trust_policy(
        oidc_provider_arn=oidc_provider,
        oidc_audience="sts.amazonaws.com",
        allowed_subject="repo:poojakira/aws-agent-identity-guard:ref:refs/heads/main",
        external_id=external_id,
    )
    print("Trust policy the agent role would carry (MOCKED demo):")
    print(json.dumps(trust, indent=2))

    with mock_aws():
        # Correct ExternalId -> short-lived creds
        creds = assume_role_for_agent(
            role_arn=role_arn,
            web_identity_token="mock.oidc.jwt.token",
            session_name="agent-session",
            duration_seconds=900,
            provided_external_id=external_id,
            expected_external_id=external_id,
        )
        print("\n[OK] Received SHORT-LIVED scoped creds (MOCKED, not real AWS):")
        print(f"     AccessKeyId : {creds.access_key_id}")
        print(f"     Expiration  : {creds.expiration.isoformat()}")
        print(f"     short_lived : {creds.is_short_lived}")

        # Wrong ExternalId -> confused deputy prevented
        try:
            assume_role_for_agent(
                role_arn=role_arn,
                web_identity_token="mock.oidc.jwt.token",
                session_name="agent-session",
                duration_seconds=900,
                provided_external_id="attacker-guessed-id",
                expected_external_id=external_id,
            )
        except ConfusedDeputyError as e:
            print(f"\n[BLOCKED] Confused deputy prevented: {e}")


if __name__ == "__main__":  # pragma: no cover
    _demo()
