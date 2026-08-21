"""AWS Agent Identity Guard - Runtime authorization for AI agents."""

from aws_agent_identity_guard.scanner import scan_policy_document, scan_trust_policy
from aws_agent_identity_guard.sdk import (
    AgentIdentityGuard,
    AgentInfo,
    ApprovalInfo,
    AttackPathInfo,
    AuthorizationError,
    Decision,
    GuardError,
    PermissionInfo,
    RiskScoreInfo,
)
from aws_agent_identity_guard.sdk import (
    ConnectionError as GuardConnectionError,
)
from aws_agent_identity_guard.sdk import (
    TimeoutError as GuardTimeoutError,
)

__version__ = "1.0.0"
__all__ = [
    "scan_policy_document",
    "scan_trust_policy",
    "AgentIdentityGuard",
    "Decision",
    "AgentInfo",
    "PermissionInfo",
    "AttackPathInfo",
    "RiskScoreInfo",
    "ApprovalInfo",
    "GuardError",
    "AuthorizationError",
    "GuardConnectionError",
    "GuardTimeoutError",
]
