"""AWS Agent Identity Guard - Comprehensive IAM security analysis and runtime authorization for AI agents.

This package provides tools for analyzing AWS IAM policies, detecting privilege escalation
paths, enforcing least-privilege principles, and providing real-time authorization decisions
for AI agent actions.

Core capabilities:
- Policy document scanning and finding generation
- Effective permission analysis across complex IAM hierarchies
- Intent alignment verification for agent actions
- Attack path detection and escalation risk scoring
- Runtime authorization with approval workflows
- Behavioral drift detection and enforcement
- Observability with structured logging, metrics, and audit trails
- Least-privilege policy generation and recommendation
"""

__version__ = "1.0.0"

# Eager imports for core scanning functionality (lightweight, always needed)
from aws_agent_identity_guard.scanner import Finding, scan_policy_document, scan_trust_policy

# Lazy import mappings: symbol -> (module_path, attribute_name)
_LAZY_IMPORTS: dict = {
    # models
    "Agent": (".models", "Agent"),
    "AuthorizationRequest": (".models", "AuthorizationRequest"),
    "AuthorizationDecision": (".models", "AuthorizationDecision"),
    "RiskScore": (".models", "RiskScore"),
    # effective_permissions
    "EffectivePermissionAnalyzer": (".effective_permissions", "EffectivePermissionAnalyzer"),
    # intent_alignment
    "IntentAlignmentEngine": (".intent_alignment", "IntentAlignmentEngine"),
    # capability_inventory
    "CapabilityInventory": (".capability_inventory", "CapabilityInventory"),
    "CapabilityGraph": (".capability_inventory", "CapabilityGraph"),
    # attack_paths
    "AttackPathAnalyzer": (".attack_paths", "AttackPathAnalyzer"),
    # escalation_engine
    "EscalationEngine": (".escalation_engine", "EscalationEngine"),
    # risk_engine
    "RiskEngine": (".risk_engine", "RiskEngine"),
    # authorization
    "AuthorizationService": (".authorization", "AuthorizationService"),
    # approval
    "ApprovalService": (".approval", "ApprovalService"),
    # policy_engine
    "PolicyEngine": (".policy_engine", "PolicyEngine"),
    # drift_detector
    "DriftDetector": (".drift_detector", "DriftDetector"),
    # behavior_analyzer
    "BehaviorAnalyzer": (".behavior_analyzer", "BehaviorAnalyzer"),
    # enforcement
    "EnforcementEngine": (".enforcement", "EnforcementEngine"),
    # observability
    "MetricsCollector": (".observability", "MetricsCollector"),
    "StructuredLogger": (".observability", "StructuredLogger"),
    "AuditTrail": (".observability", "AuditTrail"),
    # least_privilege
    "LeastPrivilegeEngine": (".least_privilege", "LeastPrivilegeEngine"),
    # api
    "APIServer": (".api", "APIServer"),
}


def __getattr__(name: str):
    """Lazy-load modules and symbols on first access to minimize import overhead."""
    if name in _LAZY_IMPORTS:
        module_path, attr_name = _LAZY_IMPORTS[name]
        import importlib

        module = importlib.import_module(module_path, package=__name__)
        value = getattr(module, attr_name)
        # Cache in module namespace for subsequent access
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    # Version
    "__version__",
    # Core scanning
    "Finding",
    "scan_policy_document",
    "scan_trust_policy",
    # Models
    "Agent",
    "AuthorizationRequest",
    "AuthorizationDecision",
    "RiskScore",
    # Effective permissions
    "EffectivePermissionAnalyzer",
    # Intent alignment
    "IntentAlignmentEngine",
    # Capability inventory
    "CapabilityInventory",
    "CapabilityGraph",
    # Attack paths
    "AttackPathAnalyzer",
    # Escalation engine
    "EscalationEngine",
    # Risk engine
    "RiskEngine",
    # Authorization
    "AuthorizationService",
    # Approval
    "ApprovalService",
    # Policy engine
    "PolicyEngine",
    # Drift detector
    "DriftDetector",
    # Behavior analyzer
    "BehaviorAnalyzer",
    # Enforcement
    "EnforcementEngine",
    # Observability
    "MetricsCollector",
    "StructuredLogger",
    "AuditTrail",
    # Least privilege
    "LeastPrivilegeEngine",
    # API
    "APIServer",
]
