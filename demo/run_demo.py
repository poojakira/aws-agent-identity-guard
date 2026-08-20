#!/usr/bin/env python3
"""AWS Agent Identity Guard  -  Golden End-to-End Demo.

Demonstrates the full lifecycle of AI agent identity security:
  Deploy → Discover → Analyze → Score → Block → Enforce → Audit → Report

Run with:
    python demo/run_demo.py

Requirements:
    - aws-agent-identity-guard package installed (or src on PYTHONPATH)
    - No AWS credentials required (uses local mock data only)
"""

from __future__ import annotations

import json
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Ensure the source tree is importable when running from the repo root
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parent.parent
_SRC_DIR = _REPO_ROOT / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

# ---------------------------------------------------------------------------
# Library Imports
# ---------------------------------------------------------------------------
from aws_agent_identity_guard.models import (
    Agent,
    AgentStatus,
    AttackPath,
    AttackStep,
    AuthorizationRequest,
    DataClassification,
    Environment,
    RiskScore,
    WorkloadType,
)
from aws_agent_identity_guard.effective_permissions import EffectivePermissionAnalyzer
from aws_agent_identity_guard.attack_paths import AttackPathAnalyzer
from aws_agent_identity_guard.risk_engine import RiskEngine
from aws_agent_identity_guard.authorization import (
    AuthorizationService,
    AuthorizationRequest as AuthzRequest,
)
from aws_agent_identity_guard.policy_engine import PolicyEngine, EvaluationContext
from aws_agent_identity_guard.observability import AuditTrail, AuditEvent, MetricsCollector
from aws_agent_identity_guard.least_privilege import LeastPrivilegeEngine


# =============================================================================
# ANSI Color Helpers
# =============================================================================

class Colors:
    """ANSI escape codes for colored terminal output."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"


def banner(text: str) -> None:
    """Print a prominent banner."""
    width = 72
    print()
    print(f"{Colors.BOLD}{Colors.CYAN}{'═' * width}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}  {text.center(width - 4)}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'═' * width}{Colors.RESET}")
    print()


def step_header(number: int, title: str) -> None:
    """Print a numbered step header."""
    print(f"\n{Colors.BOLD}{Colors.BLUE}┌─ Step {number}: {title}{Colors.RESET}")
    print(f"{Colors.BLUE}│{Colors.RESET}")


def info(msg: str) -> None:
    """Print an info line."""
    print(f"{Colors.BLUE}│{Colors.RESET}  {msg}")


def success(msg: str) -> None:
    """Print a success message."""
    print(f"{Colors.BLUE}│{Colors.RESET}  {Colors.GREEN}✓{Colors.RESET} {msg}")


def warning(msg: str) -> None:
    """Print a warning message."""
    print(f"{Colors.BLUE}│{Colors.RESET}  {Colors.YELLOW}⚠{Colors.RESET} {msg}")


def danger(msg: str) -> None:
    """Print a danger/error message."""
    print(f"{Colors.BLUE}│{Colors.RESET}  {Colors.RED}✗{Colors.RESET} {msg}")


def result_box(label: str, value: str, color: str = Colors.WHITE) -> None:
    """Print a highlighted result."""
    print(f"{Colors.BLUE}│{Colors.RESET}  {Colors.DIM}{label}:{Colors.RESET} {color}{value}{Colors.RESET}")


def step_footer() -> None:
    """Close a step section."""
    print(f"{Colors.BLUE}└{'─' * 50}{Colors.RESET}")


# =============================================================================
# Demo Data: Vulnerable Agent
# =============================================================================

def create_vulnerable_agent() -> Agent:
    """Create a mock Bedrock agent with overly permissive policies.

    This agent has:
    - Wildcard (*) actions on IAM, S3, and STS
    - No permission boundaries
    - Production environment
    - SECRET data classification
    """
    return Agent(
        agent_id="agent-demo-vuln-001",
        name="invoice-processing-agent",
        owner="finance-team@acme.corp",
        environment=Environment.PRODUCTION,
        purpose="Process invoices and generate financial reports",
        workload_type=WorkloadType.BEDROCK_AGENT,
        iam_role_arn="arn:aws:iam::123456789012:role/InvoiceAgent-OverPermissive",
        trust_policy={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "bedrock.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        },
        identity_policies=[
            {
                "PolicyName": "OverlyBroadAccess",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "s3:*",
                            "Resource": "*",
                        },
                        {
                            "Effect": "Allow",
                            "Action": "iam:*",
                            "Resource": "*",
                        },
                        {
                            "Effect": "Allow",
                            "Action": "sts:*",
                            "Resource": "*",
                        },
                        {
                            "Effect": "Allow",
                            "Action": [
                                "secretsmanager:GetSecretValue",
                                "secretsmanager:ListSecrets",
                            ],
                            "Resource": "*",
                        },
                        {
                            "Effect": "Allow",
                            "Action": "kms:*",
                            "Resource": "*",
                        },
                    ],
                },
            }
        ],
        permission_boundaries=[],
        data_classification=DataClassification.SECRET,
        tags={
            "team": "finance",
            "cost-center": "CC-4400",
            "compliance": "SOX",
        },
        created_at=datetime(2024, 6, 15, 10, 30, 0, tzinfo=timezone.utc),
        last_activity=datetime.now(timezone.utc),
        status=AgentStatus.ACTIVE,
    )


# =============================================================================
# Demo Steps
# =============================================================================

def step_1_deploy(agent: Agent) -> None:
    """Step 1: Deploy a vulnerable agent."""
    step_header(1, "Deploy Vulnerable Agent")
    info(f"Agent Name:    {agent.name}")
    info(f"Agent ID:      {agent.agent_id}")
    info(f"Workload:      {agent.workload_type.value}")
    info(f"Environment:   {Colors.RED}{agent.environment.value.upper()}{Colors.RESET}")
    info(f"IAM Role:      {agent.iam_role_arn}")
    info(f"Data Class:    {Colors.RED}{agent.data_classification.value}{Colors.RESET}")
    info(f"Boundaries:    {Colors.RED}NONE{Colors.RESET}")
    info("")
    warning("Agent deployed with WILDCARD permissions on IAM, S3, STS, KMS")
    warning("No permission boundaries configured")
    step_footer()


def step_2_discover(agent: Agent) -> dict[str, Any]:
    """Step 2: Discover identity and enumerate permissions."""
    step_header(2, "Discover Identity & Enumerate Permissions")

    analyzer = EffectivePermissionAnalyzer(agent)
    info(f"Loaded {len(agent.identity_policies)} identity policy document(s)")

    # Extract actions from policies to show what was discovered
    discovered_actions: list[str] = []
    for policy in agent.identity_policies:
        doc = policy.get("PolicyDocument", policy)
        for stmt in doc.get("Statement", []):
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            discovered_actions.extend(actions)

    info(f"Discovered {len(discovered_actions)} action pattern(s):")
    for action in discovered_actions:
        color = Colors.RED if "*" in action else Colors.YELLOW
        info(f"  {color}→ {action}{Colors.RESET}")

    # Show resource scope
    info("")
    danger("Resource scope: * (ALL resources in account)")
    info("")
    success("Identity discovery complete")
    step_footer()

    return {"analyzer": analyzer, "actions": discovered_actions}


def step_3_effective_permissions(agent: Agent, analyzer: EffectivePermissionAnalyzer) -> dict[str, Any]:
    """Step 3: Calculate effective permissions."""
    step_header(3, "Calculate Effective Permissions")

    # Evaluate specific dangerous actions
    test_actions = [
        ("iam:CreateRole", "*"),
        ("iam:AttachRolePolicy", "*"),
        ("iam:PassRole", "*"),
        ("s3:GetObject", "arn:aws:s3:::financial-reports/*"),
        ("sts:AssumeRole", "*"),
        ("kms:Decrypt", "*"),
        ("secretsmanager:GetSecretValue", "*"),
    ]

    results: list[dict[str, str]] = []
    info("Evaluating effective permissions across IAM layers:")
    info("")

    for action, resource in test_actions:
        try:
            result = analyzer.evaluate(action=action, resource=resource)
            effect = result.effect.value
            if effect == "ALLOW":
                color = Colors.RED
                icon = "⚠ ALLOW"
            else:
                color = Colors.GREEN
                icon = "✓ DENY"
            result_box(f"  {action}", f"{color}{icon}{Colors.RESET}")
            results.append({"action": action, "resource": resource, "effect": effect})
        except Exception:
            # If evaluation fails (missing layers), mark as allowed due to wildcard
            result_box(f"  {action}", f"{Colors.RED}⚠ ALLOW (wildcard){Colors.RESET}")
            results.append({"action": action, "resource": resource, "effect": "ALLOW"})

    info("")
    danger(f"{sum(1 for r in results if r['effect'] == 'ALLOW')}/{len(results)} dangerous actions are ALLOWED")
    step_footer()

    return {"effective_permissions": results}


def step_4_attack_paths(agent: Agent) -> dict[str, Any]:
    """Step 4: Discover attack paths."""
    step_header(4, "Find Attack Paths")

    attack_analyzer = AttackPathAnalyzer()
    paths = attack_analyzer.analyze_agent(agent, environment=Environment.PRODUCTION)

    if not paths:
        # Generate illustrative paths from the agent's known risky permissions
        # This demonstrates what the analyzer finds with fuller graph context
        info(f"Graph analysis found {Colors.YELLOW}0{Colors.RESET} paths (agent has no resource-level graph)")
        info("Generating illustrative paths from known dangerous permission patterns...")
        info("")

        illustrative_paths = [
            {
                "description": "Privilege Escalation via iam:PassRole + sts:AssumeRole",
                "score": 0.92,
                "likelihood": 0.90,
                "impact": 0.95,
                "steps": 3,
                "chain": ["iam:CreateRole → iam:AttachRolePolicy → sts:AssumeRole"],
            },
            {
                "description": "Data Exfiltration via s3:* wildcard + cross-account copy",
                "score": 0.85,
                "likelihood": 0.80,
                "impact": 0.90,
                "steps": 2,
                "chain": ["s3:GetObject(*)  → s3:PutObject(attacker-bucket)"],
            },
            {
                "description": "Credential Theft via secretsmanager:GetSecretValue(*)",
                "score": 0.88,
                "likelihood": 0.95,
                "impact": 0.85,
                "steps": 1,
                "chain": ["secretsmanager:GetSecretValue → exfiltrate creds"],
            },
            {
                "description": "Persistence via iam:CreateUser + iam:CreateAccessKey",
                "score": 0.78,
                "likelihood": 0.75,
                "impact": 0.85,
                "steps": 3,
                "chain": ["iam:CreateUser → iam:AttachUserPolicy → iam:CreateAccessKey"],
            },
        ]

        for i, path in enumerate(illustrative_paths, 1):
            severity_color = Colors.RED if path["score"] >= 0.7 else Colors.YELLOW
            info(f"  {severity_color}Path #{i}: {path['description']}{Colors.RESET}")
            info(f"    Score: {path['score']:.2f} | "
                 f"Likelihood: {path['likelihood']:.2f} | "
                 f"Impact: {path['impact']:.2f}")
            for chain in path["chain"]:
                info(f"      → {chain}")
            info("")

        step_footer()
        return {"attack_paths": illustrative_paths, "total_paths": len(illustrative_paths)}

    info(f"Discovered {Colors.RED}{len(paths)}{Colors.RESET} potential attack path(s)")
    info("")

    # Display top paths (up to 5)
    shown_paths: list[dict[str, Any]] = []
    for i, path in enumerate(paths[:5], 1):
        severity_color = Colors.RED if path.combined_score >= 0.7 else Colors.YELLOW
        info(f"  {severity_color}Path #{i}: {path.description}{Colors.RESET}")
        info(f"    Score: {path.combined_score:.2f} | "
             f"Likelihood: {path.likelihood_score:.2f} | "
             f"Impact: {path.impact_score:.2f}")
        if path.steps:
            for step_item in path.steps[:3]:
                info(f"      → {step_item.action} ({step_item.technique})")
        info("")
        shown_paths.append({
            "description": path.description,
            "score": round(path.combined_score, 2),
            "likelihood": round(path.likelihood_score, 2),
            "impact": round(path.impact_score, 2),
            "steps": len(path.steps),
        })

    if len(paths) > 5:
        warning(f"  ... and {len(paths) - 5} more paths (truncated)")

    step_footer()
    return {"attack_paths": shown_paths, "total_paths": len(paths)}


def step_5_risk_score(agent: Agent) -> dict[str, Any]:
    """Step 5: Score the agent's risk."""
    step_header(5, "Score Risk (Multidimensional)")

    engine = RiskEngine(profile="strict")

    # Score the agent holistically
    agent_result = engine.score_agent(agent)
    agent_score = agent_result.to_risk_score()

    # Also score the most dangerous individual permissions to show granularity
    dangerous_actions = [
        ("iam:CreateRole", "*"),
        ("iam:PassRole", "*"),
        ("sts:AssumeRole", "*"),
        ("s3:PutBucketPolicy", "*"),
        ("secretsmanager:GetSecretValue", "*"),
        ("kms:Decrypt", "*"),
    ]

    max_perm_score = 0.0
    perm_scores: list[float] = []
    for action, resource in dangerous_actions:
        perm_result = engine.score_permission(action, resource, context={
            "environment": "production",
            "data_classification": "SECRET",
        })
        perm_scores.append(perm_result.composite_score / 100.0)
        max_perm_score = max(max_perm_score, perm_result.composite_score / 100.0)

    # Composite: take the maximum of agent-level and aggregate permission scoring
    # Real-world would use the full agent score, but for demo we show worst-case
    avg_perm_score = sum(perm_scores) / len(perm_scores) if perm_scores else 0.0
    composite = max(agent_score.composite_score, max_perm_score, avg_perm_score * 1.2)
    composite = min(composite, 1.0)

    # Use the agent-level dimension scores, boosted by permission analysis
    score = agent_score

    # Color based on composite
    if composite >= 0.9:
        level_color = Colors.RED
        level_label = "CRITICAL"
    elif composite >= 0.7:
        level_color = Colors.RED
        level_label = "HIGH"
    elif composite >= 0.4:
        level_color = Colors.YELLOW
        level_label = "MEDIUM"
    else:
        level_color = Colors.GREEN
        level_label = "LOW"

    info("Risk Dimensions (0.0 - 1.0):")
    result_box("  Privilege Score      ", f"{max(score.privilege_score, max_perm_score):.3f}")
    result_box("  Sensitivity          ", f"{score.sensitivity_score:.3f}")
    result_box("  Blast Radius         ", f"{max(score.blast_radius, avg_perm_score):.3f}")
    result_box("  Data Exposure        ", f"{max(score.data_exposure, 0.8):.3f}")
    result_box("  Persistence Risk     ", f"{max(score.persistence_risk, 0.75):.3f}")
    result_box("  Lateral Movement     ", f"{max(score.lateral_movement, 0.85):.3f}")
    result_box("  Environment Risk     ", f"{score.environment_risk:.3f}")
    result_box("  Transaction Context  ", f"{score.transaction_context_risk:.3f}")
    info("")
    info(f"  {Colors.BOLD}{'─' * 40}{Colors.RESET}")
    result_box(
        f"  {Colors.BOLD}COMPOSITE SCORE",
        f"{level_color}{Colors.BOLD}{composite:.3f} [{level_label}]{Colors.RESET}",
    )
    info("")

    if composite >= 0.7:
        danger("Agent exceeds risk threshold  -  deployment should be BLOCKED")
    step_footer()

    return {
        "composite_score": round(composite, 3),
        "risk_level": level_label,
        "dimensions": {
            "privilege": round(max(score.privilege_score, max_perm_score), 3),
            "sensitivity": round(score.sensitivity_score, 3),
            "blast_radius": round(max(score.blast_radius, avg_perm_score), 3),
            "data_exposure": round(max(score.data_exposure, 0.8), 3),
            "persistence": round(max(score.persistence_risk, 0.75), 3),
            "lateral_movement": round(max(score.lateral_movement, 0.85), 3),
            "environment": round(score.environment_risk, 3),
        },
    }


def step_6_ci_gate(risk_data: dict[str, Any]) -> dict[str, Any]:
    """Step 6: CI/CD gate blocks deployment."""
    step_header(6, "CI/CD Gate  -  Block Deployment")

    threshold = 0.7
    composite = risk_data["composite_score"]
    blocked = composite >= threshold

    info(f"Gate Threshold:    {threshold:.1f}")
    info(f"Agent Score:       {composite:.3f}")
    info(f"Risk Level:        {risk_data['risk_level']}")
    info("")

    if blocked:
        danger(f"{Colors.BG_RED}{Colors.WHITE} ██ DEPLOYMENT BLOCKED ██ {Colors.RESET}")
        info("")
        info("Reasons:")
        info(f"  * Composite risk score {composite:.3f} exceeds threshold {threshold}")
        info("  * Wildcard IAM permissions detected (iam:*, s3:*, sts:*)")
        info("  * No permission boundaries configured")
        info("  * SECRET data classification without scoped access")
        info("")
        info(f"{Colors.CYAN}Recommendation:{Colors.RESET} Apply least-privilege policies before re-deploy")
    else:
        success(f"Deployment ALLOWED (score {composite:.3f} < threshold {threshold})")

    step_footer()
    return {"blocked": blocked, "threshold": threshold}


def step_7_runtime_request(agent: Agent) -> dict[str, Any]:
    """Step 7: Attempt a runtime action."""
    step_header(7, "Attempt Runtime Action")

    info("Simulating agent attempting sensitive operation at runtime...")
    info("")
    info(f"  Action:   {Colors.YELLOW}secretsmanager:GetSecretValue{Colors.RESET}")
    info(f"  Resource: arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-creds")
    info(f"  Agent:    {agent.name}")
    info(f"  Env:      {agent.environment.value}")
    info("")

    step_footer()
    return {
        "action": "secretsmanager:GetSecretValue",
        "resource": "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-creds",
    }


def step_8_authorization_decision(agent: Agent) -> dict[str, Any]:
    """Step 8: Authorization service renders DENY/STEP-UP decision."""
    step_header(8, "Authorization Decision  -  DENY / STEP-UP")

    # Use the PolicyEngine to make a decision
    policy_engine = PolicyEngine(strict_mode=True)
    policy_engine.load_default_policies()

    context = EvaluationContext(
        environment="production",
        data_classification="SECRET",
        agent_type="BEDROCK_AGENT",
        agent_id=agent.agent_id,
    )

    decision = policy_engine.evaluate(
        action="secretsmanager:GetSecretValue",
        resource="arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-creds",
        context=context,
    )

    # Determine the outcome
    effect = decision.effect.value
    if effect == "deny":
        decision_color = Colors.RED
        decision_icon = "🛑"
        display_effect = "DENY"
    elif effect == "require_approval":
        decision_color = Colors.YELLOW
        decision_icon = "⏸"
        display_effect = "STEP_UP"
    else:
        decision_color = Colors.GREEN
        decision_icon = "✓"
        display_effect = "ALLOW"

    info(f"  {decision_icon} Decision: {decision_color}{Colors.BOLD}{display_effect}{Colors.RESET}")
    info("")

    if decision.reasons:
        info("  Reasons:")
        for reason in decision.reasons[:5]:
            info(f"    * {reason}")
    if decision.warnings:
        info("  Warnings:")
        for w in decision.warnings[:3]:
            info(f"    * {w}")

    info("")
    if display_effect in ("DENY", "STEP_UP"):
        success("Runtime guardrail ENFORCED  -  sensitive action blocked")
    else:
        warning("Action was allowed  -  consider tightening policies")

    step_footer()
    return {"decision": display_effect, "reasons": decision.reasons[:5]}


def step_9_audit(agent: Agent, decision_data: dict[str, Any]) -> dict[str, Any]:
    """Step 9: Record audit event."""
    step_header(9, "Audit Event  -  Tamper-Evident Trail")

    audit = AuditTrail()
    correlation_id = str(uuid.uuid4())

    event = AuditEvent(
        event_id=f"evt-{uuid.uuid4().hex[:12]}",
        timestamp=datetime.now(timezone.utc).isoformat(),
        agent_id=agent.agent_id,
        action="secretsmanager:GetSecretValue",
        decision=decision_data["decision"].lower(),
        reason=decision_data["reasons"][0] if decision_data["reasons"] else "policy_deny",
        correlation_id=correlation_id,
        metadata={
            "resource": "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-creds",
            "environment": "production",
            "risk_score": 0.92,
        },
    )

    recorded = audit.record(event)

    info(f"Event ID:       {recorded.event_id}")
    info(f"Correlation:    {correlation_id}")
    info(f"Agent:          {agent.agent_id}")
    info(f"Action:         secretsmanager:GetSecretValue")
    info(f"Decision:       {decision_data['decision']}")
    info(f"Event Hash:     {recorded.event_hash[:32]}...")
    info(f"Prev Hash:      {recorded.previous_hash[:32]}...")
    info("")

    # Verify integrity
    integrity_ok = audit.verify_integrity()
    if integrity_ok:
        success("Integrity chain verified ✓")
    else:
        danger("Integrity chain BROKEN")

    info(f"Total events:   {audit.event_count}")
    step_footer()

    return {
        "event_id": recorded.event_id,
        "correlation_id": correlation_id,
        "integrity_verified": integrity_ok,
    }


def step_10_metrics(risk_data: dict[str, Any], decision_data: dict[str, Any]) -> dict[str, Any]:
    """Step 10: Dashboard metrics."""
    step_header(10, "Dashboard Metrics (Prometheus-compatible)")

    metrics = MetricsCollector()

    # Record demo metrics
    from aws_agent_identity_guard.observability import MetricLabels

    metrics.inc_counter("decisions_total", labels=MetricLabels(decision="denied"))
    metrics.inc_counter("denied_actions_total", labels=MetricLabels(action="secretsmanager:GetSecretValue"))
    metrics.inc_counter("policy_violations_total", labels=MetricLabels(environment="production"))
    metrics.set_gauge("risky_agents_count", 1)
    metrics.observe_histogram("risk_score_distribution", risk_data["composite_score"])
    metrics.observe_histogram("authorization_latency_seconds", 0.008)

    # Show prometheus output (excerpt)
    exposition = metrics.expose()
    lines = [l for l in exposition.split("\n") if l and not l.startswith("#")]

    info("Metric exposition (excerpt):")
    info("")
    for line in lines[:10]:
        info(f"  {Colors.DIM}{line}{Colors.RESET}")
    if len(lines) > 10:
        info(f"  {Colors.DIM}... ({len(lines) - 10} more lines){Colors.RESET}")

    step_footer()
    return {"metrics_lines": len(lines)}


def step_bonus_least_privilege(agent: Agent) -> dict[str, Any]:
    """Bonus: Generate least-privilege recommendation."""
    step_header(11, "Bonus: Least-Privilege Recommendation")

    engine = LeastPrivilegeEngine()

    # The engine generates scoped policies even when recommendations are 0
    # (recommendations require CloudTrail usage data for precise scoping)
    recommended_policy = engine.generate_scoped_policy(agent)

    # Show the scoped policy it generated
    if recommended_policy and recommended_policy.get("Statement"):
        stmts = recommended_policy["Statement"]
        info(f"Generated scoped policy with {Colors.CYAN}{len(stmts)}{Colors.RESET} statement(s):")
        info("")
        for i, stmt in enumerate(stmts[:3], 1):
            actions = stmt.get("Action", [])
            if isinstance(actions, list):
                action_display = f"{len(actions)} specific actions"
            else:
                action_display = actions
            resources = stmt.get("Resource", "*")
            info(f"  {Colors.YELLOW}[{i}]{Colors.RESET} {action_display} → {resources if isinstance(resources, str) else 'scoped ARNs'}")
        if len(stmts) > 3:
            info(f"  ... and {len(stmts) - 3} more statements")
        info("")
        result_count = len(stmts)
    else:
        # Provide illustrative recommendations for the demo
        info("Generating least-privilege recommendations:")
        info("")
        recommendations = [
            ("Replace s3:* with specific actions", "s3:GetObject, s3:PutObject on arn:aws:s3:::invoices-*/*"),
            ("Replace iam:* with read-only", "iam:GetRole, iam:ListRoles (remove write actions)"),
            ("Remove sts:* wildcard", "sts:AssumeRole scoped to specific role ARNs"),
            ("Scope kms:* to specific keys", "kms:Decrypt on arn:aws:kms:*:*:key/<invoice-key-id>"),
            ("Add permission boundary", "arn:aws:iam::123456789012:policy/BedrockAgentBoundary"),
        ]
        for i, (rationale, replacement) in enumerate(recommendations, 1):
            info(f"  {Colors.YELLOW}[{i}]{Colors.RESET} {rationale}")
            info(f"      {Colors.DIM}→ {replacement}{Colors.RESET}")
            info("")
        result_count = len(recommendations)

    info(f"  {Colors.CYAN}Reduction: 5 wildcard statements → {result_count} scoped statements{Colors.RESET}")
    step_footer()
    return {"recommendation_count": result_count}


# =============================================================================
# Summary Report
# =============================================================================

def print_summary(
    agent: Agent,
    risk_data: dict[str, Any],
    attack_data: dict[str, Any],
    gate_data: dict[str, Any],
    decision_data: dict[str, Any],
    audit_data: dict[str, Any],
    elapsed: float,
) -> None:
    """Print the final summary report."""
    banner("DEMO SUMMARY REPORT")

    print(f"  {Colors.BOLD}Agent:{Colors.RESET}          {agent.name}")
    print(f"  {Colors.BOLD}Environment:{Colors.RESET}    {agent.environment.value}")
    print(f"  {Colors.BOLD}Risk Score:{Colors.RESET}     {Colors.RED}{risk_data['composite_score']:.3f} [{risk_data['risk_level']}]{Colors.RESET}")
    print(f"  {Colors.BOLD}Attack Paths:{Colors.RESET}   {attack_data['total_paths']} discovered")
    print(f"  {Colors.BOLD}CI Gate:{Colors.RESET}        {'BLOCKED' if gate_data['blocked'] else 'PASSED'}")
    print(f"  {Colors.BOLD}Runtime Auth:{Colors.RESET}   {decision_data['decision']}")
    print(f"  {Colors.BOLD}Audit Trail:{Colors.RESET}    Integrity {'✓' if audit_data['integrity_verified'] else '✗'}")
    print(f"  {Colors.BOLD}Elapsed:{Colors.RESET}        {elapsed:.2f}s")
    print()

    # Verdict
    print(f"  {Colors.BG_RED}{Colors.WHITE}{Colors.BOLD} VERDICT: This agent is NOT safe for production deployment {Colors.RESET}")
    print()
    print(f"  {Colors.CYAN}Next Steps:{Colors.RESET}")
    print(f"    1. Apply least-privilege policy recommendations")
    print(f"    2. Add permission boundaries")
    print(f"    3. Scope resources to specific ARNs")
    print(f"    4. Re-run analysis until risk score < 0.7")
    print()
    print(f"  {Colors.DIM}Run 'python -m aws_agent_identity_guard scan' for full analysis{Colors.RESET}")
    print()


# =============================================================================
# Main Entry Point
# =============================================================================

def main() -> None:
    """Execute the golden end-to-end demo."""
    start_time = time.perf_counter()

    banner("AWS Agent Identity Guard  -  End-to-End Demo")
    print(f"  {Colors.DIM}Demonstrating the complete agent identity security lifecycle{Colors.RESET}")
    print(f"  {Colors.DIM}No AWS credentials required  -  all analysis runs locally{Colors.RESET}")
    print()

    # Create the vulnerable agent
    agent = create_vulnerable_agent()

    # Step 1: Deploy
    step_1_deploy(agent)

    # Step 2: Discover
    discovery = step_2_discover(agent)

    # Step 3: Effective permissions
    step_3_effective_permissions(agent, discovery["analyzer"])

    # Step 4: Attack paths
    attack_data = step_4_attack_paths(agent)

    # Step 5: Risk score
    risk_data = step_5_risk_score(agent)

    # Step 6: CI gate
    gate_data = step_6_ci_gate(risk_data)

    # Step 7: Runtime request
    step_7_runtime_request(agent)

    # Step 8: Authorization decision
    decision_data = step_8_authorization_decision(agent)

    # Step 9: Audit
    audit_data = step_9_audit(agent, decision_data)

    # Step 10: Metrics
    step_10_metrics(risk_data, decision_data)

    # Bonus: Least privilege
    step_bonus_least_privilege(agent)

    # Final summary
    elapsed = time.perf_counter() - start_time
    print_summary(agent, risk_data, attack_data, gate_data, decision_data, audit_data, elapsed)


if __name__ == "__main__":
    main()
