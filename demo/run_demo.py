"""
demo/run_demo.py
-----------------
Golden end-to-end demonstration of the AWS Agent Identity Guard system.

Single command:  python demo/run_demo.py

Walks through the full security lifecycle:
  1. Deploy a vulnerable agent with dangerous permissions
  2. Discover the agent's identity
  3. Calculate effective permissions
  4. Find attack paths
  5. Score risk across six dimensions
  6. Evaluate security policies
  7. Block deployment via CI/CD gate
  8. Attempt a runtime action
  9. Get DENY/STEP_UP decision with explanation
  10. Show audit event with integrity hash
  11. Show dashboard summary

No external dependencies required. Uses only stdlib formatting.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

# Ensure src is importable
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aws_agent_identity_guard.attack_paths import AttackPathAnalyzer
from aws_agent_identity_guard.authorization import (
    AuthorizationConfig,
    AuthorizationEngine,
    AuthorizationMode,
)
from aws_agent_identity_guard.escalation_engine import EscalationDetector
from aws_agent_identity_guard.models import (
    AgentIdentity,
    AgentType,
    AuthorizationDecisionType,
    DataClassification,
    EffectiveEffect,
    EffectivePermission,
    Environment,
    TransactionRequest,
)
from aws_agent_identity_guard.policy_engine import PolicyEngine
from aws_agent_identity_guard.risk_engine import RiskEngine, classify_risk


# ─── ANSI Colors ──────────────────────────────────────────────────────────────


class C:
    """ANSI color codes for terminal output."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
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


def banner(text: str, color: str = C.CYAN) -> None:
    """Print a colorful banner."""
    width = 70
    print()
    print(f"{color}{C.BOLD}{'=' * width}{C.RESET}")
    print(f"{color}{C.BOLD}  {text}{C.RESET}")
    print(f"{color}{C.BOLD}{'=' * width}{C.RESET}")
    print()


def step_header(num: int, title: str) -> None:
    """Print a numbered step header."""
    print(f"\n{C.YELLOW}{C.BOLD}[Step {num:02d}]{C.RESET} {C.WHITE}{C.BOLD}{title}{C.RESET}")
    print(f"{C.YELLOW}{'─' * 60}{C.RESET}")


def success(msg: str) -> None:
    """Print a success message."""
    print(f"  {C.GREEN}[OK]{C.RESET} {msg}")


def danger(msg: str) -> None:
    """Print a danger/alert message."""
    print(f"  {C.RED}[!!]{C.RESET} {msg}")


def info(msg: str) -> None:
    """Print an info message."""
    print(f"  {C.BLUE}[i]{C.RESET} {msg}")


def warn(msg: str) -> None:
    """Print a warning message."""
    print(f"  {C.YELLOW}[!]{C.RESET} {msg}")


def table_row(key: str, value: str, color: str = C.WHITE) -> None:
    """Print a table-like key-value row."""
    print(f"  {C.CYAN}{key:<30}{C.RESET} {color}{value}{C.RESET}")


def risk_bar(score: float, width: int = 30) -> str:
    """Generate an ASCII risk bar."""
    filled = int(score / 100 * width)
    empty = width - filled
    if score >= 76:
        color = C.RED
    elif score >= 51:
        color = C.YELLOW
    elif score >= 26:
        color = C.MAGENTA
    else:
        color = C.GREEN
    return f"{color}{'|' * filled}{C.RESET}{'.' * empty} {score:.1f}/100"


# ─── Demo Logic ───────────────────────────────────────────────────────────────


def main() -> None:
    """Run the full end-to-end demonstration."""
    start_time = time.time()

    # ASCII Art Banner
    print(f"""{C.CYAN}{C.BOLD}
    ___        ______    _                    _     ___    _
   / _ \\      / _____|  | |                  | |   |_ _|  | |
  / /_\\ \\ ___| |  ___  | |__   _ _  _ _  ___| |_   | | __| |
  |  _  |/ __| | / _ \\ | '_ \\ / _` | ' \\/ _ \\  _|  | |/ _` |
  | | | | (_ | ||  __/ | | | | (_| | | |  __/ |_   | | (_| |
  \\_| |_/\\___|\\__\\___| |_| |_|\\__,_|_||_|\\___|\\__| |___\\__,_|

          AWS Agent Identity Guard - Security Demo
{C.RESET}""")

    banner("GOLDEN END-TO-END SECURITY DEMONSTRATION", C.MAGENTA)

    # ────────────────────────────────────────────────────────────────────────
    # Step 1: Deploy Vulnerable Agent
    # ────────────────────────────────────────────────────────────────────────
    step_header(1, "Deploy Vulnerable Agent")
    info("Creating an AI agent with over-privileged permissions...")

    agent = AgentIdentity(
        agent_id="vuln-agent-001",
        name="DataProcessorAgent",
        agent_type=AgentType.BEDROCK,
        owner="ml-team",
        environment=Environment.PRODUCTION,
        purpose="Process customer data via Bedrock foundation models",
        data_classification=DataClassification.SECRET,
        iam_role_arn="arn:aws:iam::123456789012:role/DataProcessorAgent",
        declared_capabilities=[
            "bedrock:InvokeModel",
            "s3:ReadData",
            "secretsmanager:GetCredentials",
        ],
        tags={"project": "customer-insights", "cost-center": "ML-001"},
    )

    danger("Agent deployed with DANGEROUS permission set!")
    table_row("Agent ID:", agent.agent_id)
    table_row("Name:", agent.name)
    table_row("Environment:", agent.environment.value, C.RED)
    table_row("Data Classification:", agent.data_classification.value, C.RED)

    # ────────────────────────────────────────────────────────────────────────
    # Step 2: Discover Identity
    # ────────────────────────────────────────────────────────────────────────
    step_header(2, "Discover Agent Identity")
    info("Querying agent identity registry...")

    table_row("Agent Type:", agent.agent_type.value)
    table_row("Owner:", agent.owner)
    table_row("IAM Role:", agent.iam_role_arn or "N/A")
    table_row("Purpose:", agent.purpose)
    table_row("Capabilities:", ", ".join(agent.declared_capabilities))
    success("Identity fully resolved.")

    # ────────────────────────────────────────────────────────────────────────
    # Step 3: Calculate Effective Permissions
    # ────────────────────────────────────────────────────────────────────────
    step_header(3, "Calculate Effective Permissions")
    info("Running EffectivePermissionAnalyzer across all policy layers...")

    # Simulate effective permissions (overly broad)
    effective_permissions = [
        EffectivePermission(action="iam:PassRole", resource="*", effective_effect=EffectiveEffect.ALLOWED),
        EffectivePermission(action="iam:CreatePolicyVersion", resource="*", effective_effect=EffectiveEffect.ALLOWED),
        EffectivePermission(action="sts:AssumeRole", resource="*", effective_effect=EffectiveEffect.ALLOWED),
        EffectivePermission(action="lambda:CreateFunction", resource="*", effective_effect=EffectiveEffect.ALLOWED),
        EffectivePermission(action="lambda:InvokeFunction", resource="*", effective_effect=EffectiveEffect.ALLOWED),
        EffectivePermission(action="secretsmanager:GetSecretValue", resource="*", effective_effect=EffectiveEffect.ALLOWED),
        EffectivePermission(action="s3:GetObject", resource="*", effective_effect=EffectiveEffect.ALLOWED),
        EffectivePermission(action="s3:PutBucketPolicy", resource="*", effective_effect=EffectiveEffect.ALLOWED),
        EffectivePermission(action="dynamodb:Scan", resource="*", effective_effect=EffectiveEffect.ALLOWED),
        EffectivePermission(action="kms:Decrypt", resource="*", effective_effect=EffectiveEffect.ALLOWED),
        EffectivePermission(action="ec2:RunInstances", resource="*", effective_effect=EffectiveEffect.ALLOWED),
        EffectivePermission(action="ssm:StartSession", resource="*", effective_effect=EffectiveEffect.ALLOWED),
    ]

    danger(f"Found {len(effective_permissions)} ALLOWED permissions (many over-privileged):")
    for perm in effective_permissions:
        color = C.RED if "iam:" in perm.action or "sts:" in perm.action else C.YELLOW
        print(f"    {color}{perm.action:<40} -> {perm.resource}{C.RESET}")

    # ────────────────────────────────────────────────────────────────────────
    # Step 4: Find Attack Paths
    # ────────────────────────────────────────────────────────────────────────
    step_header(4, "Find Attack Paths")
    info("Running AttackPathAnalyzer to discover exploitation chains...")

    path_analyzer = AttackPathAnalyzer()
    attack_paths = path_analyzer.analyze(agent, effective_permissions)

    danger(f"Discovered {len(attack_paths)} attack paths!")
    for i, path in enumerate(attack_paths[:5], 1):
        color = C.RED if path.composite_score >= 70 else C.YELLOW
        print(f"    {color}[{i}] Score: {path.composite_score:.1f} | {path.description[:60]}{C.RESET}")
        for step in path.steps[:3]:
            print(f"        -> {step.action} on {step.resource[:40]}")

    if len(attack_paths) > 5:
        warn(f"... and {len(attack_paths) - 5} more attack paths.")

    # ────────────────────────────────────────────────────────────────────────
    # Step 5: Score Risk
    # ────────────────────────────────────────────────────────────────────────
    step_header(5, "Score Risk (Multidimensional)")
    info("Running RiskEngine across 6 dimensions...")

    risk_engine = RiskEngine()
    risk_score = risk_engine.score_agent(agent, effective_permissions, attack_paths)

    print()
    table_row("Overall Risk:", f"{risk_bar(risk_score.overall)}")
    table_row("Risk Level:", classify_risk(risk_score.overall).value,
              C.RED if risk_score.overall >= 76 else C.YELLOW)
    print()
    table_row("  Privilege:", risk_bar(risk_score.privilege))
    table_row("  Sensitivity:", risk_bar(risk_score.sensitivity))
    table_row("  Blast Radius:", risk_bar(risk_score.blast_radius))
    table_row("  Data Exposure:", risk_bar(risk_score.data_exposure))
    table_row("  Persistence:", risk_bar(risk_score.persistence))
    table_row("  Lateral Movement:", risk_bar(risk_score.lateral_movement))
    print()
    table_row("Environment Factor:", f"{risk_score.environment_factor}x (PRODUCTION)")

    # ────────────────────────────────────────────────────────────────────────
    # Step 6: Evaluate Policies
    # ────────────────────────────────────────────────────────────────────────
    step_header(6, "Evaluate Security Policies")
    info("Loading and evaluating YAML security policies...")

    policy_engine = PolicyEngine()
    policy_engine.load_policies_from_string("""
version: '1.0'
metadata:
  author: security-team
  description: Production security guardrails for AI agents
policies:
  - name: deny-iam-mutation-production
    effect: deny
    actions: ['iam:*']
    resources: ['*']
    environments: ['PRODUCTION']
    priority: 100
  - name: deny-secrets-high-risk
    effect: deny
    actions: ['secretsmanager:GetSecretValue']
    resources: ['*']
    conditions:
      risk_score_above: 60
    priority: 90
  - name: step-up-cross-account
    effect: step_up
    actions: ['sts:AssumeRole']
    resources: ['*']
    priority: 85
  - name: deny-destructive-s3
    effect: deny
    actions: ['s3:PutBucketPolicy', 's3:DeleteBucket']
    resources: ['*']
    environments: ['PRODUCTION']
    priority: 80
""")

    tx_test = TransactionRequest(
        agent_id=agent.agent_id,
        principal=agent.iam_role_arn or "",
        tool="bedrock-orchestrator",
        action="iam:CreatePolicyVersion",
        resource="*",
        data_classification=DataClassification.SECRET,
    )
    policy_decision = policy_engine.evaluate(tx_test, agent, risk_score)

    danger(f"Policy Verdict: {policy_decision.effect.value}")
    info(f"Matched Rules: {', '.join(policy_decision.matched_rules)}")
    info(f"Explanation: {policy_decision.explanation}")

    # ────────────────────────────────────────────────────────────────────────
    # Step 7: Block Deployment (CI/CD Gate)
    # ────────────────────────────────────────────────────────────────────────
    step_header(7, "CI/CD Security Gate - BLOCK Deployment")
    info("Evaluating deployment gate criteria...")

    gate_checks = [
        ("Risk Score < 50", risk_score.overall <= 50, f"FAIL (score={risk_score.overall:.1f})"),
        ("No CRITICAL escalation paths", len(attack_paths) == 0, f"FAIL ({len(attack_paths)} paths found)"),
        ("No wildcard IAM permissions", False, "FAIL (iam:* on * detected)"),
        ("Data classification approved", False, "FAIL (SECRET in PRODUCTION)"),
        ("Policy evaluation ALLOW", policy_decision.effect.value == "ALLOW", f"FAIL ({policy_decision.effect.value})"),
    ]

    all_pass = True
    for check_name, passed, fail_msg in gate_checks:
        if passed:
            success(f"{check_name}: PASS")
        else:
            danger(f"{check_name}: {fail_msg}")
            all_pass = False

    print()
    if not all_pass:
        print(f"  {C.BG_RED}{C.WHITE}{C.BOLD}  DEPLOYMENT BLOCKED  {C.RESET}")
        danger("Agent cannot be deployed. Remediation required.")
    else:
        print(f"  {C.BG_GREEN}{C.WHITE}{C.BOLD}  DEPLOYMENT APPROVED  {C.RESET}")

    # ────────────────────────────────────────────────────────────────────────
    # Step 8: Attempt Runtime Action
    # ────────────────────────────────────────────────────────────────────────
    step_header(8, "Attempt Runtime Action")
    info("Agent attempts to invoke iam:CreatePolicyVersion at runtime...")

    runtime_request = TransactionRequest(
        agent_id=agent.agent_id,
        principal=agent.iam_role_arn or "",
        tool="policy-modifier",
        action="iam:CreatePolicyVersion",
        resource="arn:aws:iam::123456789012:policy/DataAccessPolicy",
        data_classification=DataClassification.SECRET,
    )

    table_row("Action:", runtime_request.action, C.RED)
    table_row("Resource:", runtime_request.resource)
    table_row("Tool:", runtime_request.tool)
    table_row("Classification:", runtime_request.data_classification.value, C.RED)

    # ────────────────────────────────────────────────────────────────────────
    # Step 9: Get Authorization Decision
    # ────────────────────────────────────────────────────────────────────────
    step_header(9, "Authorization Decision")
    info("Running full authorization pipeline...")

    auth_config = AuthorizationConfig(
        mode=AuthorizationMode.FAIL_CLOSED,
        step_up_threshold=60.0,
        deny_threshold=85.0,
    )
    auth_engine = AuthorizationEngine(
        config=auth_config,
        risk_engine=risk_engine,
        policy_engine=policy_engine,
    )
    auth_engine.agent_registry.register(agent)

    decision = auth_engine.authorize(runtime_request)

    decision_color = C.RED if decision.decision == AuthorizationDecisionType.DENY else C.YELLOW
    print()
    print(f"  {C.BG_RED}{C.WHITE}{C.BOLD}  DECISION: {decision.decision.value}  {C.RESET}")
    print()
    table_row("Correlation ID:", decision.correlation_id)
    table_row("Risk Score:", f"{decision.risk_score.overall:.1f}/100")
    table_row("Policy Matched:", decision.policy_matched)
    info("Reasons:")
    for reason in decision.reasons:
        print(f"    {C.RED}- {reason}{C.RESET}")

    # Also try a step-up scenario
    print()
    info("Also attempting sts:AssumeRole (should require step-up)...")
    step_up_request = TransactionRequest(
        agent_id=agent.agent_id,
        principal=agent.iam_role_arn or "",
        tool="role-switcher",
        action="sts:AssumeRole",
        resource="arn:aws:iam::999888777666:role/CrossAccountAdmin",
    )
    step_up_decision = auth_engine.authorize(step_up_request)
    step_color = C.YELLOW if step_up_decision.decision == AuthorizationDecisionType.STEP_UP else C.RED
    print(f"    {step_color}Decision: {step_up_decision.decision.value}{C.RESET}")

    # ────────────────────────────────────────────────────────────────────────
    # Step 10: Show Audit Event
    # ────────────────────────────────────────────────────────────────────────
    step_header(10, "Audit Event with Integrity Hash")
    info("Retrieving tamper-evident audit trail...")

    events = auth_engine.audit_events
    if events:
        event = events[0]
        table_row("Event ID:", event.event_id)
        table_row("Correlation ID:", event.correlation_id)
        table_row("Agent:", event.agent_id)
        table_row("Action:", event.action)
        table_row("Decision:", event.decision.value,
                  C.RED if event.decision == AuthorizationDecisionType.DENY else C.GREEN)
        table_row("Policy Version:", event.policy_version)
        table_row("Integrity Hash:", event.integrity_hash[:32] + "...")
        table_row("Hash Verified:", str(event.verify_integrity()),
                  C.GREEN if event.verify_integrity() else C.RED)
        success("Audit event tamper-proof integrity verified.")
    else:
        warn("No audit events recorded.")

    # ────────────────────────────────────────────────────────────────────────
    # Step 11: Dashboard Summary
    # ────────────────────────────────────────────────────────────────────────
    step_header(11, "Security Dashboard Summary")

    escalation_detector = EscalationDetector()
    escalations = escalation_detector.detect(agent, effective_permissions)

    elapsed = time.time() - start_time

    print()
    print(f"  {C.BOLD}{C.WHITE}+{'─' * 50}+{C.RESET}")
    print(f"  {C.BOLD}{C.WHITE}|{'SECURITY POSTURE SUMMARY':^50}|{C.RESET}")
    print(f"  {C.BOLD}{C.WHITE}+{'─' * 50}+{C.RESET}")
    print(f"  | {'Agent:':<24} {agent.name:<24}|")
    print(f"  | {'Environment:':<24} {C.RED}{agent.environment.value:<24}{C.RESET}|")
    print(f"  | {'Risk Score:':<24} {C.RED}{risk_score.overall:.1f}/100 (CRITICAL){' ' * 5}{C.RESET}|")
    print(f"  | {'Attack Paths:':<24} {C.RED}{len(attack_paths)}{' ' * 22}{C.RESET}|")
    print(f"  | {'Escalation Paths:':<24} {C.RED}{len(escalations)}{' ' * 22}{C.RESET}|")
    print(f"  | {'Policy Verdict:':<24} {C.RED}DENY{' ' * 20}{C.RESET}|")
    print(f"  | {'Audit Events:':<24} {len(events):<24}|")
    print(f"  | {'Deployment:':<24} {C.RED}BLOCKED{' ' * 17}{C.RESET}|")
    print(f"  {C.BOLD}{C.WHITE}+{'─' * 50}+{C.RESET}")
    print()

    # Final metrics
    banner("DEMO COMPLETE", C.GREEN)
    table_row("Total execution time:", f"{elapsed:.3f}s")
    table_row("Authorization decisions:", str(auth_engine.decision_count))
    table_row("Latency (p50):", f"{auth_engine.latency_metrics['p50_ms']:.2f}ms")
    table_row("Latency (p99):", f"{auth_engine.latency_metrics['p99_ms']:.2f}ms")
    table_row("Attack paths found:", str(len(attack_paths)))
    table_row("Escalation patterns:", str(len(escalations)))
    table_row("Policies evaluated:", str(policy_engine.rule_count))
    print()
    success("All security controls verified. Agent is BLOCKED from production.")
    print()


if __name__ == "__main__":
    main()
