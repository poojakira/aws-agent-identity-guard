# Operations Runbook

## Overview

This runbook covers day-to-day operational procedures for maintaining AWS Agent Identity Guard in production, including deployment, monitoring, maintenance, and troubleshooting.

---

## Daily Operations Checklist

- [ ] Verify all pods/containers healthy
- [ ] Check authorization success/denial rates (within normal range)
- [ ] Review any P3/P4 alerts from overnight
- [ ] Confirm metrics scraping is active (Prometheus targets up)
- [ ] Check cache hit ratio > 70%
- [ ] Verify drift detection running (no stale baselines)

---

## Service Health Monitoring

### Key Metrics to Monitor

| Metric | Normal Range | Alert Threshold | Action |
|--------|-------------|-----------------|--------|
| `guard_requests_total` (rate) | 100–10,000 req/s | < 10 req/s or > 50,000 req/s | Investigate traffic change |
| `guard_request_duration_seconds` (p99) | < 15 ms | > 25 ms | Check Redis, scale up |
| `guard_requests_denied` (rate) | 1–5% of total | > 20% of total | Policy misconfiguration or attack |
| `guard_cache_hit_ratio` | > 70% | < 50% | Cache cold/Redis issue |
| `guard_errors_total` (rate) | < 0.1% | > 1% | Service degradation |
| Pod restarts | 0 | > 2 in 1 hour | OOM or crash loop |
| CPU utilization | 30–60% | > 85% sustained | Scale up |
| Memory utilization | 40–70% | > 90% | Memory leak or under-provisioned |

### Health Check Commands

```bash
# API health
curl -s http://guard:8080/v1/health | jq .

# Readiness (dependencies check)
curl -s http://guard:8080/v1/health/ready | jq .

# Metrics endpoint
curl -s http://guard:9090/v1/metrics | head -50

# Kubernetes pod status
kubectl get pods -n agent-guard -o wide
kubectl top pods -n agent-guard
```

### Grafana Dashboards

| Dashboard | URL | Purpose |
|-----------|-----|---------|
| Overview | `/d/guard-overview` | High-level health, request rates, latency |
| Authorization | `/d/guard-auth` | Decision breakdown, denial reasons, agent activity |
| Performance | `/d/guard-performance` | Latency percentiles, throughput, cache |
| Alerts | `/d/guard-alerts` | Active incidents, anomalies, drift events |

---

## Deployment Operations

### Rolling Update

```bash
# Update image tag
helm upgrade agent-guard ./helm/agent-identity-guard \
  --namespace agent-guard \
  --set image.tag=1.1.0 \
  --wait

# Monitor rollout
kubectl rollout status deployment/agent-guard -n agent-guard

# Verify new version
curl -s http://guard:8080/v1/health | jq .version
```

### Rollback

```bash
# Immediate rollback to previous release
helm rollback agent-guard --namespace agent-guard

# Or rollback to specific revision
helm history agent-guard --namespace agent-guard
helm rollback agent-guard 3 --namespace agent-guard

# Verify rollback
kubectl rollout status deployment/agent-guard -n agent-guard
```

### Canary Deployment

```bash
# Deploy canary (1 replica with new version)
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: agent-guard-canary
  namespace: agent-guard
spec:
  replicas: 1
  selector:
    matchLabels:
      app: agent-guard
      track: canary
  template:
    spec:
      containers:
        - name: guard-api
          image: ghcr.io/poojakira/aws-agent-identity-guard:1.1.0-rc1
EOF

# Monitor canary metrics for 30 minutes
# Compare error rates between stable and canary
# If healthy, proceed with full rollout
# If issues, delete canary
kubectl delete deployment agent-guard-canary -n agent-guard
```

---

## Policy Management

### Deploy New Policies

```bash
# 1. Validate policies locally
python -m aws_agent_identity_guard validate-policies ./policies/

# 2. Test policies
python -m aws_agent_identity_guard test-policies ./policies/

# 3. Deploy to ConfigMap (Kubernetes)
kubectl create configmap guard-policies \
  --from-file=./policies/ \
  --namespace agent-guard \
  --dry-run=client -o yaml | kubectl apply -f -

# 4. Trigger policy reload (restart not required)
kubectl rollout restart deployment/agent-guard -n agent-guard

# 5. Verify policies loaded
curl -s http://guard:8080/v1/policies | jq '.total'
```

### Policy Rollback

```bash
# Revert ConfigMap to previous version
kubectl rollout undo configmap/guard-policies -n agent-guard

# Or restore from git
git checkout HEAD~1 -- policies/
kubectl create configmap guard-policies \
  --from-file=./policies/ \
  --namespace agent-guard \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl rollout restart deployment/agent-guard -n agent-guard
```

### Emergency Policy Override

For critical situations where a policy is blocking legitimate business operations:

```bash
# Add temporary allow exception (time-limited)
cat > /tmp/emergency-allow.yaml <<EOF
apiVersion: v1
kind: SecurityPolicy
metadata:
  name: emergency-override
  version: "1.0.0"
  description: "EMERGENCY: Temporary allow for {TICKET_NUMBER}"
spec:
  priority: 1  # Highest priority
  enabled: true
  rules:
    - id: emergency-allow
      type: allow
      match:
        actions: ["{specific_action}"]
        resources: ["{specific_resource}"]
        agents: ["{specific_agent}"]
      message: "Emergency override per {TICKET_NUMBER}. Expires: {DATETIME}"
EOF

# Deploy emergency policy
# SET A TIMER TO REMOVE THIS

# Remove after incident resolved
kubectl delete configmap emergency-override -n agent-guard
```

**⚠️ Document every emergency override. Review in next business day.**

---

## Scaling Operations

### Horizontal Scaling

```bash
# Manual scale
kubectl scale deployment agent-guard -n agent-guard --replicas=5

# Update HPA limits
kubectl patch hpa agent-guard -n agent-guard \
  --patch '{"spec":{"maxReplicas":15}}'

# Check current HPA status
kubectl get hpa agent-guard -n agent-guard
```

### Vertical Scaling

```bash
# Update resource limits
helm upgrade agent-guard ./helm/agent-identity-guard \
  --namespace agent-guard \
  --set resources.limits.cpu=2 \
  --set resources.limits.memory=1Gi \
  --set resources.requests.cpu=500m \
  --set resources.requests.memory=256Mi
```

### Redis Scaling

```bash
# If using ElastiCache, scale via AWS Console or CLI
aws elasticache modify-replication-group \
  --replication-group-id guard-cache \
  --cache-node-type cache.r6g.large \
  --apply-immediately
```

---

## Maintenance Procedures

### Certificate Rotation

```bash
# Rotate TLS certificates (if terminating TLS at pod level)
kubectl create secret tls guard-tls \
  --cert=new-cert.pem \
  --key=new-key.pem \
  --namespace agent-guard \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl rollout restart deployment/agent-guard -n agent-guard
```

### API Key Rotation

```bash
# 1. Generate new API key
NEW_KEY=$(python -c "import secrets; print(secrets.token_urlsafe(32))")

# 2. Add new key to service (supports multiple concurrent keys)
# Update Secrets Manager
aws secretsmanager update-secret \
  --secret-id agent-guard/api-keys \
  --secret-string '{"keys":["'$NEW_KEY'","'$OLD_KEY'"]}'

# 3. Update all clients to use new key
# 4. After all clients migrated (7 days), remove old key
aws secretsmanager update-secret \
  --secret-id agent-guard/api-keys \
  --secret-string '{"keys":["'$NEW_KEY'"]}'
```

### Database/Cache Maintenance

```bash
# Flush Redis cache (non-destructive, causes temporary performance dip)
redis-cli -h {redis_host} FLUSHDB

# Check Redis memory usage
redis-cli -h {redis_host} INFO memory

# Check for large keys
redis-cli -h {redis_host} --bigkeys
```

### Log Rotation

Logs are written to stdout and captured by the container runtime. Retention is managed by:
- CloudWatch Logs: 90-day retention (configured in Terraform)
- Kubernetes: managed by container runtime log rotation

```bash
# Verify CloudWatch log group retention
aws logs describe-log-groups \
  --log-group-name-prefix /aws-agent-identity-guard
```

---

## Troubleshooting

### High Latency

**Symptoms:** p99 latency > 25ms, authorization responses slow

**Diagnosis:**
```bash
# Check if it's cache misses
curl -s http://guard:9090/v1/metrics | grep cache_hit_ratio

# Check Redis latency
redis-cli -h {redis_host} --latency

# Check pod resource usage
kubectl top pods -n agent-guard

# Check if evaluation is complex (many policies)
curl -s http://guard:8080/v1/policies | jq '.total'
```

**Resolution:**
1. If cache hit ratio low → restart pods to warm cache, or check Redis connectivity
2. If Redis latency high → scale Redis, check network
3. If CPU high → add replicas
4. If many policies → review policy priority ordering, consider consolidation

### High Denial Rate

**Symptoms:** Denial rate > 20% of requests suddenly

**Diagnosis:**
```bash
# Check what's being denied
curl -s http://guard:9090/v1/metrics | grep "decision.*DENY"

# Get recent denial details
curl -s "http://guard:8080/v1/audit?decision=DENY&limit=20" | jq '.[].matched_rule'

# Check if new policy was deployed recently
kubectl describe configmap guard-policies -n agent-guard | head -20
helm history agent-guard -n agent-guard
```

**Resolution:**
1. If new policy caused it → rollback policy
2. If legitimate denials (attack) → escalate to security
3. If agent role changed → check drift detector events

### Pod CrashLoopBackOff

**Symptoms:** Pods repeatedly restarting

**Diagnosis:**
```bash
# Check pod events
kubectl describe pod {pod_name} -n agent-guard

# Check logs from crashed pod
kubectl logs {pod_name} -n agent-guard --previous

# Check resource limits
kubectl get pod {pod_name} -n agent-guard -o jsonpath='{.spec.containers[0].resources}'
```

**Resolution:**
1. If OOMKilled → increase memory limits
2. If policy load error → fix policy files, check ConfigMap
3. If dependency startup failure → check Redis connectivity
4. If port conflict → check service ports

### Redis Connection Failures

**Symptoms:** Readiness probe failing, `redis_connected: false`

**Diagnosis:**
```bash
# Test Redis connectivity from pod
kubectl exec -it {pod_name} -n agent-guard -- \
  python -c "import socket; s=socket.socket(); s.connect(('redis', 6379)); print('OK')"

# Check Redis pod/service
kubectl get svc redis -n agent-guard
kubectl get endpoints redis -n agent-guard

# If ElastiCache, check security groups
aws elasticache describe-cache-clusters --show-cache-node-info
```

**Resolution:**
1. Check network policy / security group rules
2. Verify Redis service DNS resolves correctly
3. Check Redis authentication (if AUTH enabled)
4. Service operates without Redis (no cache, slower) — not a hard dependency

### Scanner CI Gate Failures

**Symptoms:** CI pipeline failing on policy scan step

**Diagnosis:**
```bash
# Run scanner locally to reproduce
python -m aws_agent_identity_guard {policy_file} --format json

# Check which rules triggered
python -m aws_agent_identity_guard {policy_file} --format json | jq '.[].rule_id'

# Check if it's a false positive
python -m aws_agent_identity_guard {policy_file} --format text
```

**Resolution:**
1. If legitimate finding → fix the policy (see remediation in output)
2. If false positive → file issue, consider `--fail-on critical` as temporary workaround
3. If scanner version mismatch → pin scanner version in CI

---

## Backup and Recovery

### What to Back Up

| Data | Method | Frequency | Retention |
|------|--------|-----------|-----------|
| Policy files | Git repository | Every commit | Indefinite |
| Terraform state | S3 with versioning | Every apply | 90 days |
| Audit trail (CloudWatch) | Automatic | Continuous | 90 days |
| Redis state | RDB snapshots (if persistent) | Hourly | 7 days |
| Helm values | Git repository | Every change | Indefinite |
| Agent registry | Export via API | Daily | 30 days |

### Recovery Procedures

**Full Service Recovery:**
```bash
# 1. Restore infrastructure (Terraform)
cd infra/terraform/environments/{env}
terraform init
terraform apply

# 2. Deploy application (Helm)
helm install agent-guard ./helm/agent-identity-guard \
  --namespace agent-guard \
  --values production-values.yaml

# 3. Restore policies
kubectl create configmap guard-policies \
  --from-file=./policies/ \
  --namespace agent-guard

# 4. Re-register agents (if registry lost)
# Use backup or re-register from agent manifests
```

---

## Operational Metrics SLOs

| Metric | SLO | Measurement | Alerting |
|--------|-----|-------------|----------|
| Availability | 99.9% | Readiness probe success rate | Page if < 99.5% over 5 min |
| Authorization latency (p99) | < 15 ms | Prometheus histogram | Alert if > 25 ms for 5 min |
| Error rate | < 0.1% | 5xx / total requests | Alert if > 1% for 2 min |
| Cache hit ratio | > 70% | gauge metric | Alert if < 50% for 10 min |
| Policy evaluation correctness | 100% | Policy test suite in CI | Block deploy if any test fails |

---

## On-Call Procedures

### Handoff Checklist

- [ ] Current service status (all green / any active issues)
- [ ] Any in-progress changes (deployments, policy updates)
- [ ] Any open incidents or ongoing investigations
- [ ] Any planned maintenance in the next shift
- [ ] Location of emergency runbooks and credentials

### Escalation Path

```
L1: On-call engineer (PagerDuty primary)
 ↓ (15 min no response or P1)
L2: Team lead (PagerDuty secondary)
 ↓ (30 min no response or multi-service impact)
L3: Engineering Director
 ↓ (active data breach or compliance event)
L4: CISO / VP Engineering
```
