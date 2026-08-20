# Operations Runbook

Day-to-day operational procedures for AWS Agent Identity Guard.

---

## Deployment Procedures

### Standard Deployment (Docker)

```bash
# Pull latest image
docker pull your-registry/agent-identity-guard:1.0.0

# Stop current instance
docker compose down

# Update image tag in docker-compose.yml
# Start new instance
docker compose up -d

# Verify health
curl http://localhost:8000/health
```

### Standard Deployment (Kubernetes/Helm)

```bash
# Update values
helm upgrade agent-guard ./helm/agent-identity-guard \
  --namespace agent-security \
  --set image.tag=1.0.1 \
  --wait --timeout 300s

# Verify rollout
kubectl rollout status deployment/agent-guard -n agent-security

# Check pods
kubectl get pods -n agent-security -l app=agent-guard
```

### Canary Deployment

1. Deploy new version to canary (10% traffic):
   ```bash
   helm upgrade agent-guard-canary ./helm/agent-identity-guard \
     --set image.tag=1.0.1 \
     --set replicaCount=1 \
     --set canary.enabled=true \
     --set canary.weight=10
   ```
2. Monitor error rate and latency for 30 minutes
3. If healthy, promote to full deployment:
   ```bash
   helm upgrade agent-guard ./helm/agent-identity-guard \
     --set image.tag=1.0.1
   helm uninstall agent-guard-canary
   ```

---

## Rollback Procedures

### Helm Rollback

```bash
# List history
helm history agent-guard -n agent-security

# Rollback to previous revision
helm rollback agent-guard 1 -n agent-security --wait

# Verify
kubectl rollout status deployment/agent-guard -n agent-security
```

### Docker Rollback

```bash
# Update docker-compose.yml to previous tag
docker compose down
docker compose up -d

# Verify
curl http://localhost:8000/health
```

### Emergency Rollback

If the service is completely down:

```bash
# Kubernetes: scale to 0, then deploy known-good version
kubectl scale deployment agent-guard --replicas=0 -n agent-security
helm rollback agent-guard 1 -n agent-security
kubectl scale deployment agent-guard --replicas=3 -n agent-security

# If Helm state is corrupted, delete and reinstall
helm uninstall agent-guard -n agent-security
helm install agent-guard ./helm/agent-identity-guard \
  --set image.tag=0.9.9  # Last known good version
```

### Rollback Decision Criteria

| Signal | Threshold | Action |
|--------|-----------|--------|
| Error rate | > 5% for 5 min | Automatic rollback |
| p99 latency | > 50ms for 5 min | Investigate, manual rollback |
| Health check failures | 3 consecutive | Automatic rollback |
| DENY spike | > 200% baseline | Investigate, possible rollback |

---

## Scaling

### Horizontal Scaling (Kubernetes)

Automatic via HPA:

```yaml
autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70
  targetMemoryUtilizationPercentage: 80
```

Manual override:

```bash
kubectl scale deployment agent-guard --replicas=6 -n agent-security
```

### Vertical Scaling

Update resource limits:

```bash
helm upgrade agent-guard ./helm/agent-identity-guard \
  --set resources.requests.cpu=1000m \
  --set resources.requests.memory=2Gi \
  --set resources.limits.cpu=2000m \
  --set resources.limits.memory=4Gi
```

### Scaling Guidelines

| Agents | Decisions/sec | Replicas | CPU/pod | Memory/pod |
|--------|--------------|----------|---------|------------|
| < 100 | < 500 | 2 | 500m | 512Mi |
| 100-1000 | 500-5000 | 4 | 1000m | 1Gi |
| 1000-5000 | 5000-20000 | 6 | 1500m | 2Gi |
| 5000+ | 20000+ | 8-10 | 2000m | 4Gi |

---

## Troubleshooting

### Service Unresponsive

1. Check pod status:
   ```bash
   kubectl get pods -n agent-security
   kubectl describe pod agent-guard-xxx -n agent-security
   ```
2. Check logs:
   ```bash
   kubectl logs deployment/agent-guard -n agent-security --tail=100
   ```
3. Check resource usage:
   ```bash
   kubectl top pods -n agent-security
   ```
4. Common causes:
   - OOM killed: increase memory limits
   - CPU throttled: increase CPU limits or add replicas
   - Liveness probe failing: check `/health` endpoint manually

### High Latency

1. Check Prometheus metrics:
   ```
   histogram_quantile(0.99, rate(agent_guard_latency_seconds_bucket[5m]))
   ```
2. Identify which component is slow:
   - Policy evaluation: check policy count and complexity
   - Risk scoring: check baseline lookup time
   - Attack path: check cache hit rate
3. Mitigations:
   - Increase cache TTL (`AGENT_GUARD_CACHE_TTL`)
   - Add replicas to distribute load
   - Simplify complex policies (reduce condition count)
   - Increase timeout if false timeouts

### High DENY Rate

1. Check if policies were recently updated:
   ```bash
   git log --oneline -10 policies/
   ```
2. Check if a new agent was registered without proper capabilities
3. Check if the risk threshold was lowered
4. Check for actual attacks vs policy misconfiguration:
   ```
   agent_guard_decisions_total{decision="DENY"} by (reason)
   ```

### Connection Errors from SDK

1. Verify the service is reachable:
   ```bash
   curl -v http://agent-guard-service:8000/health
   ```
2. Check DNS resolution:
   ```bash
   nslookup agent-guard-service.agent-security.svc.cluster.local
   ```
3. Check network policies:
   ```bash
   kubectl get networkpolicies -n agent-security
   ```
4. Check SDK retry configuration (may need to increase timeout)

---

## Health Check Failures

### /health Returns Unhealthy

The health endpoint checks three components:

| Component | Check | Common Failure |
|-----------|-------|----------------|
| `policy_store` | Can read policy files | File permissions, volume mount issue |
| `risk_engine` | Baseline data accessible | S3 access, cache corruption |
| `agent_registry` | Can query agent list | Memory pressure, initialization failure |

**Resolution steps:**

1. Check which component failed:
   ```bash
   curl http://localhost:8000/health | jq .checks
   ```
2. For `policy_store`:
   ```bash
   # Verify mount
   kubectl exec -it agent-guard-xxx -- ls /app/policies/
   # Check file permissions
   kubectl exec -it agent-guard-xxx -- cat /app/policies/default.yaml
   ```
3. For `risk_engine`:
   ```bash
   # Check S3 access (if using external baselines)
   aws s3 ls s3://agent-guard-baselines/
   # Restart pod to clear cache
   kubectl delete pod agent-guard-xxx -n agent-security
   ```
4. For `agent_registry`:
   ```bash
   # Check memory usage
   kubectl top pod agent-guard-xxx
   # If OOM, increase memory limit
   ```

---

## Performance Degradation

### Diagnosis

1. Check if load increased:
   ```
   rate(agent_guard_decisions_total[5m])
   ```
2. Check latency breakdown by component (if custom metrics available)
3. Check if attack path cache is cold (after restart):
   ```
   agent_guard_cache_hit_ratio
   ```
4. Check garbage collection pressure:
   ```bash
   kubectl logs deployment/agent-guard | grep -i "gc\|memory"
   ```

### Mitigation

| Cause | Fix |
|-------|-----|
| Load spike | Scale up replicas |
| Cold cache | Wait for warm-up (5 min) or pre-warm |
| Policy complexity | Reduce condition count, simplify patterns |
| Memory pressure | Increase limits, reduce cache size |
| Python GC | Increase workers, reduce per-worker memory |

---

## Policy Store Issues

### Policies Not Loading

1. Check file syntax:
   ```bash
   agent-identity-guard policy validate --policy-file policies/
   ```
2. Check file permissions on the mounted volume
3. Check logs for YAML parse errors:
   ```bash
   kubectl logs deployment/agent-guard | grep -i "policy\|yaml\|parse"
   ```

### Policies Not Updating (Hot Reload)

1. Verify the file watcher is running:
   ```bash
   kubectl logs deployment/agent-guard | grep -i "reload\|watch"
   ```
2. Check if the ConfigMap was updated:
   ```bash
   kubectl describe configmap agent-guard-policies -n agent-security
   ```
3. Force reload by restarting the pod:
   ```bash
   kubectl rollout restart deployment/agent-guard -n agent-security
   ```

### Policy Conflict Resolution

If conflicting policies produce unexpected results:

1. Test the specific request:
   ```bash
   agent-identity-guard policy test \
     --policy-file policies/ \
     --request '{"agent_id":"x","action":"s3:GetObject","resource":"arn:..."}'
   ```
2. Check policy priority ordering (higher priority wins)
3. Remember: explicit DENY always overrides ALLOW regardless of priority

---

## Maintenance Windows

### Certificate Rotation

1. Generate new certificates
2. Update Kubernetes secret:
   ```bash
   kubectl create secret tls agent-guard-tls \
     --cert=new-cert.pem --key=new-key.pem \
     --dry-run=client -o yaml | kubectl apply -f -
   ```
3. Rolling restart to pick up new certs:
   ```bash
   kubectl rollout restart deployment/agent-guard -n agent-security
   ```

### API Key Rotation

1. Generate new keys
2. Update the secret/environment:
   ```bash
   kubectl create secret generic agent-guard-api-keys \
     --from-literal=keys="newkey1,newkey2,oldkey1" \
     --dry-run=client -o yaml | kubectl apply -f -
   ```
3. Restart to load new keys
4. Update all SDK clients with new keys
5. Remove old keys after all clients are updated (grace period: 24h)

### Database Maintenance (DynamoDB)

1. Check table metrics in AWS Console
2. Review provisioned capacity vs actual usage
3. Clean up expired approvals (auto-TTL should handle this)
4. Verify backup schedule is running
