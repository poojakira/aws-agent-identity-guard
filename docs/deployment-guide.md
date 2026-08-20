# Deployment Guide

---

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.10+ | 3.12 recommended for performance |
| pip or uv | Latest | uv recommended for fast installs |
| Docker | 24+ | For containerized deployment |
| Kubernetes | 1.27+ | For Helm deployment |
| Helm | 3.12+ | Chart management |
| Terraform | 1.5+ | For AWS infrastructure |
| AWS CLI | 2.x | For live scanning features |

---

## Local Development Setup

```bash
# Clone the repository
git clone https://github.com/aws/agent-identity-guard.git
cd agent-identity-guard

# Create virtual environment (using uv)
uv venv
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\activate   # Windows

# Install in development mode
uv pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Start the API server (development)
uvicorn aws_agent_identity_guard.api:app --reload --host 0.0.0.0 --port 8000

# Run the demo
python -m demo.run_demo
```

### Configuration

Create a `.env` file or set environment variables:

```bash
# Server
AGENT_GUARD_HOST=0.0.0.0
AGENT_GUARD_PORT=8000
AGENT_GUARD_WORKERS=4
AGENT_GUARD_LOG_LEVEL=INFO

# Security
AGENT_GUARD_API_KEYS=key1,key2,key3
AGENT_GUARD_CORS_ORIGINS=http://localhost:3000

# Policy
AGENT_GUARD_POLICY_DIR=./policies
AGENT_GUARD_DEFAULT_EFFECT=DENY

# Risk Engine
AGENT_GUARD_RISK_THRESHOLD=70
AGENT_GUARD_RISK_WEIGHTS=permission:0.3,network:0.2,data:0.3,behavior:0.2

# Authorization
AGENT_GUARD_MODE=ENFORCE  # ENFORCE | AUDIT | DRY_RUN
AGENT_GUARD_FAIL_OPEN=false
AGENT_GUARD_TIMEOUT_MS=100
```

---

## Docker Deployment

### Single Container

```bash
# Build
docker build -t agent-identity-guard:latest .

# Run
docker run -d \
  --name agent-guard \
  -p 8000:8000 \
  -v $(pwd)/policies:/app/policies:ro \
  -e AGENT_GUARD_API_KEYS=your-key \
  -e AGENT_GUARD_MODE=ENFORCE \
  agent-identity-guard:latest
```

### Docker Compose (Full Stack)

```bash
# Start API + Prometheus + Grafana
docker compose up -d

# Verify
curl http://localhost:8000/health
```

The `docker-compose.yml` includes:
- API server (port 8000)
- Prometheus (port 9090)
- Grafana (port 3000) with pre-configured dashboards

### Image Details

- Base: `python:3.12-slim`
- Multi-stage build (build deps not in final image)
- Non-root user (`appuser`, UID 1000)
- Read-only filesystem (writable /tmp only)
- No shell in production image
- Healthcheck built-in

---

## Kubernetes / Helm Deployment

### Install from Local Chart

```bash
helm install agent-guard ./helm/agent-identity-guard \
  --namespace agent-security \
  --create-namespace \
  --values my-values.yaml
```

### Key Values

```yaml
# helm/agent-identity-guard/values.yaml overrides
replicaCount: 3

image:
  repository: your-registry/agent-identity-guard
  tag: "1.0.0"

resources:
  requests:
    cpu: 500m
    memory: 512Mi
  limits:
    cpu: 1000m
    memory: 1Gi

autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70

env:
  AGENT_GUARD_MODE: ENFORCE
  AGENT_GUARD_LOG_LEVEL: INFO
  AGENT_GUARD_WORKERS: "4"

secrets:
  apiKeys:
    secretName: agent-guard-api-keys
    key: keys

ingress:
  enabled: true
  className: alb
  annotations:
    alb.ingress.kubernetes.io/scheme: internal
    alb.ingress.kubernetes.io/target-type: ip
  hosts:
    - host: agent-guard.internal.example.com
      paths:
        - path: /
          pathType: Prefix

podDisruptionBudget:
  enabled: true
  minAvailable: 1
```

### Verify Deployment

```bash
kubectl get pods -n agent-security
kubectl logs -f deployment/agent-guard -n agent-security
curl -k https://agent-guard.internal.example.com/health
```

---

## AWS Reference Architecture

### ECS / Fargate

```
Internet/VPC --> ALB (internal) --> ECS Service (Fargate)
                                        |
                                   Task Definition:
                                   - agent-guard container (port 8000)
                                   - log driver: awslogs
                                   - secrets from Secrets Manager
                                        |
                                   Service Discovery (Cloud Map)
```

Terraform module: `infra/terraform/modules/ecs/`

```bash
cd infra/terraform/environments/production
terraform init
terraform plan -var-file=prod.tfvars
terraform apply -var-file=prod.tfvars
```

Key resources created:
- ECS Cluster (Fargate)
- Task Definition with secrets injection
- ECS Service with desired count and health checks
- ALB with target group
- Security groups (restrict to VPC CIDR)
- CloudWatch log group
- IAM task role and execution role

### EKS

Deploy via Helm to an existing EKS cluster:

```bash
aws eks update-kubeconfig --name my-cluster --region us-east-1
helm install agent-guard ./helm/agent-identity-guard \
  --namespace agent-security \
  --set image.repository=123456789012.dkr.ecr.us-east-1.amazonaws.com/agent-guard \
  --set image.tag=1.0.0
```

### Lambda (Lightweight Mode)

For environments where a full server is not warranted, deploy as a Lambda function behind API Gateway:

```bash
cd infra/terraform/modules/lambda
terraform apply -var="handler=aws_agent_identity_guard.api.handler"
```

Limitations in Lambda mode:
- Cold start adds 200-400ms on first request
- No persistent in-memory cache (use DynamoDB for state)
- Concurrency limited by Lambda account limits

---

## Terraform Modules

| Module | Path | Purpose |
|--------|------|---------|
| ECS | `infra/terraform/modules/ecs/` | Fargate service + ALB |
| EKS | `infra/terraform/modules/eks/` | Helm release on EKS |
| Lambda | `infra/terraform/modules/lambda/` | Serverless deployment |
| Networking | `infra/terraform/modules/networking/` | VPC, subnets, security groups |
| Monitoring | `infra/terraform/modules/monitoring/` | CloudWatch, alarms |

### Shared Variables

```hcl
variable "environment" {
  type    = string
  default = "production"
}

variable "image_tag" {
  type    = string
  default = "1.0.0"
}

variable "api_keys" {
  type      = list(string)
  sensitive = true
}

variable "risk_threshold" {
  type    = number
  default = 70
}
```

---

## Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `AGENT_GUARD_HOST` | `0.0.0.0` | Bind address |
| `AGENT_GUARD_PORT` | `8000` | Listen port |
| `AGENT_GUARD_WORKERS` | `4` | Uvicorn workers |
| `AGENT_GUARD_LOG_LEVEL` | `INFO` | Log level (DEBUG, INFO, WARNING, ERROR) |
| `AGENT_GUARD_LOG_FORMAT` | `json` | Log format (json, text) |
| `AGENT_GUARD_API_KEYS` | - | Comma-separated API keys |
| `AGENT_GUARD_CORS_ORIGINS` | `*` | Allowed CORS origins |
| `AGENT_GUARD_POLICY_DIR` | `./policies` | Policy file directory |
| `AGENT_GUARD_DEFAULT_EFFECT` | `DENY` | Default when no policy matches |
| `AGENT_GUARD_MODE` | `ENFORCE` | ENFORCE, AUDIT, DRY_RUN |
| `AGENT_GUARD_FAIL_OPEN` | `false` | Allow on engine failure |
| `AGENT_GUARD_TIMEOUT_MS` | `100` | Max decision time |
| `AGENT_GUARD_RISK_THRESHOLD` | `70` | Score above this triggers STEP_UP |
| `AGENT_GUARD_RISK_WEIGHTS` | `0.3,0.2,0.3,0.2` | Permission, network, data, behavior |
| `AGENT_GUARD_CACHE_TTL` | `300` | Attack path cache TTL (seconds) |
| `AGENT_GUARD_METRICS_ENABLED` | `true` | Enable Prometheus metrics |
| `AGENT_GUARD_TLS_CERT` | - | TLS certificate path |
| `AGENT_GUARD_TLS_KEY` | - | TLS private key path |
| `AGENT_GUARD_TLS_CA` | - | CA certificate for mTLS |

---

## Health Checks and Monitoring

### Health Endpoint

```
GET /health
```

Returns component status. Use for:
- Kubernetes liveness probe: `/health`
- Kubernetes readiness probe: `/health`
- ALB target group health check: `/health`

### Prometheus Metrics

Available at `GET /metrics`. Key metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `agent_guard_decisions_total` | Counter | Total decisions by outcome |
| `agent_guard_latency_seconds` | Histogram | Request latency distribution |
| `agent_guard_risk_scores` | Histogram | Risk score distribution |
| `agent_guard_policy_evaluations_total` | Counter | Policy evaluation count |
| `agent_guard_errors_total` | Counter | Error count by type |
| `agent_guard_active_agents` | Gauge | Currently registered agents |
| `agent_guard_pending_approvals` | Gauge | Outstanding approval requests |

### Grafana Dashboard

Pre-built dashboard at `infra/grafana/provisioning/`. Import via Grafana UI or provision automatically with Docker Compose.

### Alerting Rules

Example Prometheus alert rules:

```yaml
groups:
  - name: agent-guard
    rules:
      - alert: HighDenyRate
        expr: rate(agent_guard_decisions_total{decision="DENY"}[5m]) > 10
        for: 5m
        labels:
          severity: warning
      - alert: HighLatency
        expr: histogram_quantile(0.99, agent_guard_latency_seconds_bucket) > 0.05
        for: 5m
        labels:
          severity: critical
      - alert: ServiceDown
        expr: up{job="agent-guard"} == 0
        for: 1m
        labels:
          severity: critical
```
