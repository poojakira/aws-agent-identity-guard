# Deployment Guide

## Prerequisites

- Python 3.10+
- Docker 24+ (for container deployments)
- kubectl 1.28+ (for Kubernetes)
- Helm 3.12+ (for Helm chart)
- Terraform 1.5+ (for AWS infrastructure)

---

## Docker Standalone

### Build the Image

```bash
docker build -t aws-agent-identity-guard:1.0.0 .
```

The Dockerfile uses a multi-stage build:
1. **Builder stage** — compiles the Python wheel
2. **Production stage** — minimal runtime image with non-root user

### Run the Container

```bash
docker run -d \
  --name agent-guard \
  -p 8080:8080 \
  -p 9090:9090 \
  -e GUARD_ENVIRONMENT=production \
  -e GUARD_LOG_LEVEL=info \
  -e GUARD_FAIL_MODE=closed \
  -v $(pwd)/policies:/app/policies:ro \
  --memory=512m \
  --cpus=1.0 \
  aws-agent-identity-guard:1.0.0
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GUARD_ENVIRONMENT` | `production` | Deployment environment (`dev`, `staging`, `production`) |
| `GUARD_LOG_LEVEL` | `info` | Log level (`debug`, `info`, `warn`, `error`) |
| `GUARD_FAIL_MODE` | `closed` | Failure behavior (`closed` = deny, `open` = allow) |
| `GUARD_METRICS_PORT` | `9090` | Prometheus metrics port |
| `GUARD_AUTH_ENABLED` | `true` | Enable API key authentication |
| `GUARD_RATE_LIMIT_PER_SECOND` | `1000` | Global rate limit |
| `REDIS_URL` | — | Redis connection URL (optional) |

### Health Check

```bash
curl http://localhost:8080/v1/health
# {"status": "healthy", "version": "1.0.0"}

curl http://localhost:8080/v1/health/ready
# {"status": "ready", "checks": {...}}
```

---

## Docker Compose (Full Stack)

The provided `docker-compose.yml` deploys the complete stack:

| Service | Port | Description |
|---------|------|-------------|
| `guard-api` | 8080, 9090 | Agent Identity Guard API + metrics |
| `redis` | 6379 | Decision cache and state |
| `prometheus` | 9091 | Metrics collection |
| `grafana` | 3000 | Dashboards and visualization |

### Start the Stack

```bash
docker compose up -d
```

### Verify All Services

```bash
docker compose ps
docker compose logs guard-api --tail 20
```

### Access Points

- **API**: http://localhost:8080/v1/health
- **Metrics**: http://localhost:9090/v1/metrics
- **Prometheus**: http://localhost:9091
- **Grafana**: http://localhost:3000 (admin/admin)

### Configuration

Mount custom policies:

```bash
# Place policy YAML files in ./policies directory
mkdir -p policies
cp my-policies/*.yaml policies/

docker compose up -d
```

### Production Overrides

Create `docker-compose.prod.yml`:

```yaml
version: '3.9'

services:
  guard-api:
    environment:
      - GUARD_ENVIRONMENT=production
      - GUARD_FAIL_MODE=closed
      - GUARD_AUTH_ENABLED=true
    deploy:
      replicas: 3
      resources:
        limits:
          memory: 1G
          cpus: '2.0'
        reservations:
          memory: 256M
          cpus: '0.5'

  redis:
    command: redis-server --maxmemory 256mb --maxmemory-policy allkeys-lru
    deploy:
      resources:
        limits:
          memory: 256M
```

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

### Stop and Clean Up

```bash
docker compose down          # Stop containers
docker compose down -v       # Stop + remove volumes
```

---

## Kubernetes / Helm

### Install the Helm Chart

```bash
helm install agent-guard ./helm/agent-identity-guard \
  --namespace agent-guard \
  --create-namespace \
  --values custom-values.yaml
```

### Minimal `custom-values.yaml`

```yaml
replicaCount: 3

image:
  repository: ghcr.io/poojakira/aws-agent-identity-guard
  tag: '1.0.0'

config:
  environment: production
  failMode: closed
  logLevel: info
  authEnabled: true
  rateLimitPerSecond: 1000

redis:
  enabled: true
  host: redis.agent-guard.svc.cluster.local
  port: 6379

serviceAccount:
  create: true
  annotations:
    eks.amazonaws.com/role-arn: 'arn:aws:iam::123456789012:role/agent-guard-eks-role'

ingress:
  enabled: true
  className: alb
  annotations:
    alb.ingress.kubernetes.io/scheme: internal
    alb.ingress.kubernetes.io/target-type: ip
  hosts:
    - host: agent-guard.internal.company.com
      paths:
        - path: /v1
          pathType: Prefix
```

### Chart Values Reference

| Key | Default | Description |
|-----|---------|-------------|
| `replicaCount` | 3 | Number of pod replicas |
| `image.repository` | `ghcr.io/poojakira/aws-agent-identity-guard` | Container registry |
| `image.tag` | `1.0.0` | Image tag |
| `image.pullPolicy` | `IfNotPresent` | Image pull policy |
| `service.type` | `ClusterIP` | Kubernetes service type |
| `service.port` | `8080` | API service port |
| `service.metricsPort` | `9090` | Metrics port |
| `resources.limits.cpu` | `1` | CPU limit |
| `resources.limits.memory` | `512Mi` | Memory limit |
| `resources.requests.cpu` | `250m` | CPU request |
| `resources.requests.memory` | `128Mi` | Memory request |
| `autoscaling.enabled` | `true` | Enable HPA |
| `autoscaling.minReplicas` | `3` | Minimum replicas |
| `autoscaling.maxReplicas` | `10` | Maximum replicas |
| `autoscaling.targetCPUUtilization` | `70` | CPU target % |
| `autoscaling.targetMemoryUtilization` | `80` | Memory target % |
| `config.environment` | `production` | App environment |
| `config.failMode` | `closed` | Failure behavior |
| `config.logLevel` | `info` | Log verbosity |
| `config.authEnabled` | `true` | API authentication |
| `config.rateLimitPerSecond` | `1000` | Rate limit |
| `redis.enabled` | `true` | Use Redis cache |
| `redis.host` | `redis` | Redis hostname |
| `redis.port` | `6379` | Redis port |
| `monitoring.serviceMonitor.enabled` | `true` | Prometheus ServiceMonitor |
| `monitoring.serviceMonitor.interval` | `30s` | Scrape interval |

### Upgrade

```bash
helm upgrade agent-guard ./helm/agent-identity-guard \
  --namespace agent-guard \
  --values custom-values.yaml
```

### Rollback

```bash
helm rollback agent-guard 1 --namespace agent-guard
```

### Uninstall

```bash
helm uninstall agent-guard --namespace agent-guard
```

---

## AWS Reference Architecture

### ECS (Fargate)

```
┌─────────────────────────────────────────────────────────────────┐
│  VPC                                                             │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Private Subnet (AZ-a)          Private Subnet (AZ-b)     │  │
│  │  ┌─────────────┐               ┌─────────────┐           │  │
│  │  │ ECS Task    │               │ ECS Task    │           │  │
│  │  │ guard-api   │               │ guard-api   │           │  │
│  │  └──────┬──────┘               └──────┬──────┘           │  │
│  │         │                              │                  │  │
│  │  ┌──────▼──────────────────────────────▼──────┐           │  │
│  │  │        Internal ALB                         │           │  │
│  │  └──────────────────┬─────────────────────────┘           │  │
│  │                     │                                     │  │
│  │  ┌──────────────────▼─────────────────────────┐           │  │
│  │  │      ElastiCache Redis (Cluster Mode)       │           │  │
│  │  └────────────────────────────────────────────┘           │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  CloudWatch Logs    │  Secrets Manager  │  IAM Roles       │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

**ECS Task Definition (key fields):**

```json
{
  "family": "agent-identity-guard",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "1024",
  "memory": "2048",
  "containerDefinitions": [
    {
      "name": "guard-api",
      "image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/agent-identity-guard:1.0.0",
      "portMappings": [
        {"containerPort": 8080, "protocol": "tcp"},
        {"containerPort": 9090, "protocol": "tcp"}
      ],
      "environment": [
        {"name": "GUARD_ENVIRONMENT", "value": "production"},
        {"name": "GUARD_FAIL_MODE", "value": "closed"}
      ],
      "secrets": [
        {"name": "GUARD_API_KEY", "valueFrom": "arn:aws:secretsmanager:us-east-1:123456789012:secret:guard-api-key"}
      ],
      "healthCheck": {
        "command": ["CMD-SHELL", "python -c \"import urllib.request; urllib.request.urlopen('http://localhost:8080/v1/health')\""],
        "interval": 30,
        "timeout": 5,
        "retries": 3
      },
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/agent-identity-guard",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "guard"
        }
      }
    }
  ]
}
```

### EKS

Use the Helm chart with EKS-specific values:

```yaml
serviceAccount:
  create: true
  annotations:
    eks.amazonaws.com/role-arn: 'arn:aws:iam::123456789012:role/agent-guard-eks-role'

ingress:
  enabled: true
  className: alb
  annotations:
    alb.ingress.kubernetes.io/scheme: internal
    alb.ingress.kubernetes.io/target-type: ip
    alb.ingress.kubernetes.io/subnets: subnet-abc123,subnet-def456
    alb.ingress.kubernetes.io/security-groups: sg-guard-alb
    alb.ingress.kubernetes.io/healthcheck-path: /v1/health/ready
  hosts:
    - host: agent-guard.internal.company.com
      paths:
        - path: /v1
          pathType: Prefix
```

---

## Terraform

### Module Structure

```
infra/terraform/
├── modules/
│   └── scanner-iam/
│       └── main.tf          # IAM role + policy for CI scanner
└── environments/
    └── dev/
        └── main.tf          # Environment-specific configuration
```

### Deploy Scanner IAM Role

```bash
cd infra/terraform/environments/dev

terraform init
terraform plan \
  -var="trusted_account_id=111122223333" \
  -var="external_id=your-secret-external-id"

terraform apply \
  -var="trusted_account_id=111122223333" \
  -var="external_id=your-secret-external-id"
```

### What Gets Created

| Resource | Purpose |
|----------|---------|
| `aws_iam_role` | Cross-account role for CI scanner |
| `aws_iam_policy` | Read-only IAM enumeration permissions |
| `aws_cloudwatch_log_group` | Scan evidence logs (90-day retention) |

### Scanner IAM Permissions (Least Privilege)

The scanner role grants only:
- `iam:ListRoles`, `iam:ListUsers`
- `iam:GetRole`, `iam:GetUser`
- `iam:ListRolePolicies`, `iam:ListAttachedRolePolicies`
- `iam:GetRolePolicy`, `iam:GetPolicy`, `iam:GetPolicyVersion`
- `sts:GetCallerIdentity`

### Trust Policy

Requires `sts:ExternalId` for confused-deputy protection:

```hcl
condition {
  test     = "StringEquals"
  variable = "sts:ExternalId"
  values   = [var.external_id]
}
```

### Outputs

| Output | Description |
|--------|-------------|
| `scanner_role_arn` | ARN to configure in CI as `AWS_ROLE_ARN` |
| `scanner_policy_arn` | ARN of the read-only policy |
| `log_group_name` | CloudWatch log group for scan evidence |

---

## Configuration Reference

### Policy Files

Place YAML policy files in the `/app/policies` directory (or mount via volume):

```
policies/
├── base.yaml              # Default deny rules
├── production.yaml        # Production-specific rules
├── staging.yaml           # Staging overrides
└── team-specific/
    ├── finance.yaml       # Finance team policies
    └── engineering.yaml   # Engineering team policies
```

### Logging Configuration

| Variable | Options | Description |
|----------|---------|-------------|
| `GUARD_LOG_LEVEL` | `debug`, `info`, `warn`, `error` | Minimum log level |
| `GUARD_LOG_FORMAT` | `json`, `text` | Output format |
| `GUARD_LOG_DESTINATION` | `stdout`, `file` | Log destination |

### Redis Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_URL` | — | Full Redis URL (`redis://host:port/db`) |
| `REDIS_HOST` | `localhost` | Redis hostname |
| `REDIS_PORT` | `6379` | Redis port |
| `REDIS_DB` | `0` | Redis database number |
| `REDIS_PASSWORD` | — | Redis authentication password |
| `REDIS_TLS` | `false` | Enable TLS connections |

### Performance Tuning

| Variable | Default | Description |
|----------|---------|-------------|
| `GUARD_CACHE_SIZE` | `10000` | Maximum cached decisions |
| `GUARD_CACHE_TTL_SECONDS` | `300` | Cache entry TTL |
| `GUARD_WORKER_THREADS` | `4` | Request handler threads |
| `GUARD_MAX_CONNECTIONS` | `1000` | Max concurrent connections |

---

## Security Hardening Checklist

### Container

- [ ] Run as non-root user (`USER guard` in Dockerfile)
- [ ] Use minimal base image (`python:3.12-slim`)
- [ ] Set resource limits (CPU and memory)
- [ ] Mount policy files read-only (`:ro`)
- [ ] Scan container image for CVEs before deployment
- [ ] Sign container images (cosign/notation)
- [ ] Use specific image tags, not `:latest`

### Network

- [ ] Deploy behind internal-only load balancer
- [ ] Restrict security group ingress to known CIDR ranges
- [ ] Separate metrics port (9090) from API port (8080)
- [ ] Enable TLS termination at load balancer
- [ ] Use VPC endpoints for AWS service access
- [ ] Enable VPC Flow Logs for traffic auditing

### Authentication & Authorization

- [ ] Enable API key authentication (`GUARD_AUTH_ENABLED=true`)
- [ ] Rotate API keys regularly (recommended: 90 days)
- [ ] Store API keys in Secrets Manager or Parameter Store
- [ ] Use separate keys per client/environment
- [ ] Configure rate limiting appropriate to workload

### Data Protection

- [ ] Enable encryption at rest for Redis (ElastiCache)
- [ ] Enable encryption in transit (TLS) for Redis
- [ ] Store Terraform state encrypted in S3 with DynamoDB locking
- [ ] Mark sensitive variables as `sensitive = true` in Terraform
- [ ] Never log authorization decisions with request payloads in debug mode in production

### IAM

- [ ] Use IAM Roles for Service Accounts (IRSA) on EKS
- [ ] Use ECS task roles (not instance roles)
- [ ] Apply least-privilege to the scanner role itself
- [ ] Require ExternalId for cross-account role assumption
- [ ] Enable CloudTrail logging for IAM API calls

### Operational Security

- [ ] Enable container health checks (liveness + readiness)
- [ ] Set restart policies (`unless-stopped` / `Always`)
- [ ] Configure alerting on error rate spikes
- [ ] Set up log retention policies (90+ days for compliance)
- [ ] Enable `fail_closed` mode in production
- [ ] Test failover scenarios regularly
- [ ] Document incident response procedures

### Supply Chain

- [ ] Pin dependency versions in `pyproject.toml`
- [ ] Enable Dependabot for automated vulnerability scanning
- [ ] Review third-party dependencies before adoption
- [ ] Use private container registry with vulnerability scanning
- [ ] Sign releases and publish checksums

### Monitoring

- [ ] Configure Prometheus scraping for `/v1/metrics`
- [ ] Set up Grafana dashboards for key metrics
- [ ] Alert on authorization denial rate spikes
- [ ] Alert on latency p99 exceeding SLO
- [ ] Monitor Redis connection pool utilization
- [ ] Track cache hit ratio (should be > 70%)
