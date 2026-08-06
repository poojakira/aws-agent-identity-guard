terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# ── Variables ──────────────────────────────────────────────────────────────────

variable "environment" {
  type        = string
  description = "Deployment environment (dev | staging | prod)"
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be dev, staging, or prod"
  }
}

variable "trusted_account_id" {
  type        = string
  description = "AWS account ID of the CI/CD system that assumes the scanner role."
}

variable "external_id" {
  type        = string
  description = "Non-guessable ExternalId for confused-deputy protection. Store in Secrets Manager."
  sensitive   = true
}

variable "tags" {
  type        = map(string)
  default     = {}
  description = "Additional resource tags."
}

# ── Local values ───────────────────────────────────────────────────────────────

locals {
  name_prefix = "aws-agent-identity-guard-${var.environment}"
  common_tags = merge(var.tags, {
    Project     = "aws-agent-identity-guard"
    Environment = var.environment
    ManagedBy   = "terraform"
  })
}

# ── IAM policy: read-only permissions for the scanner ─────────────────────────

data "aws_iam_policy_document" "scanner_permissions" {
  statement {
    sid    = "IAMReadOnly"
    effect = "Allow"
    actions = [
      "iam:ListRoles",
      "iam:ListUsers",
      "iam:GetRole",
      "iam:GetUser",
      "iam:ListRolePolicies",
      "iam:ListAttachedRolePolicies",
      "iam:GetRolePolicy",
      "iam:GetPolicy",
      "iam:GetPolicyVersion",
      "iam:ListUserPolicies",
      "iam:ListAttachedUserPolicies",
      "iam:ListUserTags",
    ]
    resources = ["*"]
    # NOTE: IAM is a global service — region conditions do NOT apply.
    # Resource-level restriction is not possible for iam:List*/Get* actions
    # because they operate on account-wide resources.
    # The scope is inherently limited to the account containing this role.
  }

  statement {
    sid    = "STSIdentity"
    effect = "Allow"
    actions = [
      "sts:GetCallerIdentity",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "scanner" {
  name        = "${local.name_prefix}-scanner-policy"
  description = "Read-only IAM enumeration for aws-agent-identity-guard (${var.environment})"
  policy      = data.aws_iam_policy_document.scanner_permissions.json
  tags        = local.common_tags
}

# ── Trust policy: allow the CI/CD account to assume with ExternalId ───────────

data "aws_iam_policy_document" "scanner_trust" {
  statement {
    sid     = "AllowCICDAssumeRole"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.trusted_account_id}:root"]
    }

    # Confused-deputy protection: require ExternalId
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [var.external_id]
    }
  }
}

resource "aws_iam_role" "scanner" {
  name               = "${local.name_prefix}-scanner-role"
  description        = "Assumed by aws-agent-identity-guard to enumerate IAM resources (${var.environment})"
  assume_role_policy = data.aws_iam_policy_document.scanner_trust.json
  tags               = local.common_tags
}

resource "aws_iam_role_policy_attachment" "scanner" {
  role       = aws_iam_role.scanner.name
  policy_arn = aws_iam_policy.scanner.arn
}

# ── CloudWatch log group for scan evidence ────────────────────────────────────

resource "aws_cloudwatch_log_group" "scanner" {
  name              = "/aws-agent-identity-guard/${var.environment}"
  retention_in_days = 90
  tags              = local.common_tags
}

# ── Outputs ───────────────────────────────────────────────────────────────────

output "scanner_role_arn" {
  value       = aws_iam_role.scanner.arn
  description = "ARN of the IAM scanner role — provide to CI as AWS_ROLE_ARN."
}

output "scanner_policy_arn" {
  value       = aws_iam_policy.scanner.arn
  description = "ARN of the read-only IAM scanner policy."
}

output "log_group_name" {
  value       = aws_cloudwatch_log_group.scanner.name
  description = "CloudWatch log group for scan evidence."
}
