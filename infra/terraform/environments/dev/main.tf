terraform {
  required_version = ">= 1.5"

  # Remote state: S3 backend with DynamoDB locking.
  # Uncomment and populate before running `terraform init` in a real environment.
  #
  # backend "s3" {
  #   bucket         = "your-terraform-state-bucket"
  #   key            = "aws-agent-identity-guard/dev/terraform.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "terraform-state-lock"
  #   encrypt        = true
  # }
}

provider "aws" {
  region = "us-east-1"

  default_tags {
    tags = {
      Project     = "aws-agent-identity-guard"
      Environment = "dev"
      ManagedBy   = "terraform"
    }
  }
}

module "scanner_iam" {
  source = "../../modules/scanner-iam"

  environment        = "dev"
  trusted_account_id = var.trusted_account_id
  external_id        = var.external_id
}

variable "trusted_account_id" {
  type        = string
  description = "AWS account ID of the CI/CD system."
}

variable "external_id" {
  type        = string
  description = "ExternalId for confused-deputy protection."
  sensitive   = true
}

output "scanner_role_arn" {
  value = module.scanner_iam.scanner_role_arn
}
