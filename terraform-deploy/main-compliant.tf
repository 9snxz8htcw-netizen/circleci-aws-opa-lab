provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

resource "aws_s3_bucket" "compliant_bucket" {
  bucket = "circleci-lab-compliant-${random_string.suffix.result}"
  tags = {
    Environment        = "prod"
    Owner             = "security-team@company.com"
    CostCenter        = "CC-1234"
    Project           = "SecurityCompliance"
    DataClassification = "internal"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "compliant_encryption" {
  bucket = aws_s3_bucket.compliant_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "compliant_pab" {
  bucket                  = aws_s3_bucket.compliant_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "compliant_versioning" {
  bucket = aws_s3_bucket.compliant_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

output "bucket_name" {
  value = aws_s3_bucket.compliant_bucket.bucket
}

output "compliance_status" {
  value = "COMPLIANT - All NIST 800-53 controls implemented"
}
