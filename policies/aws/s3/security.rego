package aws.s3.security

# =============================================================================
# AWS S3 Security Policy
# =============================================================================
# Framework Mappings:
#   NIST 800-53: SC-28, CP-9, AC-3, CM-8
#   SOC 2:       CC6.1, A1.2, CC6.6, CC7.1
#   ISO 27001:   A.10.1.1, A.12.3.1, A.9.4.1, A.8.1.1
# =============================================================================

# -----------------------------------------------------------------------------
# RULE: Deny S3 buckets without server-side encryption
# NIST 800-53: SC-28 (Protection of Information at Rest)
# SOC 2:       CC6.1 (Logical and Physical Access Controls)
# ISO 27001:   A.10.1.1 (Policy on the use of cryptographic controls)
# -----------------------------------------------------------------------------
deny[msg] {
    input.resource_type == "aws_s3_bucket"
    not has_encryption
    msg := sprintf(
        "[SC-28][CC6.1][A.10.1.1] S3 bucket '%v' violates encryption-at-rest requirement",
        [input.bucket]
    )
}

# -----------------------------------------------------------------------------
# RULE: Deny S3 buckets without versioning enabled
# NIST 800-53: CP-9 (Information System Backup)
# SOC 2:       A1.2 (Availability - Recovery Time Objectives)
# ISO 27001:   A.12.3.1 (Information backup)
# -----------------------------------------------------------------------------
deny[msg] {
    input.resource_type == "aws_s3_bucket"
    not has_versioning
    msg := sprintf(
        "[CP-9][A1.2][A.12.3.1] S3 bucket '%v' violates versioning/backup requirement",
        [input.bucket]
    )
}

# -----------------------------------------------------------------------------
# RULE: Deny S3 buckets with public access enabled
# NIST 800-53: AC-3 (Access Enforcement)
# SOC 2:       CC6.6 (Logical Access - External Threats)
# ISO 27001:   A.9.4.1 (Information access restriction)
# -----------------------------------------------------------------------------
deny[msg] {
    input.resource_type == "aws_s3_bucket"
    input.acl == "public-read"
    msg := sprintf(
        "[AC-3][CC6.6][A.9.4.1] S3 bucket '%v' violates public access restriction requirement",
        [input.bucket]
    )
}

deny[msg] {
    input.resource_type == "aws_s3_bucket"
    input.acl == "public-read-write"
    msg := sprintf(
        "[AC-3][CC6.6][A.9.4.1] S3 bucket '%v' violates public access restriction requirement",
        [input.bucket]
    )
}

# -----------------------------------------------------------------------------
# RULE: Warn on S3 buckets missing required tags
# NIST 800-53: CM-8 (Information System Component Inventory)
# SOC 2:       CC7.1 (System Monitoring)
# ISO 27001:   A.8.1.1 (Inventory of assets)
# -----------------------------------------------------------------------------
warn[msg] {
    input.resource_type == "aws_s3_bucket"
    not has_required_tags
    msg := sprintf(
        "[CM-8][CC7.1][A.8.1.1] S3 bucket '%v' is missing required tags for asset inventory",
        [input.bucket]
    )
}

# =============================================================================
# Helper Rules
# =============================================================================

has_encryption {
    input.server_side_encryption_configuration.rule.apply_server_side_encryption_by_default.sse_algorithm
}

has_versioning {
    input.versioning.enabled == true
}

has_required_tags {
    input.tags.Environment
    input.tags.Owner
    input.tags.CostCenter
}
