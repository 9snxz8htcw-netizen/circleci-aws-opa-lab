package compliance.metadata

# =============================================================================
# Compliance Control Mapping
# Maps OPA policy rules to NIST 800-53, SOC 2, and ISO 27001 controls
# =============================================================================

control_mapping = {
    "encryption_at_rest": {
        "description": "Data at rest must be encrypted",
        "nist_800_53": ["SC-28"],
        "soc2": ["CC6.1"],
        "iso_27001": ["A.10.1.1"],
        "severity": "HIGH",
        "policy": "data.aws.s3.security.deny"
    },
    "versioning_backup": {
        "description": "Versioning must be enabled for backup and recovery",
        "nist_800_53": ["CP-9"],
        "soc2": ["A1.2"],
        "iso_27001": ["A.12.3.1"],
        "severity": "HIGH",
        "policy": "data.aws.s3.security.deny"
    },
    "public_access_restriction": {
        "description": "Public access must be blocked on all S3 buckets",
        "nist_800_53": ["AC-3"],
        "soc2": ["CC6.6"],
        "iso_27001": ["A.9.4.1"],
        "severity": "CRITICAL",
        "policy": "data.aws.s3.security.deny"
    },
    "asset_tagging": {
        "description": "Resources must have required tags for asset inventory",
        "nist_800_53": ["CM-8"],
        "soc2": ["CC7.1"],
        "iso_27001": ["A.8.1.1"],
        "severity": "MEDIUM",
        "policy": "data.aws.s3.security.warn"
    }
}
