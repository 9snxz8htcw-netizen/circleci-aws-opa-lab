# Compliance Control Mapping

This document maps OPA policy rules to NIST 800-53, SOC 2, and ISO 27001 controls.

## S3 Security Controls

| Policy Rule | Severity | NIST 800-53 | SOC 2 | ISO 27001 | Description |
|-------------|----------|-------------|-------|-----------|-------------|
| Encryption at rest | HIGH | SC-28 | CC6.1 | A.10.1.1 | S3 buckets must have server-side encryption enabled |
| Versioning/Backup | HIGH | CP-9 | A1.2 | A.12.3.1 | S3 buckets must have versioning enabled |
| Public access block | CRITICAL | AC-3 | CC6.6 | A.9.4.1 | S3 buckets must block all public access |
| Asset tagging | MEDIUM | CM-8 | CC7.1 | A.8.1.1 | S3 buckets must have required tags |

## Control Descriptions

### NIST 800-53

| Control | Name | Description |
|---------|------|-------------|
| SC-28 | Protection of Information at Rest | The information system protects the confidentiality and integrity of information at rest |
| CP-9 | Information System Backup | The organization conducts backups of user-level and system-level information |
| AC-3 | Access Enforcement | The information system enforces approved authorizations for logical access |
| CM-8 | Information System Component Inventory | The organization develops and documents an inventory of information system components |

### SOC 2

| Control | Name | Description |
|---------|------|-------------|
| CC6.1 | Logical and Physical Access Controls | The entity implements logical access security software and policies |
| A1.2 | Availability | The entity authorizes, designs, develops, and implements controls over infrastructure |
| CC6.6 | Logical Access - External Threats | The entity implements controls to prevent or detect unauthorized access from external threats |
| CC7.1 | System Monitoring | The entity uses detection and monitoring procedures to identify changes to configurations |

### ISO 27001

| Control | Name | Description |
|---------|------|-------------|
| A.10.1.1 | Policy on cryptographic controls | A policy on the use of cryptographic controls shall be developed and implemented |
| A.12.3.1 | Information backup | Backup copies of information shall be taken and tested in accordance with an agreed backup policy |
| A.9.4.1 | Information access restriction | Access to information and application system functions shall be restricted in accordance with the access control policy |
| A.8.1.1 | Inventory of assets | Assets associated with information and information processing facilities shall be identified |

## How Controls Are Enforced

Controls are enforced at the CI/CD pipeline level using Open Policy Agent (OPA):

1. Terraform resources are converted to JSON
2. OPA evaluates each resource against policy rules in `policies/aws/s3/security.rego`
3. Violations cause the `policy-validation` job to fail with exit code 1
4. The `deploy-compliant-infrastructure` job is blocked until all violations are resolved
5. Only compliant infrastructure is ever deployed to AWS
