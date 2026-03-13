# CircleCI AWS OPA Integration Lab

A portfolio lab demonstrating a production-style CI/CD security pipeline that enforces infrastructure compliance using Open Policy Agent (OPA), AWS OIDC authentication, and Terraform with no long-lived credentials.

## What This Lab Demonstrates

- Preventive controls enforced at the pipeline level
- Keyless cloud authentication using OIDC (no static AWS credentials)
- Automated policy validation against infrastructure-as-code
- Compliance-as-code aligned to NIST 800-53, SOC 2, and ISO 27001

## Pipeline Jobs

### policy-validation
- Downloads OPA binary
- Runs OPA unit tests against policies/ and tests/
- Validates Terraform resource JSON against S3 security policies
- Blocks the pipeline if any violations are found

### deploy-compliant-infrastructure
- Only runs if policy-validation passes
- Authenticates to AWS using CircleCI OIDC token (keyless)
- Deploys a fully compliant S3 bucket via Terraform
- Destroys resources after validation to avoid AWS charges

## Compliance Controls Implemented

| Control | Framework | Implementation |
|---------|-----------|----------------|
| SC-28 - Data at rest encryption | NIST 800-53 | S3 SSE-AES256 enforced by OPA |
| CP-9 - Backup and recovery | NIST 800-53 | S3 versioning enforced by OPA |
| AC-3 - Access enforcement | NIST 800-53 | Public access block in Terraform |
| CM-8 - Asset inventory | NIST 800-53 | Mandatory tagging enforced by OPA |
| CC6.1 - Logical access controls | SOC 2 | Encryption policy enforcement |
| A.10.1.1 - Cryptographic controls | ISO 27001 | Encryption at rest |
| A.12.3.1 - Information backup | ISO 27001 | Versioning policy |

## Author

Chris Cutts - Senior Security Risk Lead | GRC Engineering
