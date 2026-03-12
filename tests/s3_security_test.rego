package aws.s3.security_test

import data.aws.s3.security

# Test compliant S3 bucket passes without violations
test_compliant_s3_bucket_no_violations {
    count(security.deny) == 0 with input as {
        "resource_type": "aws_s3_bucket",
        "bucket": "compliant-bucket",
        "server_side_encryption_configuration": {
            "rule": {
                "apply_server_side_encryption_by_default": {
                    "sse_algorithm": "AES256"
                }
            }
        },
        "versioning": {
            "enabled": true
        }
    }
}

# Test non-compliant S3 bucket is flagged
test_non_compliant_s3_bucket_has_violations {
    count(security.deny) > 0 with input as {
        "resource_type": "aws_s3_bucket",
        "bucket": "non-compliant-bucket"
    }
}

# Test S3 bucket missing encryption is flagged
test_missing_encryption_flagged {
    violations := security.deny with input as {
        "resource_type": "aws_s3_bucket",
        "bucket": "no-encryption-bucket",
        "versioning": {
            "enabled": true
        }
    }
    count(violations) == 1
}

# Test S3 bucket missing versioning is flagged
test_missing_versioning_flagged {
    violations := security.deny with input as {
        "resource_type": "aws_s3_bucket",
        "bucket": "no-versioning-bucket",
        "server_side_encryption_configuration": {
            "rule": {
                "apply_server_side_encryption_by_default": {
                    "sse_algorithm": "AES256"
                }
            }
        }
    }
    count(violations) == 1
}
