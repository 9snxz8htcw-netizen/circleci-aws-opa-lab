package aws.s3.security

test_compliant_bucket_passes {
    count(deny) == 0 with input as {
        "resource_type": "aws_s3_bucket",
        "bucket": "compliant-bucket",
        "server_side_encryption_configuration": {
            "rule": {
                "apply_server_side_encryption_by_default": {
                    "sse_algorithm": "AES256"
                }
            }
        },
        "versioning": {"enabled": true}
    }
}

test_unencrypted_bucket_denied {
    count(deny) > 0 with input as {
        "resource_type": "aws_s3_bucket",
        "bucket": "bad-bucket"
    }
}

test_missing_versioning_denied {
    count(deny) > 0 with input as {
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
}
