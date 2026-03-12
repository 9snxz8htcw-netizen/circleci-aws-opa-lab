package aws.s3.security
# Test that encrypted S3 bucket with versioning is allowed
test_encrypted_bucket_allowed {
    count(deny) == 0 with input as {
        "resource_type": "aws_s3_bucket",
        "bucket": "my-secure-bucket",
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
# Test that unencrypted S3 bucket is denied
test_unencrypted_bucket_denied {
    count(deny) > 0 with input as {
        "resource_type": "aws_s3_bucket"
    }
}
# Test that public-read bucket is denied
test_public_read_bucket_denied {
    count(deny) > 0 with input as {
        "resource_type": "aws_s3_bucket",
        "acl": "public-read",
        "server_side_encryption_configuration": {}
    }
}
