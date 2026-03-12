package aws.s3.security

# Deny S3 buckets without server-side encryption enabled
deny[msg] {
    input.resource_type == "aws_s3_bucket"
    not has_encryption
    msg := sprintf("S3 bucket '%v' does not have server-side encryption enabled", [input.bucket])
}

# Deny S3 buckets without versioning enabled
deny[msg] {
    input.resource_type == "aws_s3_bucket"
    not has_versioning
    msg := sprintf("S3 bucket '%v' does not have versioning enabled", [input.bucket])
}

# Check if bucket has server-side encryption configured
has_encryption {
    input.server_side_encryption_configuration.rule.apply_server_side_encryption_by_default.sse_algorithm
}

# Check if bucket has versioning enabled
has_versioning {
    input.versioning.enabled == true
}
