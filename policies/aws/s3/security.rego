package aws.s3.security

# Deny S3 buckets without server-side encryption enabled
deny[msg] {
    input.resource_type == "aws_s3_bucket"
    not has_encryption
    bucket_name := object.get(input, "bucket", "unknown")
    msg := sprintf("S3 bucket '%v' does not have server-side encryption enabled", [bucket_name])
}

# Deny S3 buckets without versioning enabled
deny[msg] {
    input.resource_type == "aws_s3_bucket"
    not has_versioning
    bucket_name := object.get(input, "bucket", "unknown")
    msg := sprintf("S3 bucket '%v' does not have versioning enabled", [bucket_name])
}

# Deny S3 buckets with public-read ACL
deny[msg] {
    input.resource_type == "aws_s3_bucket"
    input.acl == "public-read"
    bucket_name := object.get(input, "bucket", "unknown")
    msg := sprintf("S3 bucket '%v' has public-read ACL which is not allowed", [bucket_name])
}

# Check if bucket has server-side encryption configured
has_encryption {
    input.server_side_encryption_configuration.rule.apply_server_side_encryption_by_default.sse_algorithm
}

# Check if bucket has versioning enabled
has_versioning {
    input.versioning.enabled == true
}
