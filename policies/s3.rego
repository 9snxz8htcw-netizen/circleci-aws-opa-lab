package aws.s3.security

deny[msg] {
    input.resource_type == "aws_s3_bucket"
    not input.server_side_encryption_configuration.rule.apply_server_side_encryption_by_default.sse_algorithm
    msg := "S3 bucket must have server-side encryption enabled"
}

deny[msg] {
    input.resource_type == "aws_s3_bucket"
    input.acl == "public-read"
    msg := "S3 bucket must not have public-read ACL"
}

deny[msg] {
    input.resource_type == "aws_s3_bucket"
    input.acl == "public-read-write"
    msg := "S3 bucket must not have public-read-write ACL"
}
