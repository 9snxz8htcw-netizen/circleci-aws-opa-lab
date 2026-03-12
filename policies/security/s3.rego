package aws.s3.security

deny[msg] {
    input.resource_type == "aws_s3_bucket"
    not input.server_side_encryption_configuration
    msg := "S3 buckets must have server-side encryption enabled"
}

deny[msg] {
    input.resource_type == "aws_s3_bucket"
    input.acl == "public-read"
    msg := "S3 buckets must not have public-read ACL"
}

warn[msg] {
    input.resource_type == "aws_s3_bucket"
    not input.versioning
    msg := "Consider enabling versioning for S3 buckets"
}
