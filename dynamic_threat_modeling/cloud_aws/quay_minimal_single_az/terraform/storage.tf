# S3 Storage Configuration (Free Tier)
# THREAT INJECTION: T03, T05, T07, T08

# S3 Bucket for Quay Image Storage
resource "aws_s3_bucket" "quay_storage" {
  bucket = "quay-minimal-storage-${random_string.bucket_suffix.result}"

  tags = {
    Name        = "Quay Image Storage"
    Environment = var.environment
  }
}

resource "random_string" "bucket_suffix" {
  length  = 8
  special = false
  upper   = false
}

# T03: No encryption at rest
# Encryption disabled for demonstration
# resource "aws_s3_bucket_server_side_encryption_configuration" "quay_storage" {
#   bucket = aws_s3_bucket.quay_storage.id
#   rule {
#     apply_server_side_encryption_by_default {
#       sse_algorithm = "AES256"
#     }
#   }
# }

# T05: Bucket allows public access
resource "aws_s3_bucket_public_access_block" "quay_storage" {
  bucket = aws_s3_bucket.quay_storage.id

  # T05: Public access not blocked
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# T05: Bucket policy allows anonymous read access
resource "aws_s3_bucket_policy" "quay_storage" {
  bucket = aws_s3_bucket.quay_storage.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"  # T05: Anonymous access
        Action    = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          "${aws_s3_bucket.quay_storage.arn}",
          "${aws_s3_bucket.quay_storage.arn}/*"
        ]
      }
    ]
  })
}

# T07: No access logging
# Access logging disabled for free tier
# resource "aws_s3_bucket_logging" "quay_storage" {
#   bucket = aws_s3_bucket.quay_storage.id
#   target_bucket = aws_s3_bucket.logs.id
#   target_prefix = "s3-access-logs/"
# }

# T07: No versioning
# Versioning disabled for free tier (saves storage costs)
# resource "aws_s3_bucket_versioning" "quay_storage" {
#   bucket = aws_s3_bucket.quay_storage.id
#   versioning_configuration {
#     status = "Enabled"
#   }
# }

# T03: CORS allows all origins
resource "aws_s3_bucket_cors_configuration" "quay_storage" {
  bucket = aws_s3_bucket.quay_storage.id

  cors_rule {
    allowed_headers = ["*"]
    allowed_methods = ["GET", "PUT", "POST", "DELETE", "HEAD"]
    allowed_origins = ["*"]  # T03: Should be restricted
    expose_headers  = ["ETag"]
    max_age_seconds = 3000
  }
}

# Outputs
output "s3_bucket_name" {
  value       = aws_s3_bucket.quay_storage.id
  description = "S3 bucket for Quay image storage"
}

output "s3_bucket_arn" {
  value       = aws_s3_bucket.quay_storage.arn
  description = "ARN of S3 bucket"
}
