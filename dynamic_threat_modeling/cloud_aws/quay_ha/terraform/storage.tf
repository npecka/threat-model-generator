# S3 and Storage Configuration
# THREAT INJECTION: T03, T05, T07, T08

# S3 Bucket for Quay Image Storage
resource "aws_s3_bucket" "quay_storage" {
  bucket = "quay-image-storage-${var.environment}-${random_string.bucket_suffix.result}"

  # T07: No object logging
  # T07: No versioning for audit trail
  # versioning {
  #   enabled = true
  # }

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
resource "aws_s3_bucket_server_side_encryption_configuration" "quay_storage" {
  bucket = aws_s3_bucket.quay_storage.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"  # Should use KMS for better control
    }
    # T03: Bucket keys not enabled for cost optimization
    bucket_key_enabled = false
  }
}

# T05: Bucket allows public access
resource "aws_s3_bucket_public_access_block" "quay_storage" {
  bucket = aws_s3_bucket.quay_storage.id

  # T05: Public access not fully blocked
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
# resource "aws_s3_bucket_logging" "quay_storage" {
#   bucket = aws_s3_bucket.quay_storage.id
#
#   target_bucket = aws_s3_bucket.logs.id
#   target_prefix = "s3-access-logs/"
# }

# T07: No versioning enabled (commented out)
# resource "aws_s3_bucket_versioning" "quay_storage" {
#   bucket = aws_s3_bucket.quay_storage.id
#
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
    allowed_origins = ["*"]  # T03: Should be restricted to Quay domain
    expose_headers  = ["ETag"]
    max_age_seconds = 3000
  }
}

# T10: No lifecycle policy to manage costs
# resource "aws_s3_bucket_lifecycle_configuration" "quay_storage" {
#   bucket = aws_s3_bucket.quay_storage.id
#
#   rule {
#     id     = "archive-old-images"
#     status = "Enabled"
#
#     transition {
#       days          = 90
#       storage_class = "GLACIER"
#     }
#
#     expiration {
#       days = 365
#     }
#   }
# }

# S3 Bucket for LLM Models
resource "aws_s3_bucket" "llm_models" {
  bucket = "quay-llm-models-${var.environment}-${random_string.bucket_suffix.result}"

  tags = {
    Name        = "Quay LLM Models"
    Environment = var.environment
  }
}

# T11: LLM model bucket publicly accessible
resource "aws_s3_bucket_public_access_block" "llm_models" {
  bucket = aws_s3_bucket.llm_models.id

  # T11: Models are publicly downloadable
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "llm_models" {
  bucket = aws_s3_bucket.llm_models.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadModels"
        Effect    = "Allow"
        Principal = "*"  # T11: Anonymous model access
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.llm_models.arn}/*"
      }
    ]
  })
}

# T14: Models transferred over HTTP without encryption
# T16: No model provenance or versioning tracking

# EFS for shared configuration (optional HA component)
resource "aws_efs_file_system" "quay_config" {
  creation_token = "quay-config-efs"

  # T03: No encryption at rest
  encrypted = false

  # T07: No lifecycle management
  # lifecycle_policy {
  #   transition_to_ia = "AFTER_30_DAYS"
  # }

  tags = {
    Name = "quay-config-efs"
  }
}

resource "aws_efs_mount_target" "quay_config" {
  count           = 3
  file_system_id  = aws_efs_file_system.quay_config.id
  subnet_id       = aws_subnet.private[count.index].id
  security_groups = [aws_security_group.quay_app.id]
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

output "llm_models_bucket" {
  value       = aws_s3_bucket.llm_models.id
  description = "S3 bucket for LLM models"
}

output "efs_id" {
  value       = aws_efs_file_system.quay_config.id
  description = "EFS file system ID for shared config"
}
