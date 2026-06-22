# Variables for AWS HA Quay Deployment

variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "threat-modeling"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "instance_type_app" {
  description = "EC2 instance type for Quay application servers"
  type        = string
  default     = "t3.medium"
}

variable "instance_type_llm" {
  description = "EC2 instance type for LLM service"
  type        = string
  default     = "t3.large"
}

variable "db_username" {
  description = "Database master username"
  type        = string
  default     = "quayuser"
}

# T08: Database password as variable (stored in tfvars or environment)
variable "db_password" {
  description = "Database master password"
  type        = string
  sensitive   = true
  default     = "insecure_password_123"
}

variable "db_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.t3.medium"
}

variable "redis_node_type" {
  description = "ElastiCache node type"
  type        = string
  default     = "cache.t3.medium"
}

variable "redis_password" {
  description = "Redis authentication password"
  type        = string
  sensitive   = true
  default     = ""  # T01: Empty password - no authentication
}

variable "enable_ha" {
  description = "Enable high availability features"
  type        = bool
  default     = true
}

variable "min_app_instances" {
  description = "Minimum number of Quay app instances"
  type        = number
  default     = 3
}

variable "max_app_instances" {
  description = "Maximum number of Quay app instances"
  type        = number
  default     = 6
}

variable "desired_app_instances" {
  description = "Desired number of Quay app instances"
  type        = number
  default     = 3
}

# T08: Secrets in variables instead of Secrets Manager
variable "quay_secret_key" {
  description = "Quay application secret key"
  type        = string
  sensitive   = true
  default     = "quay_secret_key_not_random"
}

variable "quay_db_secret_key" {
  description = "Quay database secret key"
  type        = string
  sensitive   = true
  default     = "insecure_db_secret_key"
}

variable "s3_access_key" {
  description = "S3 access key for object storage"
  type        = string
  sensitive   = true
  default     = "minioadmin"
}

variable "s3_secret_key" {
  description = "S3 secret key for object storage"
  type        = string
  sensitive   = true
  default     = "minioadmin123"
}

variable "enable_monitoring" {
  description = "Enable CloudWatch monitoring"
  type        = bool
  default     = false  # T07: Monitoring disabled by default
}

variable "enable_logging" {
  description = "Enable CloudWatch logging"
  type        = bool
  default     = false  # T07: Logging disabled by default
}

variable "enable_encryption" {
  description = "Enable encryption at rest and in transit"
  type        = bool
  default     = false  # T03: Encryption disabled by default
}

# Tag variables
variable "project_name" {
  description = "Project name for resource tagging"
  type        = string
  default     = "threat-model-generator"
}

variable "case_study" {
  description = "Case study identifier"
  type        = string
  default     = "quay-ha"
}

variable "owner" {
  description = "Resource owner"
  type        = string
  default     = "nicholas.pecka"
}
