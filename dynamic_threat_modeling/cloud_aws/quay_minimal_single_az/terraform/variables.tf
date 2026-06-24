# Variables for AWS Minimal Single-AZ Quay Deployment

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

# T08: Database password as variable
variable "db_password" {
  description = "Database password"
  type        = string
  sensitive   = true
  default     = "insecure_password_123"
}

# SSH public key for EC2 access
variable "ssh_public_key" {
  description = "SSH public key for EC2 instance access (generate with: ssh-keygen -t rsa -b 4096)"
  type        = string
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
  default     = "quay-minimal"
}

variable "owner" {
  description = "Resource owner"
  type        = string
  default     = "nicholas.pecka"
}
