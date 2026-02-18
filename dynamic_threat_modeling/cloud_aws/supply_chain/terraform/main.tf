# AWS Supply Chain Infrastructure - Intentionally Vulnerable for Threat Detection

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "supply-chain-threat-model"
      Environment = "experiment"
      ManagedBy   = "terraform"
    }
  }
}

# Data source for latest Ubuntu AMI
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# VPC for supply chain
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "supply-chain-vpc"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "supply-chain-igw"
  }
}

# Public Subnets (one per zone)
resource "aws_subnet" "dev" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = {
    Name = "supply-chain-dev-subnet"
    Zone = "dev-zone"
  }
}

resource "aws_subnet" "cicd" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = {
    Name = "supply-chain-cicd-subnet"
    Zone = "cicd-zone"
  }
}

resource "aws_subnet" "prod" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.3.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = {
    Name = "supply-chain-prod-subnet"
    Zone = "prod-zone"
  }
}

# Route Table
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "supply-chain-public-rt"
  }
}

# Route Table Associations
resource "aws_route_table_association" "dev" {
  subnet_id      = aws_subnet.dev.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "cicd" {
  subnet_id      = aws_subnet.cicd.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "prod" {
  subnet_id      = aws_subnet.prod.id
  route_table_id = aws_route_table.public.id
}

# Security Groups - Intentionally permissive for threats

# T1, T4: Dev Zone - Wide open for Gitea + Training Data
resource "aws_security_group" "dev" {
  name        = "supply-chain-dev-sg"
  description = "Development zone security group - INTENTIONALLY VULNERABLE"
  vpc_id      = aws_vpc.main.id

  # T1: Unauthenticated external access to Gitea
  ingress {
    description = "Gitea HTTP from anywhere (T1)"
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # T1: Training Data HTTP server exposed (ML threat)
  ingress {
    description = "Training Data HTTP from anywhere (T1)"
    from_port   = 8001
    to_port     = 8001
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # T4: Allow all from other zones
  ingress {
    description = "All traffic from VPC (T4)"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "supply-chain-dev-sg"
    Zone = "dev-zone"
  }
}

# T1, T4: CI/CD Zone - Exposed Jenkins, Registry, and MLflow
resource "aws_security_group" "cicd" {
  name        = "supply-chain-cicd-sg"
  description = "CI/CD zone security group - INTENTIONALLY VULNERABLE"
  vpc_id      = aws_vpc.main.id

  # T1: Jenkins unauthenticated
  ingress {
    description = "Jenkins from anywhere (T1)"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # T5: Anonymous registry access
  ingress {
    description = "Registry from anywhere (T5)"
    from_port   = 5000
    to_port     = 5000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # T11: MLflow exposed without authentication (ML threat)
  ingress {
    description = "MLflow from anywhere (T11)"
    from_port   = 5001
    to_port     = 5001
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # T4: Allow all from VPC
  ingress {
    description = "All traffic from VPC (T4)"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "supply-chain-cicd-sg"
    Zone = "cicd-zone"
  }
}

# T1, T4: Prod Zone - Exposed application, database, and ML inference
resource "aws_security_group" "prod" {
  name        = "supply-chain-prod-sg"
  description = "Production zone security group - INTENTIONALLY VULNERABLE"
  vpc_id      = aws_vpc.main.id

  # T1: Application exposed
  ingress {
    description = "HTTP from anywhere (T1)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # T1, T13: ML Inference API exposed without authentication (ML threat)
  ingress {
    description = "ML Inference from anywhere (T1, T13)"
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # T1: Database exposed
  ingress {
    description = "PostgreSQL from anywhere (T1)"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # T4: Allow all from VPC
  ingress {
    description = "All traffic from VPC (T4)"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "supply-chain-prod-sg"
    Zone = "prod-zone"
  }
}

# SSH Key Pair for EC2 instances
resource "aws_key_pair" "supply_chain" {
  key_name   = "supply-chain-key"
  public_key = var.ssh_public_key

  tags = {
    Name = "supply-chain-ssh-key"
  }
}

# IAM Role for Jenkins (T2: Excessive Permissions, T6: Cross-zone access)
resource "aws_iam_role" "jenkins" {
  name = "supply-chain-jenkins-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })

  tags = {
    Name = "supply-chain-jenkins-role"
    Threat = "T2-T6"
  }
}

# T2, T6: Excessive permissions policy
resource "aws_iam_role_policy" "jenkins_excessive" {
  name = "jenkins-excessive-permissions"
  role = aws_iam_role.jenkins.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:*",
          "s3:*",
          "rds:*",
          "iam:*"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "jenkins" {
  name = "supply-chain-jenkins-profile"
  role = aws_iam_role.jenkins.name
}

# IAM Roles for other instances (minimal)
resource "aws_iam_role" "minimal" {
  name = "supply-chain-minimal-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_instance_profile" "minimal" {
  name = "supply-chain-minimal-profile"
  role = aws_iam_role.minimal.name
}

# S3 Bucket for ML Artifacts (T11, T16: Public access, no versioning)
resource "aws_s3_bucket" "ml_artifacts" {
  bucket = "supply-chain-ml-artifacts-${random_string.bucket_suffix.result}"

  tags = {
    Name   = "supply-chain-ml-artifacts"
    Threat = "T11-T16"
  }
}

resource "random_string" "bucket_suffix" {
  length  = 8
  special = false
  upper   = false
}

# T11: Public read access to ML artifacts
resource "aws_s3_bucket_public_access_block" "ml_artifacts" {
  bucket = aws_s3_bucket.ml_artifacts.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "ml_artifacts_public" {
  bucket = aws_s3_bucket.ml_artifacts.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.ml_artifacts.arn}/*"
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.ml_artifacts]
}

# T16: No versioning for ML artifacts (missing provenance)
resource "aws_s3_bucket_versioning" "ml_artifacts" {
  bucket = aws_s3_bucket.ml_artifacts.id

  versioning_configuration {
    status = "Disabled"  # T16: No versioning
  }
}

# T07: No S3 logging
# (Intentionally omitting aws_s3_bucket_logging resource)
