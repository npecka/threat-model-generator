# AWS Quay Minimal Single-AZ Deployment - FREE TIER OPTIMIZED
# THREAT INJECTION: T01-T17 (excludes HA-specific T18-T21)
#
# Configuration:
# - 6 × t3.micro EC2 instances (12 vCPUs, 6 GB RAM total)
# - Single availability zone (us-east-1a)
# - All services in Docker containers (consistent with bare-metal/K8s)
# - No managed services (ElastiCache, Aurora) - containerized equivalents only
# - Maximizes free tier: 750 hours/month ÷ 6 = 125 hours (~5 days testing)

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# VPC and Networking (Single-AZ)
resource "aws_vpc" "quay_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "quay-minimal-vpc"
    Environment = "threat-modeling"
    CaseStudy   = "quay-minimal"
    Deployment  = "single-az-free-tier"
  }
}

# Single Public Subnet (no need for multiple AZs)
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.quay_vpc.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, 0)
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true  # T01: Public IPs for direct access

  tags = {
    Name = "quay-public-subnet"
    Type = "public"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.quay_vpc.id

  tags = {
    Name = "quay-igw"
  }
}

# Route Table (direct internet access, no NAT gateway needed)
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.quay_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "quay-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# Security Groups
# T01: Overly permissive security groups
# T04: Missing network segmentation
resource "aws_security_group" "quay_instances" {
  name        = "quay-instances-sg"
  description = "Security group for all Quay instances"
  vpc_id      = aws_vpc.quay_vpc.id

  # T01: SSH from anywhere
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH access"
  }

  # T01: HTTP from anywhere
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP access"
  }

  # T01: Quay app port from anywhere
  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Quay app access"
  }

  # T01: LLM service from anywhere
  ingress {
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "LLM API access"
  }

  # T04: Allow all internal traffic (no segmentation)
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "All internal traffic"
  }

  # Allow all outbound
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "quay-instances-sg"
  }
}

# T07: VPC Flow Logs not enabled (commented out)
# resource "aws_flow_log" "quay_vpc" {
#   iam_role_arn    = aws_iam_role.flow_log.arn
#   log_destination = aws_cloudwatch_log_group.flow_log.arn
#   traffic_type    = "ALL"
#   vpc_id          = aws_vpc.quay_vpc.id
# }

# Data source for latest Amazon Linux 2 AMI
data "aws_ami" "amazon_linux_2" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# SSH Key Pair (you'll need to create this in AWS console or import existing)
resource "aws_key_pair" "quay_key" {
  key_name   = "quay-minimal-key"
  public_key = var.ssh_public_key

  tags = {
    Name = "quay-minimal-key"
  }
}
