# AWS HA Quay Deployment - Full High Availability Configuration
# THREAT INJECTION: T01-T21 (all threats including HA-specific T18-T21)

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

# VPC and Networking
resource "aws_vpc" "quay_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "quay-ha-vpc"
    Environment = "threat-modeling"
    CaseStudy   = "quay-ha"
  }
}

# Public Subnets (3 AZs for HA)
resource "aws_subnet" "public" {
  count                   = 3
  vpc_id                  = aws_vpc.quay_vpc.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true  # T01: Public IPs assigned

  tags = {
    Name = "quay-public-${count.index + 1}"
    Type = "public"
  }
}

# Private Subnets (3 AZs for HA)
resource "aws_subnet" "private" {
  count             = 3
  vpc_id            = aws_vpc.quay_vpc.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 10)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "quay-private-${count.index + 1}"
    Type = "private"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.quay_vpc.id

  tags = {
    Name = "quay-igw"
  }
}

# T04: Missing Network ACLs for additional segmentation
# Network ACLs are not configured, relying only on security groups

# Route Tables
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
  count          = 3
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# NAT Gateways (for HA - one per AZ)
resource "aws_eip" "nat" {
  count  = 3
  domain = "vpc"

  tags = {
    Name = "quay-nat-eip-${count.index + 1}"
  }
}

resource "aws_nat_gateway" "nat" {
  count         = 3
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id

  tags = {
    Name = "quay-nat-${count.index + 1}"
  }
}

resource "aws_route_table" "private" {
  count  = 3
  vpc_id = aws_vpc.quay_vpc.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat[count.index].id
  }

  tags = {
    Name = "quay-private-rt-${count.index + 1}"
  }
}

resource "aws_route_table_association" "private" {
  count          = 3
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

# Data source for AZs
data "aws_availability_zones" "available" {
  state = "available"
}

# Security Groups
# T01: Overly permissive security groups
resource "aws_security_group" "quay_app" {
  name        = "quay-app-sg"
  description = "Security group for Quay application servers"
  vpc_id      = aws_vpc.quay_vpc.id

  # T01: Allow HTTP from anywhere
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP access"
  }

  # T01: Allow HTTPS from anywhere (but we're using HTTP anyway)
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS access"
  }

  # T01: SSH from anywhere
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH access"
  }

  # Allow all outbound
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "quay-app-sg"
  }
}

# T04: Database security group too permissive
resource "aws_security_group" "database" {
  name        = "quay-database-sg"
  description = "Security group for PostgreSQL database"
  vpc_id      = aws_vpc.quay_vpc.id

  # Should only allow from Quay app SG, but allows from entire VPC
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "PostgreSQL access from VPC"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "quay-database-sg"
  }
}

# T04: Redis security group too permissive
resource "aws_security_group" "cache" {
  name        = "quay-cache-sg"
  description = "Security group for Redis cache"
  vpc_id      = aws_vpc.quay_vpc.id

  ingress {
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "Redis access from VPC"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "quay-cache-sg"
  }
}

# Load Balancer Security Group
resource "aws_security_group" "alb" {
  name        = "quay-alb-sg"
  description = "Security group for Application Load Balancer"
  vpc_id      = aws_vpc.quay_vpc.id

  # T01: Allow HTTP from anywhere
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP from anywhere"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "quay-alb-sg"
  }
}

# T07: CloudWatch logging not configured
# T07: VPC Flow Logs not enabled
# resource "aws_flow_log" "quay_vpc" {
#   iam_role_arn    = aws_iam_role.flow_log.arn
#   log_destination = aws_cloudwatch_log_group.flow_log.arn
#   traffic_type    = "ALL"
#   vpc_id          = aws_vpc.quay_vpc.id
# }
