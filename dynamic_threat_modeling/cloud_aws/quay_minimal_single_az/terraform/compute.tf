# EC2 Instances for Quay Minimal Deployment
# 6 × t3.micro instances (2 vCPU, 1 GB RAM each)
# Total: 12 vCPUs, 6 GB RAM
# THREAT INJECTION: T01, T02, T06, T08, T10

# T02: Overly permissive IAM role for EC2 instances
resource "aws_iam_role" "quay_instance_role" {
  name = "quay-minimal-instance-role"

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
    Name = "quay-minimal-instance-role"
  }
}

# T02: Excessive S3 permissions
resource "aws_iam_role_policy" "quay_s3_policy" {
  name = "quay-s3-policy"
  role = aws_iam_role.quay_instance_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "s3:*"  # T02: Full S3 access instead of scoped to specific bucket
      ]
      Resource = "*"
    }]
  })
}

# T02: Can describe EC2 instances (for discovery)
resource "aws_iam_role_policy" "quay_ec2_policy" {
  name = "quay-ec2-policy"
  role = aws_iam_role.quay_instance_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "ec2:Describe*",
        "ec2:Get*"
      ]
      Resource = "*"
    }]
  })
}

resource "aws_iam_instance_profile" "quay_profile" {
  name = "quay-minimal-instance-profile"
  role = aws_iam_role.quay_instance_role.name
}

# Instance 1: Quay Application Primary
resource "aws_instance" "quay_app_1" {
  ami                    = data.aws_ami.amazon_linux_2.id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.quay_instances.id]
  iam_instance_profile   = aws_iam_instance_profile.quay_profile.name
  key_name               = aws_key_pair.quay_key.key_name

  # T08: User data contains secrets
  user_data = base64encode(templatefile("${path.module}/user-data/quay-app.sh", {
    instance_name = "quay-app-1"
    db_host       = aws_instance.database.private_ip
    db_password   = var.db_password
    redis_host    = aws_instance.database.private_ip
    minio_host    = aws_instance.storage.private_ip
    s3_bucket     = aws_s3_bucket.quay_storage.id
    aws_region    = var.aws_region
  }))

  # Free tier: 30 GB gp2 or gp3 included
  root_block_device {
    volume_size = 30
    volume_type = "gp3"
  }

  # T10: No detailed monitoring
  monitoring = false

  tags = {
    Name = "quay-app-1"
    Role = "application"
  }
}

# Instance 2: Quay Application Secondary
resource "aws_instance" "quay_app_2" {
  ami                    = data.aws_ami.amazon_linux_2.id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.quay_instances.id]
  iam_instance_profile   = aws_iam_instance_profile.quay_profile.name
  key_name               = aws_key_pair.quay_key.key_name

  user_data = base64encode(templatefile("${path.module}/user-data/quay-app.sh", {
    instance_name = "quay-app-2"
    db_host       = aws_instance.database.private_ip
    db_password   = var.db_password
    redis_host    = aws_instance.database.private_ip
    minio_host    = aws_instance.storage.private_ip
    s3_bucket     = aws_s3_bucket.quay_storage.id
    aws_region    = var.aws_region
  }))

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
  }

  monitoring = false

  tags = {
    Name = "quay-app-2"
    Role = "application"
  }
}

# Instance 3: Database & Cache (PostgreSQL + Redis in Docker)
resource "aws_instance" "database" {
  ami                    = data.aws_ami.amazon_linux_2.id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.quay_instances.id]
  iam_instance_profile   = aws_iam_instance_profile.quay_profile.name
  key_name               = aws_key_pair.quay_key.key_name

  user_data = base64encode(templatefile("${path.module}/user-data/database.sh", {
    db_password = var.db_password
  }))

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
  }

  monitoring = false

  tags = {
    Name = "database-cache"
    Role = "database"
  }
}

# Instance 4: Storage & Scanning (Minio + Clair in Docker)
resource "aws_instance" "storage" {
  ami                    = data.aws_ami.amazon_linux_2.id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.quay_instances.id]
  iam_instance_profile   = aws_iam_instance_profile.quay_profile.name
  key_name               = aws_key_pair.quay_key.key_name

  user_data = base64encode(templatefile("${path.module}/user-data/storage-scanner.sh", {
    db_host     = aws_instance.database.private_ip
    db_password = var.db_password
  }))

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
  }

  monitoring = false

  tags = {
    Name = "storage-scanner"
    Role = "storage"
  }
}

# Instance 5: LLM Service
resource "aws_instance" "llm_service" {
  ami                    = data.aws_ami.amazon_linux_2.id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.quay_instances.id]
  iam_instance_profile   = aws_iam_instance_profile.quay_profile.name
  key_name               = aws_key_pair.quay_key.key_name

  user_data = base64encode(file("${path.module}/user-data/llm-service.sh"))

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
  }

  monitoring = false

  tags = {
    Name = "llm-service"
    Role = "ml-inference"
  }
}

# Instance 6: Load Balancer & Monitoring (NGINX + monitoring tools)
resource "aws_instance" "loadbalancer" {
  ami                    = data.aws_ami.amazon_linux_2.id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.quay_instances.id]
  iam_instance_profile   = aws_iam_instance_profile.quay_profile.name
  key_name               = aws_key_pair.quay_key.key_name

  user_data = base64encode(templatefile("${path.module}/user-data/loadbalancer.sh", {
    quay_app_1_ip = aws_instance.quay_app_1.private_ip
    quay_app_2_ip = aws_instance.quay_app_2.private_ip
    llm_service_ip = aws_instance.llm_service.private_ip
  }))

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
  }

  monitoring = false

  tags = {
    Name = "loadbalancer"
    Role = "loadbalancer"
  }
}

# Outputs
output "instance_summary" {
  description = "Summary of all EC2 instances"
  value = {
    quay_app_1 = {
      public_ip  = aws_instance.quay_app_1.public_ip
      private_ip = aws_instance.quay_app_1.private_ip
    }
    quay_app_2 = {
      public_ip  = aws_instance.quay_app_2.public_ip
      private_ip = aws_instance.quay_app_2.private_ip
    }
    database = {
      public_ip  = aws_instance.database.public_ip
      private_ip = aws_instance.database.private_ip
    }
    storage = {
      public_ip  = aws_instance.storage.public_ip
      private_ip = aws_instance.storage.private_ip
    }
    llm_service = {
      public_ip  = aws_instance.llm_service.public_ip
      private_ip = aws_instance.llm_service.private_ip
    }
    loadbalancer = {
      public_ip  = aws_instance.loadbalancer.public_ip
      private_ip = aws_instance.loadbalancer.private_ip
    }
  }
}

output "quay_url" {
  description = "URL to access Quay through load balancer"
  value       = "http://${aws_instance.loadbalancer.public_ip}"
}

output "deployment_stats" {
  description = "Deployment statistics"
  value = {
    total_instances = 6
    total_vcpus     = 12
    total_memory_gb = 6
    instance_type   = "t3.micro"
    components      = "20+"
    threats         = "T01-T17"
  }
}
