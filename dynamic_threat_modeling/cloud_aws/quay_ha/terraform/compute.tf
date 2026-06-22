# EC2 Instances for Quay HA Deployment
# THREAT INJECTION: T01, T02, T06, T08, T10, T18-T21

# AMI Data Source
data "aws_ami" "amazon_linux_2" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

# T02: Overly permissive IAM role for EC2 instances
resource "aws_iam_role" "quay_instance_role" {
  name = "quay-instance-role"

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

# T02: Can access secrets across the account
resource "aws_iam_role_policy" "quay_secrets_policy" {
  name = "quay-secrets-policy"
  role = aws_iam_role.quay_instance_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret",
        "secretsmanager:ListSecrets"  # T02: Can list all secrets
      ]
      Resource = "*"
    }]
  })
}

resource "aws_iam_instance_profile" "quay_profile" {
  name = "quay-instance-profile"
  role = aws_iam_role.quay_instance_role.name
}

# Launch Template for Quay Application Servers
resource "aws_launch_template" "quay_app" {
  name_prefix   = "quay-app-"
  image_id      = data.aws_ami.amazon_linux_2.id
  instance_type = var.instance_type_app

  iam_instance_profile {
    name = aws_iam_instance_profile.quay_profile.name
  }

  network_interfaces {
    associate_public_ip_address = true  # T01: Public IPs on app servers
    security_groups             = [aws_security_group.quay_app.id]
  }

  # T08: User data contains secrets
  user_data = base64encode(templatefile("${path.module}/user-data/quay-app.sh", {
    db_host     = aws_rds_cluster.postgres.endpoint
    db_password = var.db_password  # T08: Password in user data
    redis_host  = aws_elasticache_cluster.redis.cache_nodes[0].address
    s3_bucket   = aws_s3_bucket.quay_storage.id
    aws_region  = var.aws_region
  }))

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "quay-app"
      Role = "application"
    }
  }

  # T10: No detailed monitoring
  monitoring {
    enabled = false
  }
}

# Auto Scaling Group for Quay Application (HA)
resource "aws_autoscaling_group" "quay_app" {
  name                = "quay-app-asg"
  vpc_zone_identifier = aws_subnet.private[*].id
  target_group_arns   = [aws_lb_target_group.quay_app.arn]
  health_check_type   = "ELB"
  health_check_grace_period = 300
  min_size            = 3
  max_size            = 6
  desired_capacity    = 3

  launch_template {
    id      = aws_launch_template.quay_app.id
    version = "$Latest"
  }

  # T18: No ASG health check could lead to split-brain
  # T19: No circuit breaker or gradual rollout
  # T20: No consistency checks between instances

  tag {
    key                 = "Name"
    value               = "quay-app"
    propagate_at_launch = true
  }
}

# Launch Template for LLM Service (HA)
resource "aws_launch_template" "llm_service" {
  name_prefix   = "llm-service-"
  image_id      = data.aws_ami.amazon_linux_2.id
  instance_type = "t3.large"  # Larger for ML workload

  iam_instance_profile {
    name = aws_iam_instance_profile.quay_profile.name
  }

  network_interfaces {
    associate_public_ip_address = false  # Private subnet
    security_groups             = [aws_security_group.quay_app.id]
  }

  user_data = base64encode(file("${path.module}/user-data/llm-service.sh"))

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "llm-service"
      Role = "ml-inference"
    }
  }
}

# Auto Scaling Group for LLM Service
resource "aws_autoscaling_group" "llm_service" {
  name                = "llm-service-asg"
  vpc_zone_identifier = aws_subnet.private[*].id
  target_group_arns   = [aws_lb_target_group.llm_service.arn]
  health_check_type   = "ELB"
  health_check_grace_period = 600  # Longer for model loading
  min_size            = 2
  max_size            = 4
  desired_capacity    = 2

  launch_template {
    id      = aws_launch_template.llm_service.id
    version = "$Latest"
  }

  # T20: No model version consistency checks across replicas
  # T21: Slow health check may not detect failed replicas quickly

  tag {
    key                 = "Name"
    value               = "llm-service"
    propagate_at_launch = true
  }
}

# Clair Scanner Instances (HA)
resource "aws_launch_template" "clair" {
  name_prefix   = "clair-"
  image_id      = data.aws_ami.amazon_linux_2.id
  instance_type = var.instance_type_app

  iam_instance_profile {
    name = aws_iam_instance_profile.quay_profile.name
  }

  network_interfaces {
    associate_public_ip_address = false
    security_groups             = [aws_security_group.quay_app.id]
  }

  user_data = base64encode(templatefile("${path.module}/user-data/clair.sh", {
    db_host     = aws_rds_cluster.postgres.endpoint
    db_password = var.db_password
  }))

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "clair"
      Role = "scanner"
    }
  }
}

resource "aws_autoscaling_group" "clair" {
  name                = "clair-asg"
  vpc_zone_identifier = aws_subnet.private[*].id
  target_group_arns   = [aws_lb_target_group.clair.arn]
  health_check_type   = "ELB"
  health_check_grace_period = 300
  min_size            = 2
  max_size            = 4
  desired_capacity    = 2

  launch_template {
    id      = aws_launch_template.clair.id
    version = "$Latest"
  }

  tag {
    key                 = "Name"
    value               = "clair"
    propagate_at_launch = true
  }
}
