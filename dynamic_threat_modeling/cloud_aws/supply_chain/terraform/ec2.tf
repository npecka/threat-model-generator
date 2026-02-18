# EC2 Instances for Supply Chain

# Development Instance (Gitea)
resource "aws_instance" "dev" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t3.micro"  # Free tier eligible
  subnet_id              = aws_subnet.dev.id
  vpc_security_group_ids = [aws_security_group.dev.id]
  iam_instance_profile   = aws_iam_instance_profile.minimal.name
  key_name               = aws_key_pair.supply_chain.key_name

  user_data = templatefile("${path.module}/user-data/dev.sh", {
    gitea_version = "1.21.5"
  })

  root_block_device {
    volume_size = 8
    volume_type = "gp3"
  }

  tags = {
    Name = "supply-chain-dev"
    Zone = "dev-zone"
    Role = "gitea"
  }
}

# CI/CD Instance (Jenkins + Registry)
resource "aws_instance" "cicd" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t3.micro"  # Free tier eligible
  subnet_id              = aws_subnet.cicd.id
  vpc_security_group_ids = [aws_security_group.cicd.id]
  iam_instance_profile   = aws_iam_instance_profile.jenkins.name # T2, T6: Excessive permissions
  key_name               = aws_key_pair.supply_chain.key_name

  user_data = templatefile("${path.module}/user-data/cicd.sh", {
    jenkins_version  = "2.440"
    registry_version = "2.8"
  })

  root_block_device {
    volume_size = 8
    volume_type = "gp3"
  }

  tags = {
    Name = "supply-chain-cicd"
    Zone = "cicd-zone"
    Role = "jenkins-registry"
  }
}

# Production Instance (Application + PostgreSQL)
resource "aws_instance" "prod" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t3.micro"  # Free tier eligible
  subnet_id              = aws_subnet.prod.id
  vpc_security_group_ids = [aws_security_group.prod.id]
  iam_instance_profile   = aws_iam_instance_profile.minimal.name
  key_name               = aws_key_pair.supply_chain.key_name

  user_data = templatefile("${path.module}/user-data/prod.sh", {
    postgres_version = "15"
    cicd_ip          = aws_instance.cicd.private_ip
  })

  root_block_device {
    volume_size = 8
    volume_type = "gp3"
  }

  tags = {
    Name = "supply-chain-prod"
    Zone = "prod-zone"
    Role = "application-database"
  }
}
