# Terraform Outputs

output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.main.id
}

output "dev_instance" {
  description = "Development instance details"
  value = {
    id                = aws_instance.dev.id
    public_ip         = aws_instance.dev.public_ip
    private_ip        = aws_instance.dev.private_ip
    gitea_url         = "http://${aws_instance.dev.public_ip}:3000"
    training_data_url = "http://${aws_instance.dev.public_ip}:8001"
  }
}

output "cicd_instance" {
  description = "CI/CD instance details"
  value = {
    id          = aws_instance.cicd.id
    public_ip   = aws_instance.cicd.public_ip
    private_ip  = aws_instance.cicd.private_ip
    jenkins_url = "http://${aws_instance.cicd.public_ip}:8080"
    registry_url = "http://${aws_instance.cicd.public_ip}:5000"
    mlflow_url  = "http://${aws_instance.cicd.public_ip}:5001"
  }
}

output "prod_instance" {
  description = "Production instance details"
  value = {
    id               = aws_instance.prod.id
    public_ip        = aws_instance.prod.public_ip
    private_ip       = aws_instance.prod.private_ip
    app_url          = "http://${aws_instance.prod.public_ip}"
    ml_inference_url = "http://${aws_instance.prod.public_ip}:8000"
  }
}

output "s3_bucket" {
  description = "S3 bucket for ML artifacts"
  value = {
    name = aws_s3_bucket.ml_artifacts.id
    arn  = aws_s3_bucket.ml_artifacts.arn
    url  = "https://${aws_s3_bucket.ml_artifacts.bucket}.s3.amazonaws.com"
  }
}

output "ssh_commands" {
  description = "SSH commands to connect to instances"
  value = {
    dev  = "ssh -i ~/.ssh/id_rsa ubuntu@${aws_instance.dev.public_ip}"
    cicd = "ssh -i ~/.ssh/id_rsa ubuntu@${aws_instance.cicd.public_ip}"
    prod = "ssh -i ~/.ssh/id_rsa ubuntu@${aws_instance.prod.public_ip}"
  }
}

output "summary" {
  description = "Deployment summary"
  value = <<-EOT

  ========================================
  ML-Enhanced Supply Chain Deployment Complete
  ========================================

  Development Zone (${aws_instance.dev.public_ip}):
    Gitea:         http://${aws_instance.dev.public_ip}:3000
    Training Data: http://${aws_instance.dev.public_ip}:8001

  CI/CD Zone (${aws_instance.cicd.public_ip}):
    Jenkins:  http://${aws_instance.cicd.public_ip}:8080
    Registry: http://${aws_instance.cicd.public_ip}:5000
    MLflow:   http://${aws_instance.cicd.public_ip}:5001

  Production Zone (${aws_instance.prod.public_ip}):
    Application:   http://${aws_instance.prod.public_ip}
    ML Inference:  http://${aws_instance.prod.public_ip}:8000
    PostgreSQL:    ${aws_instance.prod.public_ip}:5432

  ML Artifacts:
    S3 Bucket: ${aws_s3_bucket.ml_artifacts.id}

  SSH Access:
    dev:  ssh ubuntu@${aws_instance.dev.public_ip}
    cicd: ssh ubuntu@${aws_instance.cicd.public_ip}
    prod: ssh ubuntu@${aws_instance.prod.public_ip}

  Threat Summary:
    Traditional Threats:  T01-T10 (10 threats)
    ML-Specific Threats:  T11-T17 (7 threats)
    Total: 17 architectural threats

  Next Steps:
    1. Wait 5-7 minutes for all services to start
    2. Test ML endpoints:
       - curl http://${aws_instance.prod.public_ip}:8000/health
       - curl http://${aws_instance.cicd.public_ip}:5001/health
    3. Run threat detection analysis
    4. Clean up: terraform destroy

  ========================================
  EOT
}
