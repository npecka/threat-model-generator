# Outputs for AWS Minimal Single-AZ Quay Deployment

output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.quay_vpc.id
}

output "public_subnet_id" {
  description = "ID of public subnet"
  value       = aws_subnet.public.id
}

output "ssh_access_commands" {
  description = "SSH commands to access each instance"
  value = {
    quay_app_1    = "ssh -i ~/.ssh/quay-minimal-key ec2-user@${aws_instance.quay_app_1.public_ip}"
    quay_app_2    = "ssh -i ~/.ssh/quay-minimal-key ec2-user@${aws_instance.quay_app_2.public_ip}"
    database      = "ssh -i ~/.ssh/quay-minimal-key ec2-user@${aws_instance.database.public_ip}"
    storage       = "ssh -i ~/.ssh/quay-minimal-key ec2-user@${aws_instance.storage.public_ip}"
    llm_service   = "ssh -i ~/.ssh/quay-minimal-key ec2-user@${aws_instance.llm_service.public_ip}"
    loadbalancer  = "ssh -i ~/.ssh/quay-minimal-key ec2-user@${aws_instance.loadbalancer.public_ip}"
    jenkins_cicd  = "ssh -i ~/.ssh/quay-minimal-key ec2-user@${aws_instance.jenkins_cicd.public_ip}"
  }
}

output "service_urls" {
  description = "URLs to access services"
  value = {
    quay_registry = "http://${aws_instance.loadbalancer.public_ip}"
    llm_service   = "http://${aws_instance.loadbalancer.public_ip}/llm"
    minio_console = "http://${aws_instance.storage.public_ip}:9001"
    jenkins_cicd  = "http://${aws_instance.jenkins_cicd.public_ip}:8080"
  }
}

output "free_tier_summary" {
  description = "Free tier usage summary"
  value = {
    ec2_instances           = "7 × t3.micro"
    monthly_hours_limit     = "750 hours (all instances combined)"
    estimated_runtime_days  = "~4.5 days before exceeding free tier"
    ebs_storage            = "7 × 30 GB = 210 GB (within 30 GB free tier if deleted after testing)"
    data_transfer          = "First 100 GB/month free"
    s3_storage             = "First 5 GB free"
  }
}

output "threat_coverage" {
  description = "Threats demonstrated in this deployment"
  value = {
    total_threats    = "17"
    threat_list      = "T01-T17"
    excluded_threats = "T18-T21 (HA-specific, requires multi-AZ)"
    components       = "20+"
    paradigm         = "AWS Cloud (containerized, single-AZ)"
  }
}
