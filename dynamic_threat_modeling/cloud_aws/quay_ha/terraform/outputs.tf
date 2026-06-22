# Outputs for AWS HA Quay Deployment

output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.quay_vpc.id
}

output "public_subnet_ids" {
  description = "IDs of public subnets"
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "IDs of private subnets"
  value       = aws_subnet.private[*].id
}

# Already defined in other files, consolidating here
# output "alb_dns_name" - in loadbalancer.tf
# output "postgres_endpoint" - in database.tf
# output "redis_primary_endpoint" - in database.tf
# output "s3_bucket_name" - in storage.tf

output "quay_url" {
  description = "URL to access Quay registry"
  value       = "http://${aws_lb.quay.dns_name}"
}

output "llm_service_url" {
  description = "URL to access LLM service"
  value       = "http://${aws_lb.quay.dns_name}/llm"
}

output "clair_url" {
  description = "URL to access Clair scanner"
  value       = "http://${aws_lb.quay.dns_name}/clair"
}

output "deployment_summary" {
  description = "Summary of deployed resources"
  value = {
    region             = var.aws_region
    environment        = var.environment
    vpc_cidr           = var.vpc_cidr
    availability_zones = slice(data.aws_availability_zones.available.names, 0, 3)

    compute = {
      quay_app_instances     = "${var.min_app_instances}-${var.max_app_instances}"
      llm_service_instances  = "2-4"
      clair_instances        = "2-4"
    }

    database = {
      postgres_instances = 3
      redis_nodes        = 3
    }

    threats_injected = "T01-T21 (21 total threats)"
  }
}
