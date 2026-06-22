# RDS PostgreSQL Aurora Cluster (HA)
# THREAT INJECTION: T03, T07, T08, T18, T19, T20

# DB Subnet Group
resource "aws_db_subnet_group" "quay_db" {
  name       = "quay-db-subnet-group"
  subnet_ids = aws_subnet.private[*].id

  tags = {
    Name = "Quay DB subnet group"
  }
}

# RDS Aurora PostgreSQL Cluster
resource "aws_rds_cluster" "postgres" {
  cluster_identifier      = "quay-postgres-cluster"
  engine                  = "aurora-postgresql"
  engine_version          = "14.6"
  database_name           = "quay"
  master_username         = var.db_username
  master_password         = var.db_password  # T08: Password in Terraform state
  db_subnet_group_name    = aws_db_subnet_group.quay_db.name
  vpc_security_group_ids  = [aws_security_group.database.id]

  # T03: Storage not encrypted
  storage_encrypted = false

  # T03: No SSL/TLS enforcement
  # In real deployment would set: require_ssl = true

  # HA Configuration
  availability_zones = slice(data.aws_availability_zones.available.names, 0, 3)

  # T07: Backup retention too short
  backup_retention_period = 1  # Should be 7-35 days

  # T07: No audit logging
  enabled_cloudwatch_logs_exports = []
  # Should enable: ["postgresql"]

  # T20: Auto failover enabled but no consistency checks
  # T18: No proper quorum configuration

  # T10: No performance insights
  # performance_insights_enabled = false

  skip_final_snapshot = true  # For demo purposes

  tags = {
    Name = "quay-postgres-cluster"
  }
}

# RDS Cluster Instances (3 for HA)
resource "aws_rds_cluster_instance" "postgres" {
  count              = 3
  identifier         = "quay-postgres-${count.index + 1}"
  cluster_identifier = aws_rds_cluster.postgres.id
  instance_class     = var.db_instance_class
  engine             = aws_rds_cluster.postgres.engine
  engine_version     = aws_rds_cluster.postgres.engine_version

  # T10: No enhanced monitoring
  monitoring_interval = 0

  # T07: No performance insights
  performance_insights_enabled = false

  # Spread across AZs
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "quay-postgres-instance-${count.index + 1}"
  }
}

# ElastiCache Redis Cluster (HA)
# T01: Redis without authentication
# T18-T21: HA-specific threats
resource "aws_elasticache_subnet_group" "redis" {
  name       = "quay-redis-subnet-group"
  subnet_ids = aws_subnet.private[*].id

  tags = {
    Name = "Quay Redis subnet group"
  }
}

resource "aws_elasticache_replication_group" "redis" {
  replication_group_id       = "quay-redis-cluster"
  description                = "Redis cluster for Quay HA"
  engine                     = "redis"
  engine_version             = "7.0"
  node_type                  = var.redis_node_type
  num_cache_clusters         = 3  # Primary + 2 replicas
  port                       = 6379
  parameter_group_name       = aws_elasticache_parameter_group.redis.name
  subnet_group_name          = aws_elasticache_subnet_group.redis.name
  security_group_ids         = [aws_security_group.cache.id]

  # T03: Transit encryption disabled
  transit_encryption_enabled = false

  # T03: At-rest encryption disabled
  at_rest_encryption_enabled = false

  # T01: No authentication
  auth_token_enabled = false

  # HA settings
  automatic_failover_enabled = true
  multi_az_enabled          = true

  # T07: No logging
  # log_delivery_configuration {
  #   destination      = aws_cloudwatch_log_group.redis.name
  #   destination_type = "cloudwatch-logs"
  #   log_format       = "json"
  #   log_type         = "slow-log"
  # }

  # T18: Failover can cause split-brain if app doesn't handle properly
  # T19: No circuit breaker for cascading failures
  # T20: Session data may be inconsistent during failover
  # T21: Default maintenance window may cause unexpected downtime

  tags = {
    Name = "quay-redis-cluster"
  }
}

# T01: Redis parameter group allows unauthenticated access
resource "aws_elasticache_parameter_group" "redis" {
  name   = "quay-redis-params"
  family = "redis7"

  # No requirepass parameter - T01
  # parameter {
  #   name  = "requirepass"
  #   value = var.redis_password
  # }

  tags = {
    Name = "quay-redis-params"
  }
}

# Output cluster information
output "postgres_endpoint" {
  value       = aws_rds_cluster.postgres.endpoint
  description = "PostgreSQL cluster endpoint"
}

output "postgres_reader_endpoint" {
  value       = aws_rds_cluster.postgres.reader_endpoint
  description = "PostgreSQL cluster reader endpoint"
}

output "redis_primary_endpoint" {
  value       = aws_elasticache_replication_group.redis.primary_endpoint_address
  description = "Redis primary endpoint"
}

output "redis_reader_endpoint" {
  value       = aws_elasticache_replication_group.redis.reader_endpoint_address
  description = "Redis reader endpoint"
}
