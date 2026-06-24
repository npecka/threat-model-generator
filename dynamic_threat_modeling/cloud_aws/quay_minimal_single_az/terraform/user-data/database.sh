#!/bin/bash
# User data script for Database & Cache Instance
# Runs PostgreSQL and Redis in Docker containers
# THREAT INJECTION: T01, T03, T07, T08, T10

set -e

echo "Starting database and cache setup..."

# Update system
yum update -y

# Install Docker
amazon-linux-extras install docker -y
systemctl start docker
systemctl enable docker

# T08: Password in environment variable
export POSTGRES_PASSWORD="${db_password}"

echo "Starting PostgreSQL and Redis containers..."

# Run PostgreSQL in Docker
# T03: No SSL/TLS encryption
# T08: Weak password
# T10: No resource limits
docker run -d \
  --name postgres \
  --restart always \
  -p 5432:5432 \
  -e POSTGRES_DB=quay \
  -e POSTGRES_USER=quayuser \
  -e POSTGRES_PASSWORD=${db_password} \
  -v postgres-data:/var/lib/postgresql/data \
  postgres:14

# Run Redis in Docker
# T01: No authentication (no requirepass)
# T03: No TLS
# T10: No resource limits
docker run -d \
  --name redis \
  --restart always \
  -p 6379:6379 \
  redis:7-alpine \
  redis-server --appendonly yes

# Wait for services to start
sleep 10

# Verify containers are running
docker ps

# T07: No logging to CloudWatch
echo "Database and cache services started" >> /var/log/database-startup.log
