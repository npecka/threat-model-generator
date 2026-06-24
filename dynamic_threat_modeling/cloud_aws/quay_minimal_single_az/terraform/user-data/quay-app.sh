#!/bin/bash
# User data script for Quay Application Servers
# Instance: ${instance_name}
# THREAT INJECTION: T06, T08

set -e

echo "Starting Quay application setup on ${instance_name}..."

# Update system
yum update -y

# Install Docker
amazon-linux-extras install docker -y
systemctl start docker
systemctl enable docker

# T08: Credentials in environment variables and logs
export DB_HOST="${db_host}"
export DB_PASSWORD="${db_password}"
export REDIS_HOST="${redis_host}"
export MINIO_HOST="${minio_host}"
export S3_BUCKET="${s3_bucket}"
export AWS_REGION="${aws_region}"

# T08: Credentials logged to system logs
echo "Starting Quay with DB_HOST=$DB_HOST on ${instance_name}" >> /var/log/quay-startup.log

# Pull Quay image
docker pull quay.io/projectquay/quay:latest

# Create config directory
mkdir -p /opt/quay/config

# T08: Write config with embedded credentials
cat > /opt/quay/config/config.yaml <<EOF
FEATURE_USER_CREATION: true
FEATURE_ANONYMOUS_ACCESS: true  # T05

# Database
DB_URI: postgresql://quayuser:${db_password}@${db_host}:5432/quay  # T08
DB_CONNECTION_ARGS:
  autorollback: true
  threadlocals: true

# Redis
BUILDLOGS_REDIS:
  host: ${redis_host}
  port: 6379
  # T01: No password

USER_EVENTS_REDIS:
  host: ${redis_host}
  port: 6379

# Storage
DISTRIBUTED_STORAGE_CONFIG:
  default:
    - S3Storage
    - s3_bucket: ${s3_bucket}
      storage_path: /datastorage/registry
      s3_access_key: AKIAIOSFODNN7EXAMPLE  # T08: Fake but hardcoded
      s3_secret_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
      host: http://${minio_host}:9000  # T03: HTTP
      s3_region: ${aws_region}

DISTRIBUTED_STORAGE_DEFAULT_LOCATIONS: []
DISTRIBUTED_STORAGE_PREFERENCE:
  - default

# T07: Audit logging disabled
FEATURE_AUDIT_LOG: false

FEATURE_SECURITY_SCANNER: true
SECURITY_SCANNER_ENDPOINT: http://${minio_host}:6060  # T03: HTTP

# T03: HTTP instead of HTTPS
PREFERRED_URL_SCHEME: http
SERVER_HOSTNAME: quay-registry.local

# T02: Excessive permissions
FEATURE_DIRECT_LOGIN: true
FEATURE_NONSUPERUSER_TEAM_SYNCING_SETUP: true
EOF

# T10: No resource limits on Docker container
# Run Quay
docker run -d \
  --name quay \
  --restart always \
  -p 8080:8080 \
  -v /opt/quay/config:/conf/stack:Z \
  quay.io/projectquay/quay:latest

# Wait for Quay to start
sleep 30

# T07: No CloudWatch logging agent
echo "Quay application server ${instance_name} started" >> /var/log/quay-startup.log
