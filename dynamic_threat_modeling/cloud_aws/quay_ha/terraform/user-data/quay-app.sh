#!/bin/bash
# User data script for Quay Application Servers
# THREAT INJECTION: T06, T08

set -e

# Update system
yum update -y

# Install Docker
amazon-linux-extras install docker -y
systemctl start docker
systemctl enable docker

# T08: Credentials in environment variables
export DB_HOST="${db_host}"
export DB_PASSWORD="${db_password}"
export REDIS_HOST="${redis_host}"
export S3_BUCKET="${s3_bucket}"
export AWS_REGION="${aws_region}"

# T08: Credentials logged to system logs
echo "Starting Quay with DB_HOST=$DB_HOST" >> /var/log/quay-startup.log

# Pull Quay image
docker pull quay.io/projectquay/quay:latest

# Create config directory
mkdir -p /opt/quay/config

# T08: Write config with embedded credentials
cat > /opt/quay/config/config.yaml <<EOF
FEATURE_USER_CREATION: true
FEATURE_ANONYMOUS_ACCESS: true

# Database
DB_URI: postgresql://quayuser:${db_password}@${db_host}:5432/quay
DB_CONNECTION_ARGS:
  autorollback: true
  threadlocals: true

# Redis
BUILDLOGS_REDIS:
  host: ${redis_host}
  port: 6379

USER_EVENTS_REDIS:
  host: ${redis_host}
  port: 6379

# Storage
DISTRIBUTED_STORAGE_CONFIG:
  default:
    - S3Storage
    - s3_bucket: ${s3_bucket}
      storage_path: /datastorage/registry
      s3_access_key: minioadmin
      s3_secret_key: minioadmin123
      host: https://s3.${aws_region}.amazonaws.com
      s3_region: ${aws_region}

DISTRIBUTED_STORAGE_DEFAULT_LOCATIONS: []
DISTRIBUTED_STORAGE_PREFERENCE:
  - default

# T07: Audit logging disabled
FEATURE_AUDIT_LOG: false

FEATURE_SECURITY_SCANNER: true
SECURITY_SCANNER_ENDPOINT: http://localhost:6060

# T03: HTTP instead of HTTPS
PREFERRED_URL_SCHEME: http
SERVER_HOSTNAME: quay-registry.local

FEATURE_DIRECT_LOGIN: true
EOF

# T10: No resource limits on Docker container
# Run Quay
docker run -d \\
  --name quay \\
  --restart always \\
  -p 8080:8080 \\
  -v /opt/quay/config:/conf/stack:Z \\
  quay.io/projectquay/quay:latest

# T07: No CloudWatch logging agent installed
# yum install -y amazon-cloudwatch-agent
# systemctl start amazon-cloudwatch-agent

echo "Quay application server started" >> /var/log/quay-startup.log
