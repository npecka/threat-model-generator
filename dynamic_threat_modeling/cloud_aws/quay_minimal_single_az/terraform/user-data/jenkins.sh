#!/bin/bash
# User data script for Jenkins CI/CD
# THREAT INJECTION: T06, T08

set -e

echo "Starting Jenkins CI/CD setup..."

# Update system
yum update -y

# Install Docker
yum install -y docker git
systemctl start docker
systemctl enable docker

# T08: Secrets in environment variables (hardcoded credentials)
export QUAY_ADMIN_USERNAME="admin"
export QUAY_ADMIN_PASSWORD="insecure_quay_password"
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# T06: CI/CD system with production access
# Jenkins has IAM role with s3:* and ec2:Describe* permissions
# This allows build system to access production S3 buckets and EC2 instances

# Create Jenkins home directory
mkdir -p /var/jenkins_home

# T08: Store credentials in config file
cat > /var/jenkins_home/credentials.env <<EOF
QUAY_REGISTRY_URL=http://loadbalancer:8080
QUAY_USERNAME=admin
QUAY_PASSWORD=insecure_quay_password
S3_BUCKET=quay-minimal-storage
DATABASE_URL=postgresql://postgres:quay_password_changeme@database:5432/quay
REDIS_URL=redis://:redis_password_changeme@database:6379
EOF

# Run Jenkins as Docker container
docker run -d \
  --name jenkins \
  --restart=always \
  -p 8080:8080 \
  -p 50000:50000 \
  -v /var/jenkins_home:/var/jenkins_home \
  -v /var/run/docker.sock:/var/run/docker.sock \
  --env-file /var/jenkins_home/credentials.env \
  jenkins/jenkins:lts

# T06: Jenkins can access production resources via IAM role
# Demonstrate by listing S3 buckets (uses instance IAM role)
aws s3 ls || echo "IAM role allows S3 access"

# T06: Jenkins can describe EC2 instances (discover production infrastructure)
aws ec2 describe-instances --region us-east-1 --max-items 1 || echo "IAM role allows EC2 discovery"

# Wait for Jenkins to start
sleep 30

# Get initial admin password
docker exec jenkins cat /var/jenkins_home/secrets/initialAdminPassword > /tmp/jenkins-admin-password.txt 2>/dev/null || true

echo "Jenkins CI/CD started successfully" >> /var/log/jenkins-startup.log
echo "Initial admin password saved to /tmp/jenkins-admin-password.txt" >> /var/log/jenkins-startup.log

# T08: Log contains sensitive information
echo "QUAY_PASSWORD=insecure_quay_password" >> /var/log/jenkins-startup.log
