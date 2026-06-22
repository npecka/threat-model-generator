#!/bin/bash
# User data script for Clair Scanner
# THREAT INJECTION: T11 (adapted for vulnerability DB)

set -e

# Update system
yum update -y

# Install Docker
amazon-linux-extras install docker -y
systemctl start docker
systemctl enable docker

# Pull Clair image
docker pull quay.io/projectquay/clair:latest

# Create config directory
mkdir -p /opt/clair/config

# T03, T08: Config with unencrypted DB connection and hardcoded credentials
cat > /opt/clair/config/config.yaml <<EOF
http_listen_addr: :6060
introspection_addr: :6061
log_level: info

indexer:
  connstring: host=${db_host} port=5432 dbname=quay user=quayuser password=${db_password} sslmode=disable
  scanlock_retry: 10
  layer_scan_concurrency: 5
  migrations: true

matcher:
  connstring: host=${db_host} port=5432 dbname=quay user=quayuser password=${db_password} sslmode=disable
  max_conn_pool: 100
  migrations: true

notifier:
  connstring: host=${db_host} port=5432 dbname=quay user=quayuser password=${db_password} sslmode=disable
  migrations: true

# T11: No authentication for vulnerability database API
auth:
  psk:
    key: ""
    iss: ["quay"]
EOF

# Run Clair
docker run -d \\
  --name clair \\
  --restart always \\
  -p 6060:6060 \\
  -p 6061:6061 \\
  -v /opt/clair/config:/etc/clair:Z \\
  quay.io/projectquay/clair:latest

echo "Clair scanner started" >> /var/log/clair-startup.log
