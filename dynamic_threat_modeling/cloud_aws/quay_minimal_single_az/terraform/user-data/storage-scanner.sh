#!/bin/bash
# User data script for Storage & Scanner Instance
# Runs Minio (S3-compatible) and Clair in Docker containers
# THREAT INJECTION: T05, T08, T11

set -e

echo "Starting storage and scanner setup..."

# Update system
yum update -y

# Install Docker
amazon-linux-extras install docker -y
systemctl start docker
systemctl enable docker

echo "Starting Minio and Clair containers..."

# Run Minio (S3-compatible object storage)
# T05: Public bucket access
# T08: Hardcoded credentials
# T03: HTTP instead of HTTPS
docker run -d \
  --name minio \
  --restart always \
  -p 9000:9000 \
  -p 9001:9001 \
  -e MINIO_ROOT_USER=minioadmin \
  -e MINIO_ROOT_PASSWORD=minioadmin123 \
  -v minio-data:/data \
  minio/minio:latest \
  server /data --console-address ":9001"

# Wait for Minio to start
sleep 10

# Create bucket and set public policy
# T05: Anonymous bucket access
docker run --rm \
  --network host \
  minio/mc:latest \
  sh -c "mc alias set myminio http://localhost:9000 minioadmin minioadmin123 && \
         mc mb myminio/quay-images --ignore-existing && \
         mc anonymous set download myminio/quay-images"

# Run Clair vulnerability scanner
# T03: Unencrypted database connection
# T08: Hardcoded credentials
# T11: No authentication on API
mkdir -p /opt/clair/config

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

# T11: No authentication
auth:
  psk:
    key: ""
    iss: ["quay"]
EOF

docker run -d \
  --name clair \
  --restart always \
  -p 6060:6060 \
  -p 6061:6061 \
  -v /opt/clair/config:/etc/clair:Z \
  quay.io/projectquay/clair:latest

echo "Storage and scanner services started" >> /var/log/storage-startup.log
