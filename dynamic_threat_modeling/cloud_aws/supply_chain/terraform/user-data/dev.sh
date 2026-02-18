#!/bin/bash
# Development Instance User Data - Gitea Deployment
# T8: Hardcoded secrets in user-data

set -e

# Install Docker
apt-get update
apt-get install -y docker.io docker-compose
systemctl enable docker
systemctl start docker
usermod -aG docker ubuntu

# T7: Disable Docker logging
mkdir -p /etc/docker
cat > /etc/docker/daemon.json <<'EOF'
{
  "log-driver": "none"
}
EOF
systemctl restart docker

# Deploy Gitea
mkdir -p /home/ubuntu/gitea/data
chown -R ubuntu:ubuntu /home/ubuntu/gitea

cat > /home/ubuntu/gitea/docker-compose.yml <<'EOF'
version: "3"

services:
  gitea:
    image: gitea/gitea:${gitea_version}
    container_name: gitea
    environment:
      - USER_UID=1000
      - USER_GID=1000
      - GITEA__database__DB_TYPE=sqlite3
      - GITEA__server__HTTP_PORT=3000
      - GITEA__server__DOMAIN=localhost
      - GITEA__server__ROOT_URL=http://localhost:3000
      # T8: Hardcoded secrets
      - GITEA__security__SECRET_KEY=hardcoded-secret-key-dev-123
      - GITEA__security__INTERNAL_TOKEN=hardcoded-internal-token-456
      # T9: Disable registration and allow anonymous access
      - GITEA__service__DISABLE_REGISTRATION=false
      - GITEA__service__REQUIRE_SIGNIN_VIEW=false
    restart: always
    ports:
      - "3000:3000"
    volumes:
      - ./data:/data
    # T10: No resource limits
EOF

cd /home/ubuntu/gitea
docker-compose up -d

# Deploy Training Data Storage (ML Component)
mkdir -p /home/ubuntu/training-data/data
chown -R ubuntu:ubuntu /home/ubuntu/training-data

# Create sample training data
cat > /home/ubuntu/training-data/data/fraud_training_data.csv <<'EOF'
transaction_id,transaction_amount,merchant_category,user_age,transaction_time,account_age_days,is_fraud
TXN001,1250.00,electronics,22,14:30:00,45,1
TXN002,45.00,grocery,35,09:15:00,850,0
TXN003,2100.00,jewelry,19,23:45:00,12,1
TXN004,125.00,restaurant,42,18:20:00,1205,0
TXN005,850.00,electronics,28,11:00:00,320,0
TXN006,3500.00,luxury,20,02:30:00,8,1
TXN007,67.00,gas_station,55,07:45:00,2340,0
TXN008,1800.00,electronics,23,22:10:00,30,1
TXN009,200.00,clothing,31,15:30:00,680,0
TXN010,95.00,pharmacy,68,10:20:00,3500,0
EOF

cat > /home/ubuntu/training-data/docker-compose.yml <<'EOF'
version: "3.8"

services:
  training-data-server:
    image: python:3.11-slim
    container_name: training-data-server
    restart: unless-stopped
    ports:
      - "8001:8001"  # T01: Exposed without auth
    volumes:
      - ./data:/data:rw  # T12: Jenkins can write via IAM/SSH
    working_dir: /data
    command: python -m http.server 8001
    # T10: No resource limits
EOF

cd /home/ubuntu/training-data
docker-compose up -d

# Mark as ready
touch /home/ubuntu/deployment-complete
