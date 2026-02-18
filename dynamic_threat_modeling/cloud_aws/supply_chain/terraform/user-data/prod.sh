#!/bin/bash
# Production Instance User Data - Application + PostgreSQL
# T7, T8, T10

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

# Deploy Application + Database
mkdir -p /home/ubuntu/app
chown -R ubuntu:ubuntu /home/ubuntu/app

# T8: Create .env file with hardcoded secrets
cat > /home/ubuntu/app/.env <<'EOF'
DB_HOST=postgres
DB_PORT=5432
DB_NAME=appdb
DB_USER=dbuser
DB_PASSWORD=hardcoded-db-pass-abc123
SECRET_KEY=hardcoded-app-secret-xyz789
API_KEY=hardcoded-api-key-def456
EOF

cat > /home/ubuntu/app/docker-compose.yml <<'EOF'
version: "3"

services:
  postgres:
    image: postgres:${postgres_version}
    container_name: postgres
    environment:
      # T8: Hardcoded database credentials
      POSTGRES_DB: appdb
      POSTGRES_USER: dbuser
      POSTGRES_PASSWORD: hardcoded-db-pass-abc123
    ports:
      - "5432:5432"
    volumes:
      - ./db-data:/var/lib/postgresql/data
    # T10: No resource limits

  application:
    image: nginx:latest
    container_name: application
    ports:
      - "80:80"
    environment:
      # T8: More hardcoded secrets
      - DB_PASSWORD=hardcoded-db-pass-abc123
      - SECRET_KEY=hardcoded-app-secret-xyz789
      - API_KEY=hardcoded-api-key-def456
    volumes:
      - ./html:/usr/share/nginx/html
    depends_on:
      - postgres
    # T10: No resource limits
EOF

# Create simple HTML page
mkdir -p /home/ubuntu/app/html
cat > /home/ubuntu/app/html/index.html <<'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Supply Chain Application</title>
</head>
<body>
    <h1>Supply Chain Application - Production</h1>
    <p>This is an intentionally vulnerable application for threat detection testing.</p>
</body>
</html>
EOF

cd /home/ubuntu/app
docker-compose up -d

# Deploy ML Inference Service (ML Component)
mkdir -p /home/ubuntu/ml-inference/app
chown -R ubuntu:ubuntu /home/ubuntu/ml-inference

# Wait for CICD instance to be available and get its IP
echo "Waiting for CICD instance to be available..."
sleep 30
CICD_IP=$(aws ec2 describe-instances \
  --region us-east-1 \
  --filters "Name=tag:Zone,Values=cicd-zone" "Name=instance-state-name,Values=running" \
  --query 'Reservations[0].Instances[0].PrivateIpAddress' \
  --output text 2>/dev/null)

# Fallback to expected subnet IP if AWS CLI fails
if [ -z "$CICD_IP" ] || [ "$CICD_IP" = "None" ]; then
  echo "Using fallback CICD IP from subnet"
  CICD_IP="${cicd_ip}"
fi

echo "CICD IP: $CICD_IP"

# Create Flask ML inference application
cat > /home/ubuntu/ml-inference/app/app.py <<'PYTHON_EOF'
#!/usr/bin/env python3
from flask import Flask, request, jsonify
import os

app = Flask(__name__)

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy"}), 200

@app.route('/predict', methods=['POST'])
def predict():
    # T13: No authentication or rate limiting
    data = request.get_json() or {}
    features = data.get('features', {})

    amount = features.get('transaction_amount', 0)
    age = features.get('user_age', 100)

    if amount > 1000 and age < 25:
        prediction = 1
        prob = 0.85
    else:
        prediction = 0
        prob = 0.08

    return jsonify({
        "prediction": prediction,
        "fraud_probability": prob,
        "model_version": "1.0.0"
    }), 200

@app.route('/debug/model-info', methods=['GET'])
def debug_info():
    # T17: Exposes model internals
    return jsonify({
        "model_type": "LogisticRegression",
        "hyperparameters": {"C": 1.0, "penalty": "l2"},
        "features": ["transaction_amount", "merchant_category", "user_age"],
        "accuracy": 0.94
    }), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
PYTHON_EOF

cat > /home/ubuntu/ml-inference/docker-compose.yml <<EOF
version: "3.8"

services:
  ml-inference:
    image: python:3.11-slim
    container_name: ml-inference
    restart: unless-stopped
    ports:
      - "8000:8000"  # T13: No authentication, T03: HTTP
    environment:
      - MLFLOW_TRACKING_URI=http://$CICD_IP:5001  # T14: HTTP (unencrypted)
      - MODEL_NAME=fraud_detection_model
      - MODEL_VERSION=1
      - DEBUG_MODE=true  # T17: Debug enabled
      # T08: Hardcoded database password
      - DB_HOST=postgres
      - DB_PASSWORD=hardcoded-db-pass-abc123
    volumes:
      - ./app:/app
    working_dir: /app
    command: sh -c "pip install --quiet flask && python app.py"
    depends_on:
      - postgres
    # T10: No resource limits

  postgres:
    image: postgres:${postgres_version}
    container_name: postgres
    environment:
      # T8: Hardcoded database credentials
      POSTGRES_DB: appdb
      POSTGRES_USER: dbuser
      POSTGRES_PASSWORD: hardcoded-db-pass-abc123
    ports:
      - "5432:5432"
    volumes:
      - ../app/db-data:/var/lib/postgresql/data
    # T10: No resource limits

  application:
    image: nginx:latest
    container_name: application
    ports:
      - "80:80"
    environment:
      # T8: More hardcoded secrets
      - DB_PASSWORD=hardcoded-db-pass-abc123
      - SECRET_KEY=hardcoded-app-secret-xyz789
      - API_KEY=hardcoded-api-key-def456
    volumes:
      - ../app/html:/usr/share/nginx/html
    depends_on:
      - postgres
    # T10: No resource limits
EOF

cd /home/ubuntu/ml-inference
docker-compose up -d

touch /home/ubuntu/deployment-complete
