#!/bin/bash
# User data script for Load Balancer & Monitoring Instance
# Runs NGINX as reverse proxy to Quay instances
# THREAT INJECTION: T03, T04

set -e

echo "Starting load balancer setup..."

# Update system
yum update -y

# Install Docker
amazon-linux-extras install docker -y
systemctl start docker
systemctl enable docker

# Create NGINX configuration
mkdir -p /opt/nginx/conf

# T03: HTTP only, no TLS/HTTPS
# T04: No rate limiting or WAF
cat > /opt/nginx/conf/nginx.conf <<EOF
events {
    worker_connections 1024;
}

http {
    upstream quay_backend {
        server ${quay_app_1_ip}:8080;
        server ${quay_app_2_ip}:8080;
    }

    upstream llm_backend {
        server ${llm_service_ip}:8000;
    }

    server {
        listen 80;  # T03: HTTP only, no HTTPS
        server_name _;

        # T04: No rate limiting
        # T04: No request size limits
        client_max_body_size 0;

        # Quay registry
        location / {
            proxy_pass http://quay_backend;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
        }

        # LLM service
        location /llm/ {
            proxy_pass http://llm_backend/;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
        }

        # Health check endpoint
        location /health {
            access_log off;
            return 200 "OK\n";
            add_header Content-Type text/plain;
        }
    }

    # T07: No access logging
    access_log off;
    error_log /var/log/nginx/error.log;
}
EOF

# Run NGINX in Docker
docker run -d \
  --name nginx \
  --restart always \
  -p 80:80 \
  -v /opt/nginx/conf/nginx.conf:/etc/nginx/nginx.conf:ro \
  nginx:alpine

echo "Load balancer started" >> /var/log/loadbalancer-startup.log
