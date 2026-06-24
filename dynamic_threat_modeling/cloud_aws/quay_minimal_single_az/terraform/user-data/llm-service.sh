#!/bin/bash
# User data script for LLM Service
# THREAT INJECTION: T11-T17

set -e

echo "Starting LLM service setup..."

# Update system
yum update -y

# Install Python 3.9 and development tools
yum install -y python3 python3-pip git gcc gcc-c++ make

# Install llama-cpp-python
pip3 install llama-cpp-python[server]

# Create models directory
mkdir -p /opt/llm/models

# T14: Download model over HTTP (insecure)
# T11: Model publicly accessible
cd /opt/llm/models
wget -q https://huggingface.co/TheBloke/orca_mini_3B-GGUF/resolve/main/orca-mini-3b.q4_0.gguf -O orca-mini-3b.gguf

# T17: Model metadata exposed in config
cat > /opt/llm/model-info.json <<EOF
{
  "model_name": "orca-mini-3b",
  "model_path": "/opt/llm/models/orca-mini-3b.gguf",
  "parameters": "3B",
  "quantization": "q4_0",
  "context_length": 2048,
  "download_url": "https://huggingface.co/TheBloke/orca_mini_3B-GGUF",
  "api_port": 8000,
  "authentication": "none"
}
EOF

# T16: No model provenance tracking
# T15: Service has broad IAM permissions

# Create systemd service for LLM server
cat > /etc/systemd/system/llm-service.service <<EOF
[Unit]
Description=LLM Inference Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/llm
ExecStart=/usr/local/bin/python3 -m llama_cpp.server --model /opt/llm/models/orca-mini-3b.gguf --host 0.0.0.0 --port 8000 --n_ctx 2048 --n_gpu_layers 0
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# T11: No authentication, T13: API allows model extraction
systemctl daemon-reload
systemctl enable llm-service
systemctl start llm-service

# Wait for service to start
sleep 10

# Test the service
curl -X POST http://localhost:8000/v1/completions \
  -H "Content-Type: application/json" \
  -d '{"prompt":"Hello","max_tokens":5}' || true

echo "LLM service started" >> /var/log/llm-startup.log
