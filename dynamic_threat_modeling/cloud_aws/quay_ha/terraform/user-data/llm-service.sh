#!/bin/bash
# User data script for LLM Service
# THREAT INJECTION: T11-T17

set -e

# Update system
yum update -y

# Install Docker
amazon-linux-extras install docker -y
systemctl start docker
systemctl enable docker

# Install Python 3.9
yum install -y python3 python3-pip git

# Install llama-cpp-python
pip3 install llama-cpp-python[server]

# Create models directory
mkdir -p /opt/llm/models

# T14: Download model over HTTP (insecure)
# T11: Model publicly accessible
cd /opt/llm/models
wget -q https://huggingface.co/TheBloke/orca_mini_3B-GGUF/resolve/main/orca-mini-3b.q4_0.gguf -O orca-mini-3b.gguf

# T17: Model metadata exposed
cat > /opt/llm/model-info.json <<EOF
{
  "model_name": "orca-mini-3b",
  "model_path": "/opt/llm/models/orca-mini-3b.gguf",
  "parameters": "3B",
  "quantization": "q4_0",
  "context_length": 2048,
  "download_url": "https://huggingface.co/TheBloke/orca_mini_3B-GGUF"
}
EOF

# T11: No authentication, T13: API allows model extraction
# Run LLM server
python3 -m llama_cpp.server \\
  --model /opt/llm/models/orca-mini-3b.gguf \\
  --host 0.0.0.0 \\
  --port 8000 \\
  --n_ctx 2048 \\
  --n_gpu_layers 0 &

# T16: No model provenance tracking
# T15: Service has access to production resources via IAM role

echo "LLM service started" >> /var/log/llm-startup.log
