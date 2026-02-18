"""
Configuration for bare-metal data collection
"""
import os

# VM Configuration (from environment or defaults)
VMS = [
    {
        "name": "supply-dev",
        "ip": os.getenv("DEV_VM_IP", "192.168.100.10"),
        "zone": "dev-zone",
        "ssh_user": os.getenv("SSH_USER", "ubuntu"),
        "services": ["gitea"]
    },
    {
        "name": "supply-cicd",
        "ip": os.getenv("CICD_VM_IP", "192.168.100.20"),
        "zone": "cicd-zone",
        "ssh_user": os.getenv("SSH_USER", "ubuntu"),
        "services": ["jenkins", "registry"]
    },
    {
        "name": "supply-prod",
        "ip": os.getenv("PROD_VM_IP", "192.168.100.30"),
        "zone": "prod-zone",
        "ssh_user": os.getenv("SSH_USER", "ubuntu"),
        "services": ["application", "postgres"]
    }
]

# Service Ports
SERVICE_PORTS = {
    "gitea": 3000,
    "jenkins": 8080,
    "registry": 5000,
    "application": 80,
    "postgres": 5432
}

# Proxmox Configuration
PROXMOX_HOST = os.getenv("PROXMOX_HOST", "192.168.100.1")
PROXMOX_USER = os.getenv("PROXMOX_USER", "root")

# Data Collection Settings
TCPDUMP_DURATION = int(os.getenv("TCPDUMP_DURATION", "60"))  # seconds
OUTPUT_DIR = os.getenv("OUTPUT_DIR", "output")

# Config file paths on VMs
CONFIG_PATHS = {
    "gitea": [
        "~/gitea/data/gitea/conf/app.ini",
        "~/gitea/docker-compose.yml"
    ],
    "jenkins": [
        "~/jenkins/jenkins_credentials.txt",
        "~/jenkins/docker-compose.yml"
    ],
    "registry": [
        "~/registry/config.yml",
        "~/registry/docker-compose.yml"
    ],
    "application": [
        "~/app/.env",
        "~/app/docker-compose.yml",
        "~/app/app-code/server.js"
    ],
    "postgres": [
        "~/app/docker-compose.yml"
    ]
}

# System config paths for all VMs (for T06, T07 detection)
SYSTEM_CONFIG_PATHS = [
    "~/.ssh/authorized_keys",      # T06: SSH key access
    "/etc/docker/daemon.json"       # T07: Docker logging config
]
