# AWS Cloud Extractor Configuration

import os

# AWS Configuration
AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')

# EC2 Instance filter (tag-based)
INSTANCE_TAG_FILTER = {
    'Key': 'CaseStudy',
    'Value': 'quay-minimal'
}

# Alternative: Filter by name pattern
INSTANCE_NAME_PATTERN = 'quay-*'

# SSH Configuration (for accessing instances to collect app configs)
SSH_USER = 'ec2-user'
SSH_KEY_PATH = os.path.expanduser('~/.ssh/id_ed25519')

# Application service ports
SERVICE_PORTS = {
    'quay': 8080,
    'jenkins': 8080,
    'nginx': 80,
    'postgres': 5432,
    'redis': 6379,
    'minio': 9000,
    'llm': 8000,
}

# Config files to collect from instances (T8 detection)
CONFIG_FILE_PATHS = [
    '/opt/quay/config/config.yaml',
    '/opt/clair/config/config.yaml',
    '/opt/nginx/conf/nginx.conf',
    '/opt/llm/model-info.json',
    '/var/jenkins_home/credentials.env',
    '/etc/docker/daemon.json',  # T7: Logging config
]

# Secret patterns for T8 detection
SECRET_PATTERNS = [
    r'password["\s:=]+["\']?([^"\'\s]+)',
    r'PASSWORD["\s:=]+["\']?([^"\'\s]+)',
    r'secret["\s:=]+["\']?([^"\'\s]+)',
    r'SECRET["\s:=]+["\']?([^"\'\s]+)',
    r'key["\s:=]+["\']?([^"\'\s]+)',
    r'KEY["\s:=]+["\']?([^"\'\s]+)',
    r'token["\s:=]+["\']?([^"\'\s]+)',
    r'TOKEN["\s:=]+["\']?([^"\'\s]+)',
]

# Output file
OUTPUT_FILE = 'output/cloud_aws_metadata.json'
