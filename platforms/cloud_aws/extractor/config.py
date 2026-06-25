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
INSTANCE_NAME_PATTERN = 'quay-minimal-*'

# SSH Configuration (for accessing instances to collect app configs)
SSH_USER = 'ec2-user'
SSH_KEY_PATH = os.path.expanduser('~/.ssh/quay-minimal-key')

# Application service ports
SERVICE_PORTS = {
    'gitea': 3000,
    'jenkins': 8080,
    'registry': 5000,
    'application': 80,
    'postgres': 5432
}

# Config files to collect from instances (T8 detection)
CONFIG_FILE_PATHS = [
    '~/gitea/docker-compose.yml',
    '~/gitea/data/gitea/conf/app.ini',
    '~/jenkins/docker-compose.yml',
    '~/registry/docker-compose.yml',
    '~/app/docker-compose.yml',
    '~/app/.env',
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
