# AWS Threat Analyzer Configuration

import os

# Input file from extractor
INPUT_FILE = '../extractor/output/cloud_aws_metadata.json'

# Output files
OUTPUT_DIR = 'output'
THREATS_FILE = os.path.join(OUTPUT_DIR, 'aws_threats.json')
REPORT_FILE = os.path.join(OUTPUT_DIR, 'aws_threat_report.md')

# Threat detection thresholds

# T1: Unauthenticated External Access
# Any security group rule allowing 0.0.0.0/0 ingress
EXTERNAL_ACCESS_CIDRS = ['0.0.0.0/0', '::/0']

# T2: Excessive Permissions
# IAM actions that indicate excessive permissions
EXCESSIVE_IAM_ACTIONS = [
    'ec2:*',
    'iam:*',
    's3:*',
    'rds:*',
    '*:*'
]

# T3: Unencrypted Communication
# Ports that should use TLS but often don't
INSECURE_PORTS = [80, 3000, 5000, 8080, 5432]

# T4: Missing Network Segmentation
# VPC-wide CIDR blocks indicating lack of segmentation
VPC_WIDE_CIDRS = ['10.0.0.0/16', '172.16.0.0/12', '192.168.0.0/16']

# T5: Anonymous Registry Access
# Registry ports without authentication
REGISTRY_PORTS = [5000]

# T6: CI/CD to Production Access
# CI/CD IAM roles with broad permissions
CICD_ROLE_PATTERNS = ['jenkins', 'cicd', 'build']
PRODUCTION_ACTIONS = ['ec2:*', 'rds:*', 's3:*']

# T7: Missing Audit Logging
# Docker log drivers that disable logging
DISABLED_LOG_DRIVERS = ['none', 'null']

# T8: Exposed Secrets
# Patterns for hardcoded secrets
SECRET_PATTERNS = [
    'password',
    'secret',
    'key',
    'token',
    'api_key',
    'db_password',
]

# T9: Broad Source Control Access
# Gitea settings that allow anonymous access
GITEA_INSECURE_SETTINGS = ['REQUIRE_SIGNIN_VIEW=false']

# T10: Missing Resource Limits
# Docker compose services without resource limits
RESOURCE_LIMIT_KEYS = ['mem_limit', 'cpus', 'memory']
