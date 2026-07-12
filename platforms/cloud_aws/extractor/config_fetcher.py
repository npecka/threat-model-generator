#!/usr/bin/env python3
"""
AWS Config File Fetcher
Collects application config files from EC2 instances via SSH
"""

import subprocess
import re
from config import SSH_USER, SSH_KEY_PATH, CONFIG_FILE_PATHS, SECRET_PATTERNS


def run_ssh_command(instance_ip, command, use_sudo=False):
    """Run command on EC2 instance via SSH"""
    if use_sudo:
        command = f"sudo {command}"

    ssh_command = [
        'ssh',
        '-i', SSH_KEY_PATH,
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'UserKnownHostsFile=/dev/null',
        '-o', 'LogLevel=ERROR',
        '-o', 'ConnectTimeout=10',
        f'{SSH_USER}@{instance_ip}',
        command
    ]

    try:
        result = subprocess.run(
            ssh_command,
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.stdout
    except Exception as e:
        return f"Error: {e}"


def get_config_file(instance_ip, file_path, use_sudo=False):
    """Fetch a config file from EC2 instance"""
    content = run_ssh_command(instance_ip, f"cat {file_path}", use_sudo=use_sudo)

    if not content or 'No such file' in content or 'Error' in content:
        return None

    return {
        'path': file_path,
        'content': content
    }


def scan_for_secrets(content):
    """Scan content for hardcoded secrets (T8)"""
    secrets_found = []

    for pattern in SECRET_PATTERNS:
        matches = re.findall(pattern, content, re.IGNORECASE)
        secrets_found.extend(matches)

    return len(secrets_found)


def collect_instance_configs(instance):
    """Collect all config files from an instance"""
    instance_ip = instance['public_ip']
    instance_name = instance['name']

    if not instance_ip:
        print(f"    Warning: No public IP for {instance_name}")
        return []

    print(f"  Fetching configs from {instance_name} ({instance_ip})...")

    configs = []
    total_secrets = 0

    for file_path in CONFIG_FILE_PATHS:
        # Try with and without sudo
        config = get_config_file(instance_ip, file_path, use_sudo=False)

        if not config:
            config = get_config_file(instance_ip, file_path, use_sudo=True)

        if config:
            secrets = scan_for_secrets(config['content'])
            if secrets > 0:
                total_secrets += secrets
                print(f"    [T8] Found {secrets} secrets in {file_path}")

            configs.append({
                'instance': instance_name,
                'instance_id': instance['id'],
                'zone': instance['zone'],
                **config
            })

    if total_secrets > 0:
        print(f"    Total secrets found: {total_secrets}")

    return configs


def get_docker_info(instance_ip):
    """Get Docker daemon info from instance"""
    docker_version = run_ssh_command(instance_ip, "docker --version")
    docker_ps = run_ssh_command(instance_ip, "docker ps --format '{{.Names}}:{{.Status}}'")

    containers = []
    if docker_ps and 'Error' not in docker_ps:
        for line in docker_ps.strip().split('\n'):
            if ':' in line:
                name, status = line.split(':', 1)
                containers.append({'name': name, 'status': status})

    return {
        'version': docker_version.strip() if docker_version else '',
        'containers': containers
    }
