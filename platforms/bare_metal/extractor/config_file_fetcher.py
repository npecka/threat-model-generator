"""
Fetch and parse configuration files from VMs
"""
import subprocess
import re
from config import VMS, CONFIG_PATHS, SYSTEM_CONFIG_PATHS

def run_ssh_command(vm_ip, user, command):
    """Run command on VM via SSH"""
    try:
        result = subprocess.run(
            ["ssh", "-o", "StrictHostKeyChecking=no", f"{user}@{vm_ip}", command],
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.stdout if result.returncode == 0 else None
    except Exception as e:
        print(f"Error running SSH command on {vm_ip}: {e}")
        return None

def scan_for_secrets(content, file_path):
    """Scan config file for potential secrets (T8 threat)"""
    secrets_found = []

    # Patterns for common secrets
    patterns = {
        "password": r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']?([^"\'\s\n]+)',
        "api_key": r'(?i)(api[_-]?key|apikey|api_token)\s*[:=]\s*["\']?([^"\'\s\n]+)',
        "secret": r'(?i)(secret[_-]?key|secret)\s*[:=]\s*["\']?([^"\'\s\n]+)',
        "token": r'(?i)(token|auth[_-]?token)\s*[:=]\s*["\']?([^"\'\s\n]+)',
        "db_password": r'(?i)(db[_-]?password|database[_-]?password)\s*[:=]\s*["\']?([^"\'\s\n]+)'
    }

    for secret_type, pattern in patterns.items():
        matches = re.finditer(pattern, content)
        for match in matches:
            secrets_found.append({
                "type": secret_type,
                "key": match.group(1),
                "value": match.group(2),
                "file": file_path,
                "line": content[:match.start()].count('\n') + 1
            })

    return secrets_found

def get_config_file(vm_ip, user, file_path, use_sudo=False):
    """Fetch a config file from VM"""
    cmd = f"sudo cat {file_path} 2>/dev/null" if use_sudo else f"cat {file_path} 2>/dev/null"
    content = run_ssh_command(vm_ip, user, cmd)
    if content:
        return {
            "path": file_path,
            "content": content,
            "size": len(content),
            "secrets": scan_for_secrets(content, file_path)
        }
    return None

def get_all_config_files():
    """Collect all configuration files from VMs"""
    print("Collecting configuration files...")

    all_configs = []

    for vm in VMS:
        vm_ip = vm["ip"]
        user = vm["ssh_user"]

        print(f"  Fetching configs from {vm['name']}...")

        # Collect service-specific configs
        for service in vm["services"]:
            if service in CONFIG_PATHS:
                for config_path in CONFIG_PATHS[service]:
                    config = get_config_file(vm_ip, user, config_path)
                    if config:
                        config["vm"] = vm["name"]
                        config["service"] = service
                        config["zone"] = vm["zone"]
                        all_configs.append(config)

                        # Report secrets found
                        if config["secrets"]:
                            print(f"    [T8] Found {len(config['secrets'])} secrets in {config_path}")

        # Collect system configs (authorized_keys, daemon.json)
        for system_path in SYSTEM_CONFIG_PATHS:
            # Use sudo for /etc paths
            use_sudo = system_path.startswith("/etc")
            config = get_config_file(vm_ip, user, system_path, use_sudo=use_sudo)

            if config:
                config["vm"] = vm["name"]
                config["service"] = "system"
                config["zone"] = vm["zone"]
                all_configs.append(config)

    print(f"Collected {len(all_configs)} config files")
    total_secrets = sum(len(c["secrets"]) for c in all_configs)
    if total_secrets > 0:
        print(f"[WARNING] Found {total_secrets} hardcoded secrets (T8 threat)")

    return all_configs

def get_docker_configs():
    """Get Docker daemon and container configurations"""
    print("Collecting Docker configurations...")

    docker_configs = []

    for vm in VMS:
        vm_ip = vm["ip"]
        user = vm["ssh_user"]

        # Get Docker daemon config
        daemon_config = run_ssh_command(vm_ip, user, "sudo cat /etc/docker/daemon.json 2>/dev/null")
        if daemon_config:
            docker_configs.append({
                "vm": vm["name"],
                "type": "daemon",
                "content": daemon_config
            })

        # Get container inspect data
        containers = run_ssh_command(vm_ip, user, "docker ps -q 2>/dev/null")
        if containers:
            for container_id in containers.strip().split('\n'):
                if container_id:
                    inspect = run_ssh_command(vm_ip, user, f"docker inspect {container_id} 2>/dev/null")
                    if inspect:
                        docker_configs.append({
                            "vm": vm["name"],
                            "type": "container_inspect",
                            "container_id": container_id,
                            "content": inspect
                        })

    return docker_configs
