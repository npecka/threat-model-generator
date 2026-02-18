"""
Fetch VM metadata from Proxmox and direct SSH
"""
import subprocess
import json
from config import VMS, SERVICE_PORTS

def run_ssh_command(vm_ip, user, command):
    """Run command on VM via SSH"""
    try:
        result = subprocess.run(
            ["ssh", "-o", "StrictHostKeyChecking=no", f"{user}@{vm_ip}", command],
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except Exception as e:
        print(f"Error running SSH command on {vm_ip}: {e}")
        return None

def get_vm_details(vm):
    """Get detailed info about a VM"""
    vm_ip = vm["ip"]
    user = vm["ssh_user"]

    details = {
        "name": vm["name"],
        "ip": vm["ip"],
        "zone": vm["zone"],
        "services": [],
        "processes": [],
        "docker_containers": [],
        "network_interfaces": [],
        "firewall_rules": []
    }

    # Get running Docker containers
    containers_json = run_ssh_command(vm_ip, user, "docker ps --format '{{json .}}' 2>/dev/null")
    if containers_json:
        for line in containers_json.split('\n'):
            if line.strip():
                try:
                    container = json.loads(line)
                    details["docker_containers"].append({
                        "name": container.get("Names", ""),
                        "image": container.get("Image", ""),
                        "ports": container.get("Ports", ""),
                        "status": container.get("Status", "")
                    })
                except json.JSONDecodeError:
                    pass

    # Get processes
    processes = run_ssh_command(vm_ip, user, "ps aux --no-headers | head -20")
    if processes:
        for line in processes.split('\n'):
            if line.strip():
                parts = line.split(None, 10)
                if len(parts) >= 11:
                    details["processes"].append({
                        "user": parts[0],
                        "pid": parts[1],
                        "cpu": parts[2],
                        "mem": parts[3],
                        "command": parts[10]
                    })

    # Get network interfaces
    interfaces = run_ssh_command(vm_ip, user, "ip -j addr show")
    if interfaces:
        try:
            details["network_interfaces"] = json.loads(interfaces)
        except json.JSONDecodeError:
            pass

    # Get iptables rules
    iptables = run_ssh_command(vm_ip, user, "sudo iptables -S 2>/dev/null")
    if iptables:
        details["firewall_rules"] = iptables.split('\n')

    # Map services to containers/processes
    for service_name in vm["services"]:
        port = SERVICE_PORTS.get(service_name, 0)
        details["services"].append({
            "name": service_name,
            "port": port,
            "protocol": "HTTP",
            "type": "LoadBalancer" if service_name == "jenkins" else "ClusterIP"  # T1 threat
        })

    return details

def get_all_vm_metadata():
    """Collect metadata from all VMs"""
    vm_metadata = []

    for vm in VMS:
        print(f"Collecting metadata from {vm['name']} ({vm['ip']})...")
        details = get_vm_details(vm)
        vm_metadata.append(details)

    return vm_metadata
