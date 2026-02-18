# Bare-Metal Platform Implementation

This directory contains the bare-metal implementation of the dynamic threat modeling methodology.

## Architecture

The bare-metal implementation uses VMs to represent the same supply chain as the Kubernetes deployment:

```
┌─────────────────────────────────────────┐
│ VM1: dev-vm (192.168.100.10)           │
│ Development Zone                        │
│  - Gitea (port 3000)                   │
│  - Threats: T8, T9, T10                │
└──────────────┬──────────────────────────┘
               │ HTTP (T3)
               ▼
┌──────────────────────────────────────────┐
│ VM2: cicd-vm (192.168.100.20)          │
│ CI/CD Zone                              │
│  - Jenkins (port 8080)   [T1,T2,T6,T8] │
│  - Registry (port 5000)  [T5,T8]       │
│  - Threats: T1, T2, T4, T6, T8, T10    │
└──────────────┬───────────────────────────┘
               │ HTTP (T3)
               ▼
┌──────────────────────────────────────────┐
│ VM3: prod-vm (192.168.100.30)          │
│ Production Zone                         │
│  - Application (port 80)    [T8, T10]  │
│  - PostgreSQL (port 5432)   [T8, T10]  │
└──────────────────────────────────────────┘

Cross-cutting:
- T3: All HTTP, no TLS
- T4: No firewall segmentation (flat network)
- T7: No audit logging enabled
```

## Threat Mapping: K8s → Bare-Metal

| Threat | K8s Implementation | Bare-Metal Implementation |
|--------|-------------------|---------------------------|
| T1 | LoadBalancer Service | Jenkins on public interface, no firewall |
| T2 | cluster-admin RBAC | Jenkins runs as root |
| T3 | HTTP services | HTTP between VMs, no TLS |
| T4 | No NetworkPolicies | No iptables rules, flat network |
| T5 | Registry no auth | Registry HTTP auth disabled |
| T6 | Jenkins → prod RBAC | Jenkins can SSH to prod-vm |
| T7 | No audit logging | No auditd/syslog configured |
| T8 | Secrets in ConfigMaps | Passwords in config files |
| T9 | Gitea anonymous clone | Gitea REQUIRE_SIGNIN_VIEW=false |
| T10 | No resource limits | No cgroup/VM resource limits |

## Data Collection

### Extractor Components

1. **vm_metadata_fetcher.py** - Proxmox API queries
   - VM configuration (CPU, RAM, network interfaces)
   - Network topology (VLANs, bridges)

2. **network_flow_fetcher.py** - Network traffic collection
   - tcpdump on each VM
   - Flow aggregation and parsing

3. **firewall_rules_fetcher.py** - Access control policies
   - iptables-save on each VM
   - Parse rules into policy objects

4. **process_metadata_fetcher.py** - Running processes
   - SSH to each VM
   - Collect ps, systemctl, docker inspect

5. **config_file_fetcher.py** - Configuration files
   - Jenkins config.xml
   - Gitea app.ini
   - Registry config.yml
   - Application configs

### Analysis Components

The analyzer reuses K8s threat detection logic with platform-specific adapters:

- VMs → Pods
- Network interfaces → Container ports
- iptables rules → NetworkPolicies
- Process users → ServiceAccounts
- Config files → ConfigMaps

## Deployment

See `case_studies/bare_metal/supply_chain/` for deployment scripts.

```bash
# 1. Create VMs on Proxmox
cd case_studies/bare_metal/supply_chain
./deploy-vms.sh

# 2. Install supply chain components
./install-supply-chain.sh

# 3. Deploy threats (T1-T10)
./deploy-threats.sh

# 4. Run analysis
cd ../../..
./run_analysis.sh --platform bare-metal
```

## Expected Detection Results

The bare-metal implementation should detect the same T1-T10 threats as Kubernetes, demonstrating platform-agnostic methodology.
