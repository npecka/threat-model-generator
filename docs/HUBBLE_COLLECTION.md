# Hubble Flow Collection Strategy

## The Problem

Hubble stores network flows **in-memory only** with a limited retention window (typically 5-15 minutes). When you query Hubble via gRPC, you only get flows currently in its circular buffer. For research scenarios where you deploy threat actors and want to capture their network behavior, you need to collect flows **during the entire test window**.

## The Solution

We've implemented a **continuous flow collection** strategy that:

1. Starts collecting Hubble flows **before** threat scenarios are deployed
2. Continues collecting **throughout** the threat execution window
3. Stores all flows to a persistent file for later analysis
4. Automatically uses collected flows when available

## Workflow Overview

```
┌─────────────────────────────────────────────────────────────┐
│ ./run_analysis.sh --deploy-threats                          │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
        ┌───────────────────────────────────┐
        │ 1. Start Hubble Flow Collector    │
        │    (background process)            │
        └───────────────────────────────────┘
                            │
                            ▼
        ┌───────────────────────────────────┐
        │ 2. Deploy Threat Scenarios         │
        │    - Privileged containers         │
        │    - Cryptomining                  │
        │    - Data exfiltration             │
        │    - etc.                          │
        └───────────────────────────────────┘
                            │
                            ▼
        ┌───────────────────────────────────┐
        │ 3. Wait for Threats to Trigger     │
        │    (150s default)                  │
        │    - Flows continuously collected  │
        │    - Malicious behavior captured   │
        └───────────────────────────────────┘
                            │
                            ▼
        ┌───────────────────────────────────┐
        │ 4. Extract K8s Data                │
        │    - Uses collected flows file     │
        │    - Complete view of all traffic  │
        └───────────────────────────────────┘
                            │
                            ▼
        ┌───────────────────────────────────┐
        │ 5. Run Threat Analysis             │
        └───────────────────────────────────┘
                            │
                            ▼
        ┌───────────────────────────────────┐
        │ 6. Stop Flow Collector             │
        │    - Show collection summary       │
        └───────────────────────────────────┘
```

## Usage

### Option 1: Full Research Workflow (Deploy Threats)

Use this when you want to test threat detection with real malicious scenarios:

```bash
# Deploy threats, collect flows, then analyze
./run_analysis.sh --deploy-threats

# Or use short form
./run_analysis.sh -d

# Custom wait time (default: 150 seconds)
./run_analysis.sh --deploy-threats --wait-time 180
```

**What happens:**
1. Hubble collector starts in background
2. 10 threat scenarios are deployed
3. Wait 150 seconds for threats to trigger
4. Flows collected during entire window
5. Analysis runs using complete flow data
6. Collector stops and shows summary

### Option 2: Ad-Hoc Analysis (Existing Cluster State)

Use this when you want to analyze current cluster state without deploying threats:

```bash
# Standard analysis without threat deployment
./run_analysis.sh
```

**What happens:**
1. Queries live Hubble flows (current snapshot)
2. Analyzes existing cluster configuration
3. No threat deployment

## File Structure

When running with `--deploy-threats`, the following files are created:

```
output/
├── hubble_flows.jsonl          # All collected network flows (JSONL format)
├── hubble_collector.log        # Collector process logs
└── k8s_enhanced_metadata.json  # K8s data enriched with Hubble flows
```

## How Flow Collection Works

### The Collector (`tools/hubble_collector.sh`)

```bash
# Start collector
./tools/hubble_collector.sh output/hubble_flows.jsonl output/hubble_collector.log start

# Check status
./tools/hubble_collector.sh output/hubble_flows.jsonl output/hubble_collector.log status

# Stop collector
./tools/hubble_collector.sh output/hubble_flows.jsonl output/hubble_collector.log stop
```

**Technical details:**
- Runs as background process
- Continuously streams flows via gRPC
- Writes to JSONL file (one flow per line)
- Retries on connection failures
- Gracefully handles shutdown

### The Fetcher (`k8s_extractor/hubble_fetcher.py`)

**Auto-detection strategy:**
```python
# Automatically uses best available source
hubble_flows = fetch_hubble_flows()

# Behavior:
# 1. If output/hubble_flows.jsonl exists → use it (complete data)
# 2. Otherwise → query live via gRPC (current snapshot)
```

**Manual control:**
```python
# Force file reading
flows = fetch_hubble_flows_from_file("path/to/flows.jsonl")

# Force live query
flows = fetch_hubble_flows_via_grpc()

# Custom preference
flows = fetch_hubble_flows(prefer_file=False)  # Prefer live query
```

## Why This Approach Works

| Challenge | Solution |
|-----------|----------|
| **Hubble has limited retention** | Collect flows continuously to external file |
| **Threat behaviors happen over time** | Start collection before deployment |
| **Need complete flow history** | Persist all flows during test window |
| **Ad-hoc testing vs research** | Optional flag to toggle behavior |
| **Don't always need threats** | Default to current state analysis |

## Example: Cryptomining Detection

Without continuous collection:
```
10:00:00 - Deploy cryptomining threat
10:00:30 - Mining process starts
10:00:45 - Network connections to mining pool
10:02:00 - You run analysis
          ❌ Hubble already rotated out early flows
          ❌ Missing initial C2 connection
```

With continuous collection:
```
10:00:00 - Start collector (./run_analysis.sh -d)
10:00:05 - Deploy cryptomining threat
10:00:30 - Mining process starts ✅ captured
10:00:45 - Network to mining pool ✅ captured
10:02:00 - Analysis runs
          ✅ Complete flow history available
          ✅ All malicious connections detected
```

## Cleanup

To remove deployed threats after testing:

```bash
cd threat_scenarios
./cleanup-all.sh
```

This removes all `threat-*` namespaces and their resources.

## Configuration

### Environment Variables

```bash
# Override Hubble endpoint
export HUBBLE_ENDPOINT="hubble-relay.kube-system.svc.cluster.local:443"
./run_analysis.sh -d
```

### Customizing Wait Time

Different threats have different trigger delays:

```yaml
# From empirical_detectable/crypto_mining/deployment.yaml
sleep 30  # Wait before mining starts
```

Adjust wait time to ensure all threats trigger:

```bash
# Wait 3 minutes for slower threats
./run_analysis.sh --deploy-threats --wait-time 180
```

## Troubleshooting

### "No flows collected"

**Check:**
1. Is Hubble running? `kubectl get pods -n kube-system | grep hubble`
2. Is endpoint reachable? `grpcurl hubble-api.lab.internal:443 list`
3. Check collector log: `cat output/hubble_collector.log`

### "Collector still running after script finishes"

**Cleanup manually:**
```bash
./tools/hubble_collector.sh output/hubble_flows.jsonl output/hubble_collector.log stop
```

### "Analysis uses live query instead of file"

**Possible causes:**
1. File doesn't exist (check `ls output/hubble_flows.jsonl`)
2. File is empty (collector failed to start)
3. Path mismatch (check collector output path)

Check what source was used:
```
[Hubble] Using pre-collected flows from output/hubble_flows.jsonl  # ✅ File
[Hubble] Querying live flows via gRPC                              # ⚠️ Live
```

## Performance Notes

- **Flow file size:** Varies by cluster traffic (can be 1-3GB for busy clusters)
- **Collector overhead:** Minimal CPU/memory (~10 MB RAM)
- **150-second collection:** Can collect millions of flows in busy clusters
- **Loading optimization:** By default, only the last 50,000 flows are loaded (most recent)
- **Retention:** Manual cleanup required (files not auto-deleted)

### Large Flow Files

For busy clusters, Hubble can collect millions of flows per minute. To handle this efficiently:

- **Default:** Loads last 50,000 flows (most recent during collection window)
- **Rationale:** Threat scenarios trigger during the collection window, so recent flows contain the malicious activity
- **Customization:** Set `max_flows` parameter in `fetch_hubble_flows_from_file()` to adjust
- **Performance:** Loading 50K flows takes seconds vs. hours for 100M+ flows

## Research Benefits

This approach ensures:
- ✅ **Reproducible experiments** - Capture complete test window
- ✅ **No timing issues** - Don't need to run analysis immediately
- ✅ **Complete data** - All network flows preserved
- ✅ **Flexible testing** - Toggle threats on/off as needed
- ✅ **Persistent evidence** - Flows saved for later review
