#!/bin/bash
#
# Hubble Flow Collector - Continuous flow capture during analysis window
#
# This script runs in the background during threat scenario execution,
# collecting all Hubble network flows to a JSON file for later analysis.
#

set -e

# Configuration
OUTPUT_FILE="${1:-output/hubble_flows.jsonl}"
HUBBLE_ENDPOINT="${HUBBLE_ENDPOINT:-hubble-api.lab.internal:443}"
PID_FILE="/tmp/hubble_collector.pid"
LOG_FILE="${2:-output/hubble_collector.log}"

# Function to start collector
start_collector() {
    echo "🔍 Starting Hubble flow collector..."
    echo "   Endpoint: ${HUBBLE_ENDPOINT}"
    echo "   Output: ${OUTPUT_FILE}"
    echo "   Log: ${LOG_FILE}"

    # Check for existing grpcurl processes and clean them up
    EXISTING_GRPCURL=$(pgrep -f "grpcurl" 2>/dev/null | wc -l)
    if [ "${EXISTING_GRPCURL}" -gt 0 ]; then
        echo "   ⚠️  Found ${EXISTING_GRPCURL} existing grpcurl process(es). Cleaning up first..."
        pkill -f "grpcurl.*observer.Observer.GetFlows" 2>/dev/null || true
        sleep 1
        pkill -9 grpcurl 2>/dev/null || true
        echo "   ✅ Existing grpcurl processes terminated"
    fi

    # Ensure output directory exists
    mkdir -p "$(dirname "${OUTPUT_FILE}")"
    mkdir -p "$(dirname "${LOG_FILE}")"

    # Clear previous flows
    > "${OUTPUT_FILE}"

    # Start collecting in background
    # Using kubectl port-forward + grpcurl to stream flows
    (
        echo "$(date '+%Y-%m-%d %H:%M:%S') - Starting Hubble flow collection" >> "${LOG_FILE}"

        # Start kubectl port-forward in background
        kubectl port-forward -n kube-system svc/hubble-relay 4245:80 >> "${LOG_FILE}" 2>&1 &
        PORT_FORWARD_PID=$!
        echo "Port-forward PID: ${PORT_FORWARD_PID}" >> "${LOG_FILE}"

        # Wait for port-forward to be ready
        sleep 3

        # Find grpcurl (check local tools directory first, then PATH)
        GRPCURL=""
        SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

        if [ -x "${SCRIPT_DIR}/grpcurl" ]; then
            GRPCURL="${SCRIPT_DIR}/grpcurl"
            echo "Using local grpcurl: ${GRPCURL}" >> "${LOG_FILE}"
        elif command -v grpcurl > /dev/null 2>&1; then
            GRPCURL="grpcurl"
            echo "Using system grpcurl: $(which grpcurl)" >> "${LOG_FILE}"
        else
            echo "ERROR: grpcurl not found. Install with:" >> "${LOG_FILE}"
            echo "  cd tools && wget https://github.com/fullstorydev/grpcurl/releases/download/v1.9.1/grpcurl_1.9.1_linux_x86_64.tar.gz" >> "${LOG_FILE}"
            echo "  tar -xzf grpcurl_1.9.1_linux_x86_64.tar.gz && chmod +x grpcurl" >> "${LOG_FILE}"
            kill $PORT_FORWARD_PID 2>/dev/null || true
            exit 1
        fi

        # Stream flows with follow mode
        ${GRPCURL} -plaintext -format json \
            -d '{"follow": true, "number": 10000}' \
            localhost:4245 \
            observer.Observer.GetFlows >> "${OUTPUT_FILE}" 2>> "${LOG_FILE}"

        # Cleanup port-forward on exit
        kill $PORT_FORWARD_PID 2>/dev/null || true
    ) &

    # Save PID
    echo $! > "${PID_FILE}"
    echo "   ✅ Collector started (PID: $(cat ${PID_FILE}))"
    echo "   📊 Flows will be written to: ${OUTPUT_FILE}"
}

# Function to stop collector
stop_collector() {
    if [ -f "${PID_FILE}" ]; then
        PID=$(cat "${PID_FILE}")
        echo "🛑 Stopping Hubble flow collector (PID: ${PID})..."

        # Kill the process and all children (includes port-forward)
        pkill -P "${PID}" 2>/dev/null || true
        kill "${PID}" 2>/dev/null || true

        # Also kill any kubectl port-forward on port 4245
        pkill -f "kubectl port-forward.*hubble-relay.*4245" 2>/dev/null || true

        # CRITICAL: Explicitly kill any grpcurl processes (prevents orphaned processes)
        pkill -f "grpcurl.*observer.Observer.GetFlows" 2>/dev/null || true
        pkill grpcurl 2>/dev/null || true

        # Wait for graceful shutdown
        sleep 2

        # Force kill if still running
        kill -9 "${PID}" 2>/dev/null || true
        pkill -9 -f "grpcurl.*observer.Observer.GetFlows" 2>/dev/null || true

        rm -f "${PID_FILE}"

        echo "   ✅ Collector stopped"

        # Verify grpcurl processes are terminated
        REMAINING_GRPCURL=$(pgrep -f "grpcurl" 2>/dev/null | wc -l)
        if [ "${REMAINING_GRPCURL}" -gt 0 ]; then
            echo "   ⚠️  Warning: ${REMAINING_GRPCURL} grpcurl process(es) still running. Forcing termination..."
            pkill -9 grpcurl 2>/dev/null || true
        fi

        # Show collection summary
        if [ -f "${OUTPUT_FILE}" ]; then
            FLOW_COUNT=$(wc -l < "${OUTPUT_FILE}" 2>/dev/null || echo "0")
            FILE_SIZE=$(du -h "${OUTPUT_FILE}" | cut -f1)
            echo "   📊 Collected ${FLOW_COUNT} flows (${FILE_SIZE})"
        fi
    else
        echo "⚠️  Collector not running (no PID file found)"

        # Even without PID file, clean up any orphaned grpcurl processes
        echo "🔍 Checking for orphaned grpcurl processes..."
        ORPHANED_GRPCURL=$(pgrep -f "grpcurl" 2>/dev/null | wc -l)
        if [ "${ORPHANED_GRPCURL}" -gt 0 ]; then
            echo "   ⚠️  Found ${ORPHANED_GRPCURL} orphaned grpcurl process(es). Cleaning up..."
            pkill -f "grpcurl.*observer.Observer.GetFlows" 2>/dev/null || true
            sleep 1
            pkill -9 grpcurl 2>/dev/null || true
            echo "   ✅ Orphaned processes terminated"
        else
            echo "   ✅ No orphaned grpcurl processes found"
        fi
    fi
}

# Function to check status
status_collector() {
    if [ -f "${PID_FILE}" ]; then
        PID=$(cat "${PID_FILE}")
        if ps -p "${PID}" > /dev/null 2>&1; then
            FLOW_COUNT=$(wc -l < "${OUTPUT_FILE}" 2>/dev/null || echo "0")
            echo "✅ Collector running (PID: ${PID})"
            echo "   📊 Flows collected: ${FLOW_COUNT}"
            echo "   📁 Output: ${OUTPUT_FILE}"
        else
            echo "⚠️  Stale PID file (process not running)"
            rm -f "${PID_FILE}"
        fi
    else
        echo "❌ Collector not running"
    fi
}

# Main command dispatcher
case "${3:-start}" in
    start)
        start_collector
        ;;
    stop)
        stop_collector
        ;;
    status)
        status_collector
        ;;
    restart)
        stop_collector
        sleep 1
        start_collector
        ;;
    *)
        echo "Usage: $0 [output_file] [log_file] {start|stop|status|restart}"
        echo ""
        echo "Arguments:"
        echo "  output_file  - Path to store collected flows (default: output/hubble_flows.jsonl)"
        echo "  log_file     - Path to store collector logs (default: output/hubble_collector.log)"
        echo ""
        echo "Commands:"
        echo "  start   - Start flow collection in background"
        echo "  stop    - Stop flow collection"
        echo "  status  - Check collector status"
        echo "  restart - Restart collector"
        echo ""
        echo "Environment Variables:"
        echo "  HUBBLE_ENDPOINT - Hubble API endpoint (default: hubble-api.lab.internal:443)"
        exit 1
        ;;
esac
