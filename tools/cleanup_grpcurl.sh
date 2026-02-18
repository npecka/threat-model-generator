#!/bin/bash
#
# Emergency Cleanup Script for Orphaned grpcurl Processes
#
# This script forcefully terminates all grpcurl processes that may have
# been left running after hubble_collector.sh failures or interruptions.
#
# Usage:
#   ./cleanup_grpcurl.sh           # Check and cleanup grpcurl processes
#   ./cleanup_grpcurl.sh --force   # Force kill without confirmation
#

set -e

FORCE_MODE=false

# Parse arguments
if [ "$1" = "--force" ] || [ "$1" = "-f" ]; then
    FORCE_MODE=true
fi

echo "🔍 Scanning for grpcurl processes..."
echo ""

# Find all grpcurl processes
GRPCURL_PIDS=$(pgrep -f "grpcurl" 2>/dev/null || true)
GRPCURL_COUNT=$(echo "${GRPCURL_PIDS}" | grep -v "^$" | wc -l)

if [ "${GRPCURL_COUNT}" -eq 0 ]; then
    echo "✅ No grpcurl processes found. System is clean."
    echo ""

    # Also check kubectl port-forward processes
    PORT_FORWARD_COUNT=$(pgrep -f "kubectl port-forward.*hubble-relay.*4245" 2>/dev/null | wc -l)
    if [ "${PORT_FORWARD_COUNT}" -gt 0 ]; then
        echo "⚠️  Found ${PORT_FORWARD_COUNT} kubectl port-forward process(es) for Hubble"
        if [ "$FORCE_MODE" = true ]; then
            pkill -f "kubectl port-forward.*hubble-relay.*4245" 2>/dev/null || true
            echo "✅ Port-forward processes terminated"
        else
            echo "Run with --force to clean these up"
        fi
    fi

    exit 0
fi

echo "⚠️  Found ${GRPCURL_COUNT} grpcurl process(es):"
echo ""

# Show process details
ps aux | grep grpcurl | grep -v grep || true
echo ""

# Show disk usage (if outputting to files)
echo "📊 Checking for large output files..."
LARGE_FILES=$(find /mnt/c/Users/*/Documents/GitHub/osd-mapper/output -name "*.jsonl" -size +100M 2>/dev/null || true)
if [ -n "${LARGE_FILES}" ]; then
    echo ""
    echo "⚠️  Large output files detected (may indicate runaway process):"
    du -h ${LARGE_FILES}
    echo ""
fi

# Confirm cleanup (unless force mode)
if [ "$FORCE_MODE" = false ]; then
    echo "Do you want to terminate these processes? [y/N]"
    read -r CONFIRM
    if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ]; then
        echo "❌ Cleanup cancelled"
        exit 0
    fi
fi

echo ""
echo "🛑 Terminating grpcurl processes..."

# Graceful termination first
pkill -f "grpcurl.*observer.Observer.GetFlows" 2>/dev/null || true
pkill grpcurl 2>/dev/null || true

# Wait for graceful shutdown
sleep 2

# Force kill any remaining
REMAINING=$(pgrep -f "grpcurl" 2>/dev/null | wc -l)
if [ "${REMAINING}" -gt 0 ]; then
    echo "   ⚠️  ${REMAINING} process(es) still running. Force killing..."
    pkill -9 grpcurl 2>/dev/null || true
fi

# Also clean up kubectl port-forward
echo "🛑 Cleaning up kubectl port-forward processes..."
pkill -f "kubectl port-forward.*hubble-relay.*4245" 2>/dev/null || true

# Verify cleanup
sleep 1
FINAL_COUNT=$(pgrep -f "grpcurl" 2>/dev/null | wc -l)

if [ "${FINAL_COUNT}" -eq 0 ]; then
    echo ""
    echo "✅ All grpcurl processes terminated successfully"
    echo ""

    # Check disk space recovery
    echo "💾 Current disk usage on C: drive:"
    df -h /mnt/c/ | tail -1
    echo ""
else
    echo ""
    echo "❌ Warning: ${FINAL_COUNT} grpcurl process(es) still running"
    echo "   Manual intervention may be required"
    echo ""
fi
