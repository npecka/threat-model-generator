#!/bin/bash
# Run all security scanning tools and collect results for comparison
# This script compares Trivy, Checkov, and KubeLinter against our methodology

set -e

RESULTS_DIR="results/tool_comparison"
mkdir -p $RESULTS_DIR

echo "=========================================="
echo "Security Tool Comparison Script"
echo "=========================================="
echo ""

# Check if tools are installed
echo "Checking tool availability..."

if ! command -v trivy &> /dev/null; then
    echo "❌ Trivy not found. Install with: brew install trivy"
    echo "   or visit: https://aquasecurity.github.io/trivy/"
    TRIVY_AVAILABLE=false
else
    echo "✓ Trivy found: $(trivy --version | head -1)"
    TRIVY_AVAILABLE=true
fi

if ! command -v checkov &> /dev/null; then
    echo "❌ Checkov not found. Install with: pip install checkov"
    CHECKOV_AVAILABLE=false
else
    echo "✓ Checkov found: $(checkov --version)"
    CHECKOV_AVAILABLE=true
fi

if ! command -v kube-linter &> /dev/null; then
    echo "❌ KubeLinter not found. Install with: brew install kube-linter"
    echo "   or visit: https://github.com/stackrox/kube-linter"
    KUBELINTER_AVAILABLE=false
else
    echo "✓ KubeLinter found: $(kube-linter version)"
    KUBELINTER_AVAILABLE=true
fi

echo ""
echo "=========================================="
echo "Running Security Scans"
echo "=========================================="
echo ""

# Trivy Scans
if [ "$TRIVY_AVAILABLE" = true ]; then
    echo "=== Running Trivy on Kubernetes manifests ==="
    trivy config dynamic_threat_modeling/kubernetes/supply_chain/ \
      --format json \
      --severity HIGH,CRITICAL \
      -o $RESULTS_DIR/trivy-k8s.json \
      2>&1 | tee $RESULTS_DIR/trivy-k8s.log
    echo "✓ Trivy Kubernetes scan complete"
    echo ""

    echo "=== Running Trivy on AWS Terraform ==="
    trivy config dynamic_threat_modeling/cloud_aws/supply_chain/terraform/ \
      --format json \
      --severity HIGH,CRITICAL \
      -o $RESULTS_DIR/trivy-aws.json \
      2>&1 | tee $RESULTS_DIR/trivy-aws.log
    echo "✓ Trivy AWS scan complete"
    echo ""

    echo "=== Running Trivy on Bare-metal Docker Compose ==="
    trivy config dynamic_threat_modeling/bare_metal/supply_chain/docker-compose/ \
      --format json \
      --severity HIGH,CRITICAL \
      -o $RESULTS_DIR/trivy-baremetal.json \
      2>&1 | tee $RESULTS_DIR/trivy-baremetal.log
    echo "✓ Trivy Bare-metal scan complete"
    echo ""
else
    echo "⊘ Skipping Trivy scans (not installed)"
    echo ""
fi

# Checkov Scans
if [ "$CHECKOV_AVAILABLE" = true ]; then
    echo "=== Running Checkov on Kubernetes manifests ==="
    checkov -d dynamic_threat_modeling/kubernetes/supply_chain/ \
      --framework kubernetes \
      --compact \
      -o json \
      --output-file-path $RESULTS_DIR \
      --repo-id k8s-supply-chain \
      2>&1 | tee $RESULTS_DIR/checkov-k8s.log
    # Checkov creates results_json.json, rename it
    if [ -f "$RESULTS_DIR/results_json.json" ]; then
        mv $RESULTS_DIR/results_json.json $RESULTS_DIR/checkov-k8s.json
    fi
    echo "✓ Checkov Kubernetes scan complete"
    echo ""

    echo "=== Running Checkov on AWS Terraform ==="
    checkov -d dynamic_threat_modeling/cloud_aws/supply_chain/terraform/ \
      --framework terraform \
      --compact \
      -o json \
      --output-file-path $RESULTS_DIR \
      --repo-id aws-supply-chain \
      2>&1 | tee $RESULTS_DIR/checkov-aws.log
    # Rename results file
    if [ -f "$RESULTS_DIR/results_json.json" ]; then
        mv $RESULTS_DIR/results_json.json $RESULTS_DIR/checkov-aws.json
    fi
    echo "✓ Checkov AWS scan complete"
    echo ""

    echo "=== Running Checkov on Bare-metal Docker Compose ==="
    checkov -d dynamic_threat_modeling/bare_metal/supply_chain/docker-compose/ \
      --framework docker_compose \
      --compact \
      -o json \
      --output-file-path $RESULTS_DIR \
      --repo-id baremetal-supply-chain \
      2>&1 | tee $RESULTS_DIR/checkov-baremetal.log
    # Rename results file
    if [ -f "$RESULTS_DIR/results_json.json" ]; then
        mv $RESULTS_DIR/results_json.json $RESULTS_DIR/checkov-baremetal.json
    fi
    echo "✓ Checkov Bare-metal scan complete"
    echo ""
else
    echo "⊘ Skipping Checkov scans (not installed)"
    echo ""
fi

# KubeLinter Scan
if [ "$KUBELINTER_AVAILABLE" = true ]; then
    echo "=== Running KubeLinter on Kubernetes manifests ==="
    kube-linter lint dynamic_threat_modeling/kubernetes/supply_chain/ \
      --format json \
      > $RESULTS_DIR/kubelinter-k8s.json \
      2>&1 || true  # KubeLinter exits with error if issues found
    echo "✓ KubeLinter scan complete"
    echo ""
else
    echo "⊘ Skipping KubeLinter scan (not installed)"
    echo ""
fi

echo "=========================================="
echo "Scan Results Summary"
echo "=========================================="
echo ""
echo "Results saved to: $RESULTS_DIR/"
echo ""
ls -lh $RESULTS_DIR/
echo ""

# Generate quick summary
echo "Quick Summary:"
echo ""

if [ "$TRIVY_AVAILABLE" = true ]; then
    K8S_COUNT=$(jq -r '[.Results[]?.Misconfigurations[]?] | length' $RESULTS_DIR/trivy-k8s.json 2>/dev/null || echo "0")
    AWS_COUNT=$(jq -r '[.Results[]?.Misconfigurations[]?] | length' $RESULTS_DIR/trivy-aws.json 2>/dev/null || echo "0")
    BM_COUNT=$(jq -r '[.Results[]?.Misconfigurations[]?] | length' $RESULTS_DIR/trivy-baremetal.json 2>/dev/null || echo "0")
    echo "Trivy findings:"
    echo "  - Kubernetes: $K8S_COUNT misconfigurations"
    echo "  - AWS: $AWS_COUNT misconfigurations"
    echo "  - Bare-metal: $BM_COUNT misconfigurations"
fi

if [ "$CHECKOV_AVAILABLE" = true ]; then
    K8S_FAILED=$(jq -r '.results.failed_checks | length' $RESULTS_DIR/checkov-k8s.json 2>/dev/null || echo "0")
    AWS_FAILED=$(jq -r '.results.failed_checks | length' $RESULTS_DIR/checkov-aws.json 2>/dev/null || echo "0")
    BM_FAILED=$(jq -r '.results.failed_checks | length' $RESULTS_DIR/checkov-baremetal.json 2>/dev/null || echo "0")
    echo "Checkov findings:"
    echo "  - Kubernetes: $K8S_FAILED failed checks"
    echo "  - AWS: $AWS_FAILED failed checks"
    echo "  - Bare-metal: $BM_FAILED failed checks"
fi

if [ "$KUBELINTER_AVAILABLE" = true ]; then
    ISSUES=$(jq -r '.Reports | length' $RESULTS_DIR/kubelinter-k8s.json 2>/dev/null || echo "0")
    echo "KubeLinter findings:"
    echo "  - Kubernetes: $ISSUES issues"
fi

echo ""
echo "=========================================="
echo "Next Steps"
echo "=========================================="
echo ""
echo "1. Review raw results in: $RESULTS_DIR/"
echo "2. Run parser to map findings to T01-T10:"
echo "   python tools/comparison/parse_tool_results.py"
echo "3. Generate comparison table for paper"
echo ""
echo "✓ All scans complete!"
