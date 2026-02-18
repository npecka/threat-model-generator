# Security Tool Comparison

This directory contains scripts to compare our dynamic threat modeling methodology against existing security scanning tools.

## Quick Start

### 1. Install Required Tools

**Option A: Using Homebrew (macOS/Linux)**
```bash
brew install trivy kube-linter
pip install checkov
```

**Option B: Manual Installation**

- **Trivy**: https://aquasecurity.github.io/trivy/latest/getting-started/installation/
- **Checkov**: `pip install checkov`
- **KubeLinter**: https://github.com/stackrox/kube-linter#installing-kubelinter

### 2. Run All Tools

```bash
cd k8s-threat-model-generator
bash tools/comparison/run_all_tools.sh
```

This will:
- Scan Kubernetes manifests in `case_studies/kubernetes/supply_chain/`
- Scan AWS Terraform configs in `case_studies/cloud_aws/supply_chain/terraform/`
- Save JSON results to `results/tool_comparison/`

### 3. Parse Results

```bash
python tools/comparison/parse_tool_results.py
```

This will:
- Map tool findings to T01-T10 threat taxonomy
- Generate comparison tables in Markdown and LaTeX
- Print summary statistics

## Output Files

After running the scripts, you'll have:

```
results/tool_comparison/
├── trivy-k8s.json          # Trivy Kubernetes scan results
├── trivy-aws.json          # Trivy AWS scan results
├── checkov-k8s.json        # Checkov Kubernetes scan results
├── checkov-aws.json        # Checkov AWS scan results
├── kubelinter-k8s.json     # KubeLinter scan results
├── comparison_table.md     # Markdown comparison table
└── comparison_table.tex    # LaTeX comparison table (for paper)
```

## Adding to Your Paper

Copy the contents of `results/tool_comparison/comparison_table.tex` into your paper's Section 4.3.

See `TOOL_COMPARISON_PLAN.md` for detailed integration instructions.

## What Each Tool Does

| Tool | Focus | Platforms Supported | Key Strengths |
|------|-------|---------------------|---------------|
| **Trivy** | Container images, IaC configs | K8s, Terraform, Docker | CVE scanning, wide format support |
| **Checkov** | Policy-as-code IaC scanning | K8s, Terraform, CloudFormation | Extensive policy library |
| **KubeLinter** | Kubernetes best practices | Kubernetes only | K8s-specific production readiness checks |
| **Your Tool** | Runtime architectural threats | All (bare-metal, K8s, AWS) | Runtime correlation, cross-component analysis |

## Expected Results

Based on the T01-T10 taxonomy:

- **Your Tool**: 10/10 threats (100% coverage)
- **Trivy**: ~4-5/10 threats (static config issues)
- **Checkov**: ~5-6/10 threats (IaC policy violations)
- **KubeLinter**: ~4/10 threats (K8s best practices)

**Key insight**: Existing tools miss architectural threats (T03, T06, T09) and runtime-validated threats (T04, T07) that require correlating configuration with runtime behavior.

## Troubleshooting

### Tools not found
```bash
# Check if tools are in PATH
which trivy checkov kube-linter

# Install missing tools (see section 1 above)
```

### Permission denied
```bash
chmod +x tools/comparison/run_all_tools.sh
chmod +x tools/comparison/parse_tool_results.py
```

### JSON parsing errors
Some tools may not output valid JSON if no issues are found. This is normal - the parser handles empty/missing files gracefully.

## Next Steps

After generating comparison results:

1. Review `results/tool_comparison/comparison_table.tex`
2. Integrate into paper Section 4.3 (see `TOOL_COMPARISON_PLAN.md`)
3. Update abstract and conclusion to mention comparative evaluation
4. Discuss unique value proposition in Section 4.3.3

## Contact

Questions? Contact: nicholaspecka@unt.edu
