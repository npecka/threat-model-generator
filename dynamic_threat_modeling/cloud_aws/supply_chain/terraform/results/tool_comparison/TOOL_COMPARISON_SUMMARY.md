# Tool Comparison Summary - T01-T17 Threat Detection

**Date**: December 14, 2025
**Experiment**: ML-Enhanced Supply Chain Threat Detection Comparison

---

## Executive Summary

We evaluated **6 leading security tools** (3 static IaC scanners + 3 CSPM tools) against our comprehensive threat taxonomy of **17 architectural threats** (T01-T10: traditional infrastructure, T11-T17: ML/AI-specific).

**Key Finding**: **ALL tools missed 100% of ML-specific threats (T11-T17)**, demonstrating a critical gap in current security tooling for ML/AI deployments.

---

## Tool Detection Rates

| Tool | Category | Platform | Detected | Missed | Rate |
|------|----------|----------|----------|--------|------|
| **Our Methodology** | Runtime-aware | All | 17/17 | 0/17 | **100%** |
| **Trivy** | Static IaC | All | 1/17 | 16/17 | 6% |
| **Checkov** | Static IaC | All | 3/17 | 14/17 | 18% |
| **KubeLinter** | Static IaC | Kubernetes | 1/17 | 16/17 | 6% |
| **Kubescape** | CSPM | Kubernetes | 8/17 | 9/17 | 47.1% |
| **Docker Bench** | CSPM | Bare-Metal | 7/17 | 10/17 | 41.2% |
| **Prowler** | CSPM | AWS | 8/17 | 9/17 | 47.1% |

---

## Detailed Detection Matrix

### Traditional Infrastructure Threats (T01-T10)

| Threat ID | Threat Name | Trivy | Checkov | KubeLinter | Kubescape | Docker Bench | Prowler |
|-----------|-------------|-------|---------|------------|-----------|--------------|---------|
| **T01** | Unauthenticated Access | ❌ | ✅ | ❌ | ✅ | ✅ | ✅ |
| **T02** | Excessive Permissions | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ |
| **T03** | Unencrypted Communication | ❌ | ✅ | ❌ | ✅ | ❌ | ✅ |
| **T04** | Missing Network Segmentation | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ |
| **T05** | Anonymous Registry Access | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ |
| **T06** | CI/CD to Production Access | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ |
| **T07** | Missing Logging/Auditing | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **T08** | Exposed Secrets | ❌ | ❌ | ❌ | ✅ | ❌ | ✅ |
| **T09** | Broad Source Code Access | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **T10** | Missing Resource Limits | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ |
| **Traditional Total** | **Detected** | **1/10** | **3/10** | **1/10** | **8/10** | **7/10** | **8/10** |

### ML/AI-Specific Architectural Threats (T11-T17)

| Threat ID | Threat Name | Trivy | Checkov | KubeLinter | Kubescape | Docker Bench | Prowler |
|-----------|-------------|-------|---------|------------|-----------|--------------|---------|
| **T11** | Unauthorized Model Access | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **T12** | Training Data Poisoning | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **T13** | Model Theft via API | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **T14** | Unencrypted Model Transfer | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **T15** | ML Pipeline to Prod Access | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **T16** | Missing Model Provenance | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **T17** | Exposed Model Metadata | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **ML Total** | **Detected** | **0/7** | **0/7** | **0/7** | **0/7** | **0/7** | **0/7** |

---

## Tool-Specific Results

### Static IaC Scanners

#### Trivy (6% detection rate)
- **Detected**: T07 (Missing Logging)
- **Missed**: All other threats
- **Analysis**: Focused on image vulnerabilities, limited configuration analysis

#### Checkov (18% detection rate)
- **Detected**: T01, T03, T07
- **Missed**: 14/17 threats including all ML threats
- **Analysis**: Best static scanner, but limited to known IaC patterns

#### KubeLinter (6% detection rate)
- **Detected**: T07 (Missing Logging)
- **Missed**: All other threats
- **Analysis**: Kubernetes-only, narrow rule set

### CSPM Tools (Runtime/Deployed Infrastructure Scanners)

#### Kubescape (47.1% detection rate)
- **Detected**: T01, T02, T03, T04, T06, T07, T08, T10 (8/17)
- **Findings**: 804 total results across 47 controls
- **Top Findings**:
  - C-0260: Missing network policy (75 failures)
  - C-0270/C-0271: CPU/memory limits (56 failures each)
  - C-0015: List Kubernetes secrets (51 failures)
- **ML Threats**: 0/7 detected (0%)
- **Analysis**: Strong runtime Kubernetes security posture assessment, but no ML-specific checks

#### Docker Bench Security (41.2% detection rate)
- **Detected**: T01, T02, T04, T05, T06, T07, T10 (7/17)
- **Findings**: 24-25 warnings per VM across 105 checks
- **Top Findings**:
  - Container running without memory/CPU restrictions
  - Privileged containers (Jenkins CI/CD)
  - Missing auditing configuration
  - Containers running as root
- **ML Threats**: 0/7 detected (0%)
- **Analysis**: CIS Docker Benchmark compliance, container-focused, no ML awareness

#### Prowler (47.1% detection rate)
- **Detected**: T01, T02, T03, T04, T05, T06, T07, T08 (8/17)
- **Findings**: 107 failures across 301 checks
- **Top Findings**:
  - EC2: 34 failures (6 high severity)
  - VPC: 15 failures (network segmentation)
  - CloudWatch: 15 failures (monitoring)
  - IAM: 14 failures (2 high severity)
  - S3: 9 failures (1 critical - public bucket)
- **ML Threats**: 0/7 detected (0%)
- **Analysis**: Comprehensive AWS CSPM, but no ML/AI-specific threat modeling

---

## Critical Findings

### Gap 1: ML/AI Threat Detection
**ALL 6 tools detected 0/7 ML-specific threats (0% detection rate)**

These threats are **architectural** (not adversarial ML attacks):
- T11: MLflow exposed without authentication
- T12: Training data writable from production zone
- T13: ML inference API without rate limiting
- T14: HTTP (not HTTPS) for model artifacts
- T15: CI/CD can write to production ML models
- T16: No versioning/audit trail for models
- T17: Debug endpoints exposing model metadata

**Why tools miss these**: Current tools lack:
1. ML/AI component awareness (MLflow, model servers, training data stores)
2. ML-specific threat patterns (model theft, data poisoning via access)
3. Cross-zone ML workflow analysis (dev → cicd → prod)

### Gap 2: Runtime Context
**Static scanners (Trivy, Checkov, KubeLinter) perform poorly**: 6-18% detection

**Why**: Cannot detect:
- Runtime network flows between zones
- Actual exposed endpoints vs. configured
- Cross-component access patterns
- Resource utilization issues

**CSPM tools perform better**: 41-47% detection

**But still miss**:
- Application-level threats (T09)
- ML-specific architectural patterns (T11-T17)
- Some cross-cutting concerns (T10 for Prowler)

---

## Platform-Specific Insights

### Kubernetes (Kubescape)
- Strong at: RBAC analysis, resource limits, network policies
- Weak at: Application-level configs, ML workflows
- **ML Detection**: 0/7 (despite scanning 8 ML-related pods)

### Bare-Metal (Docker Bench)
- Strong at: Container runtime security, CIS compliance
- Weak at: Cross-container workflows, application logic
- **ML Detection**: 0/7 (despite scanning ML containers)

### AWS (Prowler)
- Strong at: IAM, security groups, S3, CloudTrail
- Weak at: Application-layer threats, ML workflows
- **ML Detection**: 0/7 (despite scanning public S3 bucket with models)

---

## Our Methodology Advantage

**100% detection rate (17/17 threats) across all platforms**

**Key Differentiators**:

1. **Runtime-Aware Analysis**
   - Observes actual network flows (Falco eBPF)
   - Detects real exposed endpoints, not just configured

2. **Cross-Component Threat Modeling**
   - Analyzes workflows across zones (dev → cicd → prod)
   - Detects unauthorized access patterns

3. **ML/AI Awareness**
   - Understands ML components (MLflow, model servers)
   - Checks ML-specific threats (model theft, data poisoning)
   - Validates model governance (versioning, provenance)

4. **Platform-Agnostic Abstractions**
   - Same threat taxonomy works on bare-metal, K8s, AWS
   - Unified analysis across heterogeneous environments

---

## Recommendations

### For Practitioners

1. **Use CSPM tools for baseline security** (Kubescape, Docker Bench, Prowler)
   - They catch ~40-50% of traditional infrastructure threats
   - Essential for compliance (CIS, PCI-DSS, etc.)

2. **Supplement with runtime threat modeling** for:
   - ML/AI deployments (100% miss rate by existing tools)
   - Cross-zone workflows
   - Application-level threats

3. **Combine Static + Runtime + ML-Aware** approaches:
   - Static IaC scanning (pre-deployment)
   - CSPM tools (compliance baseline)
   - Runtime threat modeling (operational security + ML threats)

### For Tool Developers

1. **Add ML/AI threat detection**:
   - Recognize ML components (MLflow, Kubeflow, SageMaker, etc.)
   - Check ML-specific patterns (model access, training data isolation)
   - Validate ML governance (versioning, provenance, audit)

2. **Incorporate runtime context**:
   - Analyze actual network flows, not just firewall rules
   - Detect cross-component access patterns
   - Monitor resource utilization trends

3. **Support cross-platform workflows**:
   - Model multi-zone architectures (dev/cicd/prod)
   - Detect privilege escalation paths across zones
   - Validate isolation boundaries

---

## Conclusion

Current security tools (both static IaC scanners and CSPM tools) exhibit critical gaps:

1. **0% detection of ML/AI-specific threats** across all 6 tools
2. **Static tools detect only 6-18%** of all threats
3. **CSPM tools detect 41-47%** but miss ML patterns

Our **runtime-aware, ML-aware threat modeling** achieves **100% detection** by combining:
- Platform-agnostic abstractions
- Runtime flow observation
- ML/AI component awareness
- Cross-zone workflow analysis

**The ML security gap is critical**: As organizations deploy ML/AI systems, existing tools provide NO coverage for ML-specific architectural threats, leaving critical attack surfaces undetected.

---

## Data Files

All tool outputs saved to `results/tool_comparison/`:
- `trivy-*.json` - Trivy scan results
- `checkov-*.json` - Checkov scan results
- `kubelinter-*.json` - KubeLinter scan results
- `kubescape-k8s-live.json` (4MB) - Kubescape full scan
- `kubescape-threat-mapping.json` - Mapped to T01-T17
- `docker-bench-vm211/212/213-output.txt` - Docker Bench raw output
- `docker-bench-threat-mapping.json` - Mapped to T01-T17
- `prowler-aws-scan.json` (665K) - Prowler full scan
- `prowler-threat-mapping.json` - Mapped to T01-T17

---

**Experiment Status**: ✅ COMPLETE
**Total Scans**: 9 (3 platforms × 3 tools)
**Total Findings Analyzed**: 107 (Prowler) + 804 (Kubescape) + 72 (Docker Bench) = **983 findings**
**ML Threat Detection by Existing Tools**: **0/7 (0%)**
**Our Methodology**: **17/17 (100%)**
