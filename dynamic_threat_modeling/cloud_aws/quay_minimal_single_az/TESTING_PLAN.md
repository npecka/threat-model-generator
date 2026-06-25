# Testing Plan for AWS Quay Deployment - Research Paper Data Collection

## Paper Context

From CSSP.tex, the paper validates the semi-automated threat modeling methodology by:
1. Deploying systems across 3 platforms (bare-metal, K8s, AWS)
2. Injecting 17 threats (T01-T17)
3. Running the framework to detect all threats
4. Comparing against 6 security tools (Trivy, Checkov, Kubelinter, Kubescape, Prowler, Docker Bench)
5. Demonstrating framework detects 17/17 (100%) vs tools detecting 1-8/17 (6-47%)

## Current Status

**Case Study 1 (Supply Chain):** Complete
- 7 components across 3 platforms
- 17 threats (T01-T17)
- Results in paper

**Case Study 2 (Quay):** Adding for scalability demonstration
- 20+ components vs 7 components
- Same 17 threats (T01-T17)
- AWS minimal deployment ready

## Testing Objectives

### Primary Goal
Demonstrate framework **scalability** from 7 → 20+ components while maintaining 100% threat detection.

### Secondary Goals
1. Update performance metrics table (Table: Cross-Platform Performance Metrics)
2. Maintain tool comparison results (validate tools still detect same threats)
3. Show consistent detection across larger system

## Data to Collect

### 1. Infrastructure Metrics (for Table update)

**Test Environment Hardware:**
- Infrastructure: 6 EC2 instances (vs 3 in CS1)
- Total CPU: 12 vCPUs (vs 6 in CS1)
- Total Memory: 6 GB (vs 3 GB in CS1)
- Instance Types: t3.micro (2 vCPU, 1 GB)

**Data Collection Tools:**
- Tools: VPC Flow Logs + boto3
- CPU Required: AWS-managed (hypervisor-level)
- Memory Required: AWS-managed

**Data Collection Overhead:**
- Collection Time: Measure actual seconds
- CPU During Collection: AWS hypervisor-level (not visible)
- Memory During Collection: AWS hypervisor-level (not visible)

**Threat Modeling Execution Time:**
- Data Extraction: Time to run boto3 queries
  - Network flow collection: VPC Flow Logs query time + delivery delay
  - Metadata collection: boto3 API query time (EC2, VPC, IAM, S3)
- Threat Analysis: Time to run correlation + Prowler
  - Tool scanning: Prowler + Checkov execution time
  - Correlation: Framework correlation time

**Resource Consumption:**
- Peak Memory: Peak during analysis
- Average CPU: CPU % during scan

### 2. Threat Detection Results

**Framework Detection (should be 17/17):**
Run framework analyzer to confirm all T01-T17 detected:
- T01: Security groups allow 0.0.0.0/0
- T02: IAM roles with S3:*, EC2:Describe*
- T03: HTTP-only (no TLS)
- T04: No network ACLs
- T05: S3 public buckets
- T06: IAM cross-zone permissions
- T07: No VPC Flow Logs, no CloudWatch
- T08: Secrets in user data, terraform.tfvars
- T09: Broad IAM permissions
- T10: No detailed monitoring
- T11: LLM API without auth
- T12: No training data validation
- T13: Open inference API
- T14: HTTP model downloads
- T15: LLM service has prod IAM
- T16: No model provenance
- T17: Model metadata in configs

**Tool Comparison (update Table: Comparative Threat Detection):**

Run each tool and map findings to T01-T17:

1. **Prowler** (AWS-specific):
   ```bash
   prowler aws --output-directory ./prowler-results
   # Map findings to threats
   ```
   Expected: ~8/17 (T01, T02, T03, T04, T05, T06, T07, T08)

2. **Checkov** (IaC scanner):
   ```bash
   checkov -d terraform/
   # Map findings to threats
   ```
   Expected: ~3/17 (T01, T03, T07)

3. **Trivy** (container/config scanner):
   ```bash
   trivy config terraform/
   # Map findings to threats
   ```
   Expected: ~1/17 (T07)

### 3. Scalability Metrics

**Component Count:**
- Case Study 1: 7 components
- Case Study 2: 20+ components (count exact number deployed)

**Threat Instances:**
- Case Study 1 AWS: All 17 types detected
- Case Study 2 AWS: Should detect all 17 types + count total instances

**Components to count:**
1. Quay Application × 2
2. PostgreSQL
3. Redis
4. Minio
5. Clair
6. LLM Service
7. NGINX Load Balancer
8. Plus: ConfigMaps, Secrets, IAM roles, Security Groups, S3 buckets

## Testing Procedure

### Phase 1: Deploy Infrastructure (15-20 min)

```bash
cd dynamic_threat_modeling/cloud_aws/quay_minimal_single_az/terraform

# Deploy
terraform init  # Already done
terraform apply  # Review plan, type 'yes'

# Verify all instances running
aws ec2 describe-instances --region us-east-1 \
  --filters "Name=tag:CaseStudy,Values=quay-minimal" \
  --query 'Reservations[*].Instances[*].[InstanceId,State.Name]'

# Get outputs
terraform output
```

### Phase 2: Wait for Services to Start (10-15 min)

```bash
# SSH into instances and check Docker containers
# Instance IPs from terraform output

# Check database instance
ssh -i ~/.ssh/quay-minimal-key ec2-user@<database-ip>
docker ps  # Should see postgres and redis

# Check storage instance  
ssh -i ~/.ssh/quay-minimal-key ec2-user@<storage-ip>
docker ps  # Should see minio and clair

# Check LLM instance
ssh -i ~/.ssh/quay-minimal-key ec2-user@<llm-ip>
ps aux | grep llama  # Should see LLM process

# Check load balancer
ssh -i ~/.ssh/quay-minimal-key ec2-user@<lb-ip>
docker ps  # Should see nginx
```

### Phase 3: Enable VPC Flow Logs (for runtime correlation)

```bash
# Create CloudWatch log group for VPC Flow Logs
aws logs create-log-group --log-group-name "/aws/vpc/flowlogs/quay-minimal" --region us-east-1

# Create IAM role for Flow Logs
# (Framework should handle this, or document manual steps)

# Enable VPC Flow Logs
VPC_ID=$(terraform output -raw vpc_id)
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids $VPC_ID \
  --traffic-type ALL \
  --log-destination-type cloud-watch-logs \
  --log-group-name "/aws/vpc/flowlogs/quay-minimal" \
  --region us-east-1

# Wait ~60 seconds for initial data
```

### Phase 4: Run Framework Analysis (5-10 min)

```bash
cd ../../../../platforms/cloud_aws/analyzer

# Run threat detection
python main.py --region us-east-1 --tag CaseStudy=quay-minimal

# Collect metrics:
# - Execution time
# - Threats detected
# - Threat instances count
```

### Phase 5: Run Tool Comparison (20-30 min)

```bash
# 1. Prowler (AWS security assessment)
cd ../../../dynamic_threat_modeling/cloud_aws/quay_minimal_single_az
prowler aws --output-directory ./prowler-results --region us-east-1
# Time: ~5-10 minutes
# Map findings to T01-T17

# 2. Checkov (Terraform IaC scan)
cd terraform
checkov -d . --output json > checkov-results.json
# Time: ~1 minute
# Map findings to T01-T17

# 3. Trivy (Config scan)
trivy config . --format json > trivy-results.json
# Time: ~1 minute
# Map findings to T01-T17
```

### Phase 6: Collect Performance Data

**Measure:**
1. Framework execution time (from logs)
2. Tool execution times (from command timing)
3. Resource consumption (monitor during execution)
4. Flow log delivery delay (check CloudWatch timestamps)

**Document:**
1. Total EC2 instance count: 6
2. Total vCPUs: 12
3. Total Memory: 6 GB
4. Component count: (count deployed containers/services)
5. Threat detection: Framework vs Tools comparison

### Phase 7: Cleanup (5 min)

```bash
# IMPORTANT: Destroy to stay within free tier
cd dynamic_threat_modeling/cloud_aws/quay_minimal_single_az/terraform

# Disable flow logs first
aws ec2 delete-flow-logs --flow-log-ids <id-from-creation>

# Destroy infrastructure
terraform destroy  # Type 'yes'

# Verify deletion
aws ec2 describe-instances --region us-east-1 \
  --filters "Name=tag:CaseStudy,Values=quay-minimal"

# Should return empty
```

## Expected Results

### For Paper

**Scalability Demonstration:**
| Metric | Case Study 1 | Case Study 2 |
|--------|--------------|--------------|
| Components | 7 | 20+ |
| EC2 Instances | 3 × t3.micro | 6 × t3.micro |
| vCPUs | 6 | 12 |
| Memory | 3 GB | 6 GB |
| Threats Detected | 17/17 (100%) | 17/17 (100%) |

**Tool Comparison (should be consistent):**
- Framework: 17/17 (100%)
- Prowler: ~8/17 (47%)
- Checkov: ~3/17 (18%)
- Trivy: ~1/17 (6%)

**Performance Metrics:**
- Data collection time: ~2-5s (boto3 queries)
- VPC Flow Log delay: ~50-60s
- Threat analysis time: ~5-15s
- Tool scanning time: ~5-10 minutes (Prowler dominant)

**Narrative:**
"To demonstrate scalability, we deployed a second case study with 20+ components (vs 7 in Case Study 1), requiring 2× the infrastructure resources (6 instances vs 3, 12 vCPUs vs 6). The framework maintained 100% threat detection accuracy across both deployments, validating that the platform-agnostic abstractions scale effectively with system complexity."

## Data Recording Template

```
# Case Study 2 (AWS Quay Minimal) - Test Results

Date: ___________
Tester: Nicholas Pecka

## Infrastructure
- Instances: 6 × t3.micro
- vCPUs: 12
- Memory: 6 GB
- Components: _____ (count actual)

## Framework Results
- Execution Time: _____ seconds
- Threats Detected: ___/17
- Threat Instances: _____ total
- Detection Rate: _____%

## Tool Comparison
- Prowler: ___/17 threats (time: ___ min)
- Checkov: ___/17 threats (time: ___ sec)
- Trivy: ___/17 threats (time: ___ sec)

## Performance Metrics
- Data Extraction: ___ s
  - boto3 queries: ___ s
  - VPC Flow Logs: ___ s delay
- Threat Analysis: ___ s
  - Tool scanning: ___ s
  - Correlation: ___ s
- Total Time: ___ s

## Notes
- Any issues encountered:
- Threat detection differences:
- Performance observations:
```

## Questions to Answer

1. **Does framework detect all 17 threats in larger system?** (Should be YES)
2. **How does execution time scale?** (Should be similar or slightly higher)
3. **Do tools detect same threats as CS1?** (Should be consistent)
4. **What's the exact component count?** (Need to count deployed services)

## Success Criteria

✅ Framework detects 17/17 threats (100%)
✅ Tools show similar detection rates (~6-47%)
✅ Performance metrics within reasonable bounds
✅ All data collected for paper tables
✅ Infrastructure destroyed within free tier limits

## Timeline

- **Deploy:** 20 minutes
- **Test:** 30-40 minutes
- **Tool comparison:** 20-30 minutes
- **Cleanup:** 5 minutes
- **Total:** ~90 minutes

**Recommendation:** Run test during a single session to minimize EC2 hours.
