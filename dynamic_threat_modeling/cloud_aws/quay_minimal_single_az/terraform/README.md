# AWS Quay Minimal Single-AZ Deployment (FREE TIER OPTIMIZED)

## Overview

This Terraform configuration deploys **Project Quay** in a **maximized free-tier single-AZ configuration** to demonstrate framework scalability from 7 components (Case Study 1) to 20+ components (Case Study 2) while staying within AWS free tier limits.

## Architecture

### Key Design Principles

1. **Paradigm Consistency**: All services run in Docker containers (same as bare-metal and K8s)
2. **Free Tier Maximization**: Uses maximum instances while staying under 750 hours/month limit
3. **Single-AZ**: No multi-AZ complexity (excludes T18-T21 HA threats)
4. **No Managed Services**: PostgreSQL and Redis in Docker (not RDS/ElastiCache)

### Infrastructure

```
6 × t3.micro EC2 instances (Single-AZ: us-east-1a)
Total Resources: 12 vCPUs, 6 GB RAM, 180 GB storage
Components: 20+
Threats: T01-T17
```

### Instance Distribution

| Instance | Role | Services | Ports |
|----------|------|----------|-------|
| 1 | Quay App Primary | Quay (Docker) | 8080 |
| 2 | Quay App Secondary | Quay (Docker) | 8080 |
| 3 | Database & Cache | PostgreSQL + Redis (Docker) | 5432, 6379 |
| 4 | Storage & Scanner | Minio + Clair (Docker) | 9000, 9001, 6060 |
| 5 | LLM Service | llama-cpp-python | 8000 |
| 6 | Load Balancer | NGINX (Docker) | 80 |

### Network Architecture

- **1 VPC**: 10.0.0.0/16
- **1 Public Subnet**: Direct internet access (no NAT gateway)
- **1 Security Group**: Shared across all instances (demonstrates T04)
- **Internet Gateway**: For outbound/inbound traffic

## Free Tier Coverage

### What's Free

✅ **EC2 Instances**: 750 hours/month of t3.micro
- 6 instances × 24 hours × 5 days = 720 hours (under limit)
- **Cost: $0** if testing ≤ 5 days

✅ **EBS Storage**: 30 GB free tier
- 6 × 30 GB = 180 GB total
- **Cost: ~$9/month** if kept running ($0.10/GB-month × 150 GB over limit)
- **Cost: $0** if deleted within free tier period

✅ **Data Transfer**: 100 GB/month free
- Typical usage: 5-10 GB for testing
- **Cost: $0**

✅ **S3 Storage**: 5 GB free tier
- Minimal usage for testing
- **Cost: $0**

✅ **VPC**: No charge for VPC, subnets, route tables, internet gateway

### What's NOT Used (Cost Avoidance)

❌ **NAT Gateway**: ~$32/month + data charges - **NOT DEPLOYED**
❌ **Application Load Balancer**: ~$20/month - **NOT DEPLOYED** (using NGINX instead)
❌ **ElastiCache**: ~$13/month minimum - **NOT DEPLOYED** (using containerized Redis)
❌ **RDS Aurora**: Not free tier - **NOT DEPLOYED** (using containerized PostgreSQL)
❌ **Multi-AZ**: Double the instances - **NOT DEPLOYED**

### Total Estimated Cost

**5 days of testing**: **$0** (within free tier limits)
**1 month continuous**: **~$9** (EBS storage overage only)

**Important**: Delete all resources after testing to stay at $0!

## Comparison to Previous Deployment

| Metric | Case Study 1 (Supply Chain) | Case Study 2 (Quay Minimal) |
|--------|------------------------------|------------------------------|
| **Components** | 7 | 20+ |
| **EC2 Instances** | 3 × t3.micro | 6 × t3.micro |
| **Total vCPUs** | 6 | 12 |
| **Total Memory** | 3 GB | 6 GB |
| **Deployment** | Single-AZ | Single-AZ |
| **Services** | Managed (some) | All containerized |
| **Threats** | T01-T17 | T01-T17 |
| **Free Tier** | Yes | Yes |

**Scalability Demonstration**: 2× instances, 2× resources, 3× components

## Injected Threats

This deployment includes all 17 core threats:

### Traditional Infrastructure (T01-T10)
- **T01**: Unauthenticated External Access - Security groups allow 0.0.0.0/0
- **T02**: Excessive Permissions - IAM roles with S3:*, EC2:Describe*
- **T03**: Unencrypted Communication - HTTP only, no TLS
- **T04**: Missing Network Segmentation - Single security group, no network ACLs
- **T05**: Anonymous Registry Access - S3 bucket publicly accessible
- **T06**: CI/CD to Production Access - IAM roles grant broad permissions
- **T07**: Missing Audit Logging - No VPC Flow Logs, no CloudWatch
- **T08**: Exposed Secrets - Passwords in user data, environment variables, logs
- **T09**: Overly Broad Access - IAM wildcards
- **T10**: Missing Resource Limits - No CloudWatch monitoring, no container limits

### ML/AI-Specific (T11-T17)
- **T11**: Unauthorized Model Access - LLM API without authentication
- **T12**: Training Data Poisoning - No validation (simulated)
- **T13**: Model Theft via API - Open inference API
- **T14**: Unencrypted Model Transfer - HTTP download
- **T15**: ML Pipeline to Production Access - LLM service has IAM permissions
- **T16**: Missing Model Provenance - No tracking
- **T17**: Exposed Model Metadata - Config files contain model details

### Excluded Threats
- **T18-T21**: HA-specific threats (require multi-AZ deployment)

## Prerequisites

### 1. AWS Account Setup

- AWS free tier account (within 12 months of creation for EC2 free tier)
- AWS CLI installed and configured
- Terraform installed (>= 1.0)

### 2. SSH Key Pair

Generate an SSH key pair:
```bash
ssh-keygen -t rsa -b 4096 -f ~/.ssh/quay-minimal-key
```

The public key (`~/.ssh/quay-minimal-key.pub`) goes in `terraform.tfvars`

### 3. AWS Credentials

Configure AWS CLI:
```bash
aws configure
```

Provide:
- AWS Access Key ID
- AWS Secret Access Key
- Default region: `us-east-1`
- Default output format: `json`

## Deployment Steps

### 1. Configure Variables

```bash
cd dynamic_threat_modeling/cloud_aws/quay_minimal_single_az/terraform

# Copy example tfvars
cp terraform.tfvars.example terraform.tfvars

# Edit terraform.tfvars
nano terraform.tfvars
```

**Required changes:**
- Set `ssh_public_key` to your public key from `~/.ssh/quay-minimal-key.pub`

### 2. Initialize Terraform

```bash
terraform init
```

### 3. Review Plan

```bash
terraform plan
```

**Expected resources**: ~20-25 resources
- 1 VPC
- 1 Subnet
- 1 Internet Gateway
- 1 Route Table
- 1 Security Group
- 6 EC2 instances
- 1 S3 bucket
- IAM roles and policies

### 4. Deploy

```bash
terraform apply
```

Type `yes` when prompted.

**Deployment time**: 5-8 minutes

### 5. Verify Deployment

```bash
# Show all outputs
terraform output

# Get Quay URL
terraform output quay_url

# Get instance IPs
terraform output instance_summary
```

### 6. Access Services

**Via Load Balancer:**
```bash
QUAY_URL=$(terraform output -raw quay_url)
curl http://$QUAY_URL/health
```

**Direct SSH Access:**
```bash
terraform output ssh_access_commands
```

**Service URLs:**
- Quay Registry: `http://<loadbalancer-ip>/`
- LLM Service: `http://<loadbalancer-ip>/llm`
- Minio Console: `http://<storage-ip>:9001`

## Running Threat Analysis

### Option 1: Use Existing Framework

```bash
cd ../../../../platforms/cloud_aws/analyzer
python main.py
```

### Option 2: Run Prowler (Tool Comparison)

```bash
# Scan AWS account
prowler aws --output-directory ./prowler-results

# Compare Prowler findings vs framework
# Expected: Prowler ~8-10 threats (47% coverage)
#           Framework 17 threats (100% coverage)
```

### Option 3: Manual Verification

**T01 - Unauthenticated Access:**
```bash
# Test public SSH access
nmap <instance-ip> -p 22,80,8080

# Test Quay without authentication
curl http://<loadbalancer-ip>/
```

**T05 - Public S3 Bucket:**
```bash
BUCKET=$(terraform output -raw s3_bucket_name)
aws s3 ls s3://$BUCKET --no-sign-request
```

**T11 - LLM Without Auth:**
```bash
curl -X POST http://<loadbalancer-ip>/llm/v1/completions \
  -H "Content-Type: application/json" \
  -d '{"prompt":"test","max_tokens":10}'
```

## Monitoring Free Tier Usage

### Check EC2 Hours

```bash
# View current instance running time
aws ec2 describe-instances \
  --filters "Name=tag:CaseStudy,Values=quay-minimal" \
  --query 'Reservations[].Instances[].[InstanceId,LaunchTime,State.Name]' \
  --output table
```

### Check S3 Usage

```bash
# View bucket size
aws s3 ls s3://$(terraform output -raw s3_bucket_name) --summarize --human-readable --recursive
```

### Set Billing Alerts

**Recommended**: Set up AWS billing alerts at $5, $10, $20 thresholds in AWS Console → Billing → Budgets

## Cleanup

**IMPORTANT**: Destroy resources to avoid charges!

```bash
# Destroy all infrastructure
terraform destroy

# Verify deletion
aws ec2 describe-instances --filters "Name=tag:CaseStudy,Values=quay-minimal"
aws s3 ls | grep quay-minimal
```

**Manual cleanup** (if terraform destroy fails):
1. Terminate EC2 instances via AWS Console
2. Delete S3 bucket
3. Delete VPC and associated resources
4. Delete IAM roles

## Performance Metrics for Research Paper

Expected metrics (for table comparison):

| Metric | Value |
|--------|-------|
| Infrastructure | 6 EC2 t3.micro instances |
| Total CPU | 12 vCPUs |
| Total Memory | 6 GB |
| Instance Type | t3.micro (2 vCPU, 1 GB) |
| Components | 20+ |
| Data Collection Time | ~2-5s (VPC Flow Logs if enabled) |
| Analysis Time | ~2-10s (Prowler + framework) |
| Threats Detected | 17/17 (T01-T17) |

### Data Collection Tools

- **VPC Flow Logs** (optional, costs apply)
- **boto3** for AWS API queries
- **Prowler** for security scanning

## Troubleshooting

### Issue: Terraform Apply Fails

**Error**: `InvalidKeyPair.NotFound`
**Solution**: Make sure `ssh_public_key` in terraform.tfvars is correct

**Error**: `UnauthorizedOperation`
**Solution**: Check AWS credentials with `aws sts get-caller-identity`

### Issue: Instances Not Starting

**Check user data logs:**
```bash
ssh -i ~/.ssh/quay-minimal-key ec2-user@<instance-ip>
tail -f /var/log/cloud-init-output.log
```

### Issue: Services Not Accessible

**Check security group:**
```bash
aws ec2 describe-security-groups --group-ids <sg-id>
```

**Check Docker containers:**
```bash
ssh -i ~/.ssh/quay-minimal-key ec2-user@<instance-ip>
docker ps -a
docker logs <container-name>
```

### Issue: Exceeded Free Tier

**Monitor billing:**
- AWS Console → Billing Dashboard
- Check "Free Tier" section
- Review detailed billing report

## Cost Optimization

### For Minimal Testing (< $1)

1. **Deploy for 4-6 hours only**
2. **Use terraform destroy immediately after testing**
3. **Don't enable VPC Flow Logs** (costs $0.50/GB)
4. **Minimal S3 uploads**

### For Extended Testing (~$9/month)

1. **Keep instances running** (over 750 hours/month)
2. **EBS storage charges** (180 GB - 30 GB free = 150 GB × $0.10 = $15)
3. **Total**: ~$9-15/month

## Comparison to Full HA Deployment

| Aspect | This (Minimal) | Full HA (quay_ha) |
|--------|----------------|-------------------|
| Instances | 6 | 14+ |
| vCPUs | 12 | 40+ |
| Memory | 6 GB | 40+ GB |
| AZs | 1 | 3 |
| Database | Docker | RDS Aurora (3 nodes) |
| Cache | Docker | ElastiCache (3 nodes) |
| Load Balancer | NGINX | Application Load Balancer |
| NAT Gateway | No | Yes (3) |
| **Cost/month** | **~$0-9** | **~$800-1,200** |
| **Threats** | **T01-T17** | **T01-T21** |

## References

- [AWS Free Tier](https://aws.amazon.com/free/)
- [Project Quay](https://github.com/quay/quay)
- [Terraform AWS Provider](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)
- [Prowler](https://github.com/prowler-cloud/prowler)
