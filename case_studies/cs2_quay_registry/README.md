# Case Study 2: Quay Container Registry

20-component enterprise container registry deployment on AWS (7 EC2 t3.micro instances).

## Components

Quay Application (x2 HA), PostgreSQL, Redis, Minio, Clair, NGINX, Jenkins, LLM image analysis service, plus supporting infrastructure (VPC, S3 buckets, IAM roles, security groups, subnets).

## Trust Zones

- **External Zone**: NGINX load balancer
- **Application Zone**: Quay instances, Clair, LLM service
- **Backend Zone**: PostgreSQL, Redis, Minio, Jenkins

## Infrastructure

- 7 EC2 t3.micro instances (14 vCPUs, 7 GB RAM)
- 2.3x increase over CS1 (3 instances, 6 vCPUs, 3 GB)

## Results

- **Threat types detected**: 17/17 (100%)
- **Threat instances**: 47 (36 traditional + 11 ML)
- **Data extraction time**: 69.2s
- **Threat analysis time**: 3.1s
- **Total time**: 72.3s

## Tool Comparison (CS2)

| Tool | Threat Types | Detection Rate |
|------|-------------|----------------|
| Our Framework | 17/17 | 100% |
| Prowler | 10/17 | 59% |
| Checkov | 7/17 | 41% |
| Trivy | 5/17 | 29% |
