# Bare-Metal Docker Compose Configurations

This directory contains the docker-compose.yml files that are deployed on the bare-metal VMs by the `install-supply-chain.sh` script.

## Purpose

These files are extracted from the embedded configurations in `install-supply-chain.sh` to enable static analysis by security scanning tools (Trivy, Checkov).

## Files

- **gitea.docker-compose.yml** - Source control (deployed on Dev VM)
- **jenkins.docker-compose.yml** - CI/CD automation (deployed on CI/CD VM)
- **registry.docker-compose.yml** - Container registry (deployed on CI/CD VM)
- **application.docker-compose.yml** - Production app + PostgreSQL (deployed on Prod VM)

## Deployment

These files are **not** used directly for deployment. They are reference copies for security scanning.

The actual deployment creates these files on remote VMs via SSH commands in `install-supply-chain.sh`.

## Security Scanning

These files enable static analysis tools to scan bare-metal deployments:

```bash
# Scan with Trivy
trivy config case_studies/bare_metal/supply_chain/docker-compose/

# Scan with Checkov
checkov -d case_studies/bare_metal/supply_chain/docker-compose/ --framework docker_compose
```

## Intentional Vulnerabilities

These docker-compose files contain the same T01-T10 threats as the Kubernetes and AWS deployments:

- **T02**: Jenkins runs as root with privileged mode
- **T08**: Hardcoded passwords in environment variables
- **T10**: No resource limits defined
- And more (see parent README.md for full threat list)
