# Contributing to Dynamic Threat Modeling Framework

Thank you for your interest in contributing to this project!

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/threat-model-generator.git`
3. Create a branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Run tests to ensure nothing breaks
6. Commit your changes: `git commit -m "Description of changes"`
7. Push to your fork: `git push origin feature/your-feature-name`
8. Create a Pull Request

## Development Setup

### Prerequisites

- Python 3.8+
- Kubernetes cluster (for K8s testing)
- Docker and Docker Compose (for bare-metal testing)
- AWS account (for cloud testing)

### Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/threat-model-generator.git
cd threat-model-generator

# Install Python dependencies
pip install -r requirements.txt

# Install optional security tools
# Trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Kubescape
curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash

# Prowler (AWS)
pip install prowler
```

## Testing

Before submitting a pull request, please test your changes:

### Run Platform-Specific Tests

**Kubernetes:**
```bash
cd dynamic_threat_modeling/kubernetes/supply_chain
kubectl apply -f .
cd ../../../platforms/kubernetes/analyzer
python main.py
```

**Bare-metal:**
```bash
# Deploy on test VMs
cd dynamic_threat_modeling/bare_metal/supply_chain/docker-compose
# Follow deployment instructions
cd ../../../../platforms/bare_metal/analyzer
python main.py
```

**AWS:**
```bash
cd dynamic_threat_modeling/cloud_aws/supply_chain/terraform
terraform apply
cd ../../../../platforms/cloud_aws/analyzer
python main.py
```

### Run Tool Comparison

```bash
cd tools/comparison
./run_all_tools.sh
python parse_tool_results.py
```

## Code Style

- Follow PEP 8 for Python code
- Use meaningful variable and function names
- Add docstrings to all functions and classes
- Keep functions small and focused
- Add comments for complex logic

## Pull Request Guidelines

- **Title:** Clear, concise description of changes
- **Description:** Explain what changes were made and why
- **Testing:** Describe how changes were tested
- **Documentation:** Update relevant documentation
- **Breaking Changes:** Clearly mark any breaking changes

## Areas for Contribution

We welcome contributions in the following areas:

### 1. Platform Support
- Add support for additional platforms (Azure, GCP, etc.)
- Improve existing platform extractors and analyzers

### 2. Threat Detection
- Add new threat patterns to the taxonomy
- Improve existing threat detection algorithms
- Enhance ML/AI-specific threat detection

### 3. Tool Integration
- Integrate additional security scanning tools
- Improve tool result parsing and mapping
- Add support for new tool versions

### 4. Performance
- Optimize graph algorithms
- Reduce memory usage for large deployments
- Improve runtime correlation efficiency

### 5. Documentation
- Improve setup guides
- Add tutorials and examples
- Create video demonstrations
- Translate documentation

### 6. Testing
- Add unit tests
- Create integration tests
- Develop test case studies
- Add CI/CD pipelines

## Reporting Issues

When reporting issues, please include:

1. **Description:** Clear description of the issue
2. **Steps to Reproduce:** Detailed steps to reproduce the problem
3. **Expected Behavior:** What you expected to happen
4. **Actual Behavior:** What actually happened
5. **Environment:**
   - Platform (Kubernetes/Bare-metal/AWS)
   - Python version
   - Tool versions (if applicable)
   - Operating system
6. **Logs:** Relevant error messages or logs

## Feature Requests

We welcome feature requests! Please:

1. Check if the feature already exists or is planned
2. Clearly describe the feature and its use case
3. Explain why it would be valuable
4. Provide examples if possible

## Code of Conduct

- Be respectful and inclusive
- Welcome newcomers
- Accept constructive criticism
- Focus on what is best for the community
- Show empathy towards other community members

## License

By contributing, you agree that your contributions will be licensed under the same license as the project.

## Questions?

If you have questions, please:
- Open an issue for discussion
- Contact the maintainers: nicholaspecka@unt.edu

Thank you for contributing!
