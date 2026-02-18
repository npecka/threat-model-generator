#!/bin/bash
# CI/CD Instance User Data - Jenkins + Registry
# T1, T2, T5, T6, T7, T8

set -e

# Install Docker
apt-get update
apt-get install -y docker.io docker-compose
systemctl enable docker
systemctl start docker
usermod -aG docker ubuntu

# T7: Disable Docker logging
mkdir -p /etc/docker
cat > /etc/docker/daemon.json <<'EOF'
{
  "log-driver": "none"
}
EOF
systemctl restart docker

# Deploy Jenkins (T1: No auth, T2: Root user)
mkdir -p /home/ubuntu/jenkins
chown -R ubuntu:ubuntu /home/ubuntu/jenkins

cat > /home/ubuntu/jenkins/docker-compose.yml <<'EOF'
version: "3"

services:
  jenkins:
    image: jenkins/jenkins:${jenkins_version}
    container_name: jenkins
    user: root
    privileged: true
    environment:
      - JAVA_OPTS=-Djenkins.install.runSetupWizard=false
      # T8: Hardcoded secrets
      - JENKINS_ADMIN_ID=admin
      - JENKINS_ADMIN_PASSWORD=hardcoded-jenkins-pass-789
    ports:
      - "8080:8080"
      - "50000:50000"
    volumes:
      - ./data:/var/jenkins_home
      - /var/run/docker.sock:/var/run/docker.sock
    # T10: No resource limits
EOF

# Deploy Docker Registry (T5: No authentication)
mkdir -p /home/ubuntu/registry
chown -R ubuntu:ubuntu /home/ubuntu/registry

cat > /home/ubuntu/registry/docker-compose.yml <<'EOF'
version: "3"

services:
  registry:
    image: registry:${registry_version}
    container_name: registry
    ports:
      - "5000:5000"
    volumes:
      - ./data:/var/lib/registry
    # T5: No auth configuration
    # T10: No resource limits
EOF

# Start services
cd /home/ubuntu/jenkins && docker-compose up -d
cd /home/ubuntu/registry && docker-compose up -d

# T6: Create SSH key for Jenkins to access production
mkdir -p /home/ubuntu/.ssh
ssh-keygen -t rsa -N "" -f /home/ubuntu/.ssh/id_rsa -C "jenkins@cicd"
chown -R ubuntu:ubuntu /home/ubuntu/.ssh

# T1: Disable Jenkins security after it starts
sleep 60
docker exec jenkins bash -c "cat > /var/jenkins_home/config.xml <<'JENKINS_EOF'
<?xml version='1.1' encoding='UTF-8'?>
<hudson>
  <disabledAdministrativeMonitors/>
  <version>2.440</version>
  <numExecutors>2</numExecutors>
  <mode>NORMAL</mode>
  <useSecurity>false</useSecurity>
  <authorizationStrategy class=\"hudson.security.AuthorizationStrategy\$Unsecured\"/>
  <securityRealm class=\"hudson.security.SecurityRealm\$None\"/>
  <disableRememberMe>false</disableRememberMe>
  <projectNamingStrategy class=\"jenkins.model.ProjectNamingStrategy\$DefaultProjectNamingStrategy\"/>
  <workspaceDir>\$${JENKINS_HOME}/workspace/\$${ITEM_FULLNAME}</workspaceDir>
  <buildsDir>\$${ITEM_ROOTDIR}/builds</buildsDir>
  <views>
    <hudson.model.AllView>
      <owner class=\"hudson\" reference=\"../../..\"/>
      <name>all</name>
      <filterExecutors>false</filterExecutors>
      <filterQueue>false</filterQueue>
      <properties class=\"hudson.model.View\$PropertyList\"/>
    </hudson.model.AllView>
  </views>
  <primaryView>all</primaryView>
  <slaveAgentPort>50000</slaveAgentPort>
  <label></label>
  <crumbIssuer class=\"hudson.security.csrf.DefaultCrumbIssuer\">
    <excludeClientIPFromCrumb>false</excludeClientIPFromCrumb>
  </crumbIssuer>
  <nodeProperties/>
  <globalNodeProperties/>
</hudson>
JENKINS_EOF"

docker restart jenkins

# Deploy MLflow Model Registry (ML Component)
mkdir -p /home/ubuntu/mlflow
chown -R ubuntu:ubuntu /home/ubuntu/mlflow

cat > /home/ubuntu/mlflow/docker-compose.yml <<'EOF'
version: "3.8"

services:
  mlflow-server:
    image: ghcr.io/mlflow/mlflow:v2.9.2
    container_name: mlflow-server
    restart: unless-stopped
    ports:
      - "5001:5000"  # T11: Exposed without authentication (port 5001 to avoid conflict)
    environment:
      - MLFLOW_AUTH=none  # T11: No authentication
      - BACKEND_STORE_URI=file:///mlflow/backend  # T16: Filesystem backend, no provenance
      - DEFAULT_ARTIFACT_ROOT=/mlflow/artifacts
    volumes:
      - ./backend:/mlflow/backend
      - ./artifacts:/mlflow/artifacts
    command: >
      mlflow server
      --host 0.0.0.0
      --port 5000
      --backend-store-uri file:///mlflow/backend
      --default-artifact-root /mlflow/artifacts
      --no-serve-artifacts
    # T10: No resource limits
EOF

cd /home/ubuntu/mlflow
docker-compose up -d

touch /home/ubuntu/deployment-complete
