from pytm import TM, Boundary, Actor, Process, Datastore, Dataflow, Data, Threat

tm = TM('K8s Cluster Threat Model')
tm.description = 'Threat model generated from Kubernetes runtime + config analysis'
tm.isOrdered = True
tm.mergeResponses = True

externalBoundary = Boundary('External Services')

Internet = Process(name='Internet', boundary=externalBoundary)

Internet.description = 'External world (reserved:world)'
Internet.inBoundary = externalBoundary
prod_zone = Boundary('prod-zone')
cicd_zone = Boundary('cicd-zone')
dev_zone = Boundary('dev-zone')

jenkins_6c4b664d4_bpttc = Process(name='jenkins-6c4b664d4-bpttc', boundary=cicd_zone)
jenkins_6c4b664d4_bpttc.description = 'jenkins-6c4b664d4-bpttc in cicd-zone'
jenkins_6c4b664d4_bpttc.inBoundary = cicd_zone
mlflow_server_85d4fc986_pht8x = Process(name='mlflow-server-85d4fc986-pht8x', boundary=cicd_zone)
mlflow_server_85d4fc986_pht8x.description = 'mlflow-server-85d4fc986-pht8x in cicd-zone'
mlflow_server_85d4fc986_pht8x.inBoundary = cicd_zone
registry_7b8cc845cf_lmgzx = Process(name='registry-7b8cc845cf-lmgzx', boundary=cicd_zone)
registry_7b8cc845cf_lmgzx.description = 'registry-7b8cc845cf-lmgzx in cicd-zone'
registry_7b8cc845cf_lmgzx.inBoundary = cicd_zone
gitea_6c699dbc99_8t4dc = Datastore(name='gitea-6c699dbc99-8t4dc', boundary=dev_zone)
gitea_6c699dbc99_8t4dc.description = 'gitea-6c699dbc99-8t4dc in dev-zone'
gitea_6c699dbc99_8t4dc.inBoundary = dev_zone
training_data_init = Process(name='training-data-init', boundary=dev_zone)
training_data_init.description = 'training-data-init in dev-zone'
training_data_init.inBoundary = dev_zone
application_6fc58f67fd_xkl86 = Process(name='application-6fc58f67fd-xkl86', boundary=prod_zone)
application_6fc58f67fd_xkl86.description = 'application-6fc58f67fd-xkl86 in prod-zone'
application_6fc58f67fd_xkl86.inBoundary = prod_zone
application_6fc58f67fd_xmw49 = Process(name='application-6fc58f67fd-xmw49', boundary=prod_zone)
application_6fc58f67fd_xmw49.description = 'application-6fc58f67fd-xmw49 in prod-zone'
application_6fc58f67fd_xmw49.inBoundary = prod_zone
ml_inference_7b68c45fbc_gtqtj = Process(name='ml-inference-7b68c45fbc-gtqtj', boundary=prod_zone)
ml_inference_7b68c45fbc_gtqtj.description = 'ml-inference-7b68c45fbc-gtqtj in prod-zone'
ml_inference_7b68c45fbc_gtqtj.inBoundary = prod_zone
postgres_7b8b7467b5_q6dbr = Datastore(name='postgres-7b8b7467b5-q6dbr', boundary=prod_zone)
postgres_7b8b7467b5_q6dbr.description = 'postgres-7b8b7467b5-q6dbr in prod-zone'
postgres_7b8b7467b5_q6dbr.inBoundary = prod_zone


# =========================================================================
# CUSTOM THREATS - Multi-Modal Correlated Threats
# =========================================================================

# Define correlated threat definitions
# T01: Multi-Modal Correlated Threat
Threat(
    SID='T01',
    target=('Process', 'Datastore', 'Dataflow'),
    description='T01: Validation=POTENTIAL, Confidence=MEDIUM',
    details='Static: kubescape | Runtime: POTENTIAL',
    severity='HIGH',
    condition='True'  # Confidence: MEDIUM
)

# T02: Multi-Modal Correlated Threat
Threat(
    SID='T02',
    target=('Process', 'Datastore', 'Dataflow'),
    description='T02: Validation=CONFIRMED, Confidence=HIGH',
    details='Static: trivy, kubescape | Runtime: CONFIRMED',
    severity='CRITICAL',
    condition='True'  # Confidence: HIGH
)

# T04: Multi-Modal Correlated Threat
Threat(
    SID='T04',
    target=('Process', 'Datastore', 'Dataflow'),
    description='T04: Validation=POTENTIAL, Confidence=MEDIUM',
    details='Static: kubescape | Runtime: POTENTIAL',
    severity='HIGH',
    condition='True'  # Confidence: MEDIUM
)

# T05: Multi-Modal Correlated Threat
Threat(
    SID='T05',
    target=('Process', 'Datastore', 'Dataflow'),
    description='T05: Validation=UNVALIDATED, Confidence=MEDIUM',
    details='Static: trivy, kubescape | Runtime: UNVALIDATED',
    severity='MEDIUM',
    condition='True'  # Confidence: MEDIUM
)

# T06: Multi-Modal Correlated Threat
Threat(
    SID='T06',
    target=('Process', 'Datastore', 'Dataflow'),
    description='T06: Validation=POTENTIAL, Confidence=MEDIUM',
    details='Static: trivy, kubescape | Runtime: POTENTIAL',
    severity='HIGH',
    condition='True'  # Confidence: MEDIUM
)

# T08: Multi-Modal Correlated Threat
Threat(
    SID='T08',
    target=('Process', 'Datastore', 'Dataflow'),
    description='T08: Validation=CONFIRMED, Confidence=HIGH',
    details='Static: trivy, kubescape | Runtime: CONFIRMED',
    severity='CRITICAL',
    condition='True'  # Confidence: HIGH
)

# T09: Multi-Modal Correlated Threat
Threat(
    SID='T09',
    target=('Process', 'Datastore', 'Dataflow'),
    description='T09: Validation=UNVALIDATED, Confidence=MEDIUM',
    details='Static: kubescape | Runtime: UNVALIDATED',
    severity='MEDIUM',
    condition='True'  # Confidence: MEDIUM
)

# T10: Multi-Modal Correlated Threat
Threat(
    SID='T10',
    target=('Process', 'Datastore', 'Dataflow'),
    description='T10: Validation=UNVALIDATED, Confidence=MEDIUM',
    details='Static: trivy, kubescape | Runtime: UNVALIDATED',
    severity='MEDIUM',
    condition='True'  # Confidence: MEDIUM
)

# T13: Multi-Modal Correlated Threat
Threat(
    SID='T13',
    target=('Process', 'Datastore', 'Dataflow'),
    description='T13: Validation=UNVALIDATED, Confidence=MEDIUM',
    details='Static: kubescape | Runtime: UNVALIDATED',
    severity='MEDIUM',
    condition='True'  # Confidence: MEDIUM
)

# T15: Multi-Modal Correlated Threat
Threat(
    SID='T15',
    target=('Process', 'Datastore', 'Dataflow'),
    description='T15: Validation=UNVALIDATED, Confidence=MEDIUM',
    details='Static: kubescape | Runtime: UNVALIDATED',
    severity='MEDIUM',
    condition='True'  # Confidence: MEDIUM
)

# ML-AUTH001: Unauthorized Model Access
Threat(
    SID='ML-AUTH001',
    target=('Process', 'Datastore'),
    description='MLflow server mlflow-server-85d4fc986-pht8x has no authentication configured',
    details='ML-specific domain threat',
    severity='High',
    condition='True'
)

# ML-POISON001: Training Data Poisoning
Threat(
    SID='ML-POISON001',
    target=('Process', 'Datastore'),
    description='Training data training-data-init accessible from CI/CD zone',
    details='ML-specific domain threat',
    severity='High',
    condition='True'
)

# ML-CRYPTO001: Unencrypted Model Transfer
Threat(
    SID='ML-CRYPTO001',
    target=('Process', 'Datastore'),
    description='ML service mlflow-server transfers models over unencrypted HTTP',
    details='ML-specific domain threat',
    severity='High',
    condition='True'
)

# Runtime Threat: EMPIRICAL-RT001
Threat(
    SID='RT-FALCO-01',
    target=('Process',),
    description='Shell spawned in freshrss-7ff8bf7fcf-lmvws at runtime',
    details='Detected via Falco runtime monitoring',
    severity='High',
    condition='True'
)


# Annotate elements with detected threats (for visual indicators)
# Threats detected on mlflow-server-85d4fc986-pht8x: 1
mlflow_server_85d4fc986_pht8x.threatsDetected = 1
mlflow_server_85d4fc986_pht8x.threatIds = 'ML-AUTH001'
mlflow_server_85d4fc986_pht8x.riskLevel = 'High'

# Threats detected on training-data-init: 1
training_data_init.threatsDetected = 1
training_data_init.threatIds = 'ML-POISON001'
training_data_init.riskLevel = 'High'


# --- CORRELATED: Multi-Modal Validated Threats ---
# T01 (POTENTIAL, MEDIUM confidence)
# T02 (CONFIRMED, HIGH confidence)
# T04 (POTENTIAL, MEDIUM confidence)
# T05 (UNVALIDATED, MEDIUM confidence)
# T06 (POTENTIAL, MEDIUM confidence)
# T08 (CONFIRMED, HIGH confidence)
# T09 (UNVALIDATED, MEDIUM confidence)
# T10 (UNVALIDATED, MEDIUM confidence)
# T13 (UNVALIDATED, MEDIUM confidence)
# T15 (UNVALIDATED, MEDIUM confidence)

# --- ML-SPECIFIC: Domain Threats (T11-T17) ---
# ML-AUTH001: mlflow-server-85d4fc986-pht8x - MLflow server mlflow-server-85d4fc986-pht8x has no authentication configured
# ML-POISON001: training-data-init - Training data training-data-init accessible from CI/CD zone
# ML-CRYPTO001: mlflow-server - ML service mlflow-server transfers models over unencrypted HTTP
# ML-CRYPTO001: ml-inference - ML service ml-inference transfers models over unencrypted HTTP

# --- EMPIRICAL: Runtime Behavior (Falco) ---
# EMPIRICAL-RT001: freshrss-7ff8bf7fcf-lmvws - Shell spawned in freshrss-7ff8bf7fcf-lmvws at runtime

# Process the threat model (generates STRIDE + custom threats)
tm.process()