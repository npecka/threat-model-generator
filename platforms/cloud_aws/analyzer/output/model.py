from pytm import TM, Boundary, Actor, Process, Datastore, Dataflow, Data, Threat

tm = TM('AWS Supply Chain Threat Model')
tm.description = 'Threat model generated from AWS runtime + config analysis'
tm.isOrdered = True
tm.mergeResponses = True

externalBoundary = Boundary('External Services')

Internet = Process(name='Internet', boundary=externalBoundary)

Internet.description = 'External world (public internet)'
Internet.inBoundary = externalBoundary

subnet_0aade118bfb3dac8a = Boundary('subnet-0aade118bfb3dac8a')
subnet_0fcd5fb7c57e09f78 = Boundary('subnet-0fcd5fb7c57e09f78')
subnet_069c9c3717f54b465 = Boundary('subnet-069c9c3717f54b465')

registry = Datastore(name='registry', boundary=subnet_0aade118bfb3dac8a)
registry.description = 'registry in subnet-0aade118bfb3dac8a'
registry.inBoundary = subnet_0aade118bfb3dac8a
jenkins = Process(name='jenkins', boundary=subnet_0aade118bfb3dac8a)
jenkins.description = 'jenkins in subnet-0aade118bfb3dac8a'
jenkins.inBoundary = subnet_0aade118bfb3dac8a
gitea = Process(name='gitea', boundary=subnet_0fcd5fb7c57e09f78)
gitea.description = 'gitea in subnet-0fcd5fb7c57e09f78'
gitea.inBoundary = subnet_0fcd5fb7c57e09f78
application = Process(name='application', boundary=subnet_069c9c3717f54b465)
application.description = 'application in subnet-069c9c3717f54b465'
application.inBoundary = subnet_069c9c3717f54b465
postgres = Datastore(name='postgres', boundary=subnet_069c9c3717f54b465)
postgres.description = 'postgres in subnet-069c9c3717f54b465'
postgres.inBoundary = subnet_069c9c3717f54b465


# =========================================================================
# CUSTOM THREATS - Multi-Modal Correlated Threats
# =========================================================================

# Define correlated threat definitions
# T01: Multi-Modal Correlated Threat
Threat(
    SID='T01',
    target=('Process', 'Datastore', 'Dataflow'),
    description='T01: Validation=CONFIRMED, Confidence=MEDIUM',
    details='Static: checkov | Runtime: CONFIRMED',
    severity='CRITICAL',
    condition='True'  # Confidence: MEDIUM
)

# T03: Multi-Modal Correlated Threat
Threat(
    SID='T03',
    target=('Process', 'Datastore', 'Dataflow'),
    description='T03: Validation=CONFIRMED, Confidence=HIGH',
    details='Static: checkov | Runtime: CONFIRMED',
    severity='CRITICAL',
    condition='True'  # Confidence: HIGH
)

# T05: Multi-Modal Correlated Threat
Threat(
    SID='T05',
    target=('Process', 'Datastore', 'Dataflow'),
    description='T05: Validation=UNVALIDATED, Confidence=MEDIUM',
    details='Static:  | Runtime: UNVALIDATED',
    severity='MEDIUM',
    condition='True'  # Confidence: MEDIUM
)

# T07: Multi-Modal Correlated Threat
Threat(
    SID='T07',
    target=('Process', 'Datastore', 'Dataflow'),
    description='T07: Validation=UNVALIDATED, Confidence=MEDIUM',
    details='Static: checkov | Runtime: UNVALIDATED',
    severity='MEDIUM',
    condition='True'  # Confidence: MEDIUM
)

# T10: Multi-Modal Correlated Threat
Threat(
    SID='T10',
    target=('Process', 'Datastore', 'Dataflow'),
    description='T10: Validation=UNVALIDATED, Confidence=MEDIUM',
    details='Static:  | Runtime: UNVALIDATED',
    severity='MEDIUM',
    condition='True'  # Confidence: MEDIUM
)


# Annotate elements with detected threats
# Total threats detected: 5
registry.totalThreatsDetected = 5
registry.riskLevel = 'Critical'


# --- CORRELATED: Multi-Modal Validated Threats ---
# T01 (CONFIRMED, MEDIUM confidence)
# T03 (CONFIRMED, HIGH confidence)
# T05 (UNVALIDATED, MEDIUM confidence)
# T07 (UNVALIDATED, MEDIUM confidence)
# T10 (UNVALIDATED, MEDIUM confidence)

# Process the threat model (generates STRIDE + custom threats)
tm.process()