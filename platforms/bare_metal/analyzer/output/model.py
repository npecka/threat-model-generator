from pytm import TM, Boundary, Actor, Process, Datastore, Dataflow, Data, Threat

tm = TM('Bare-Metal Supply Chain Threat Model')
tm.description = 'Threat model generated from bare-metal runtime + config analysis'
tm.isOrdered = True
tm.mergeResponses = True

externalBoundary = Boundary('External Services')

Internet = Process(name='Internet', boundary=externalBoundary)

Internet.description = 'External world (public internet)'
Internet.inBoundary = externalBoundary

dev_zone = Boundary('dev-zone')
cicd_zone = Boundary('cicd-zone')
prod_zone = Boundary('prod-zone')


External_239_255_255_250 = Process(name='239.255.255.250', boundary=externalBoundary)
External_239_255_255_250.description = 'External connection target'
External_239_255_255_250.inBoundary = externalBoundary
Internet_to_External_239_255_255_250_1900_data = Data('Observed runtime flow (port=1900)')
Internet_to_External_239_255_255_250_1900 = Dataflow(name='Internet_to_External_239_255_255_250_1900', source=Internet, sink=External_239_255_255_250, protocol='UDP', data=Internet_to_External_239_255_255_250_1900_data, dstPort=1900)

# =========================================================================
# CUSTOM THREATS - Multi-Modal Correlated Threats
# =========================================================================

# Define correlated threat definitions
# T01: Multi-Modal Correlated Threat
Threat(
    SID='T01',
    target=('Process', 'Datastore', 'Dataflow'),
    description='T01: Validation=CONFIRMED, Confidence=HIGH',
    details='Static: docker_bench, checkov | Runtime: CONFIRMED',
    severity='CRITICAL',
    condition='True'  # Confidence: HIGH
)

# T02: Multi-Modal Correlated Threat
Threat(
    SID='T02',
    target=('Process', 'Datastore', 'Dataflow'),
    description='T02: Validation=POTENTIAL, Confidence=MEDIUM',
    details='Static: docker_bench, checkov | Runtime: POTENTIAL',
    severity='HIGH',
    condition='True'  # Confidence: MEDIUM
)

# T04: Multi-Modal Correlated Threat
Threat(
    SID='T04',
    target=('Process', 'Datastore', 'Dataflow'),
    description='T04: Validation=POTENTIAL, Confidence=MEDIUM',
    details='Static: docker_bench | Runtime: POTENTIAL',
    severity='HIGH',
    condition='True'  # Confidence: MEDIUM
)

# T05: Multi-Modal Correlated Threat
Threat(
    SID='T05',
    target=('Process', 'Datastore', 'Dataflow'),
    description='T05: Validation=UNVALIDATED, Confidence=MEDIUM',
    details='Static: docker_bench | Runtime: UNVALIDATED',
    severity='MEDIUM',
    condition='True'  # Confidence: MEDIUM
)

# T06: Multi-Modal Correlated Threat
Threat(
    SID='T06',
    target=('Process', 'Datastore', 'Dataflow'),
    description='T06: Validation=POTENTIAL, Confidence=LOW',
    details='Static: docker_bench, checkov | Runtime: POTENTIAL',
    severity='HIGH',
    condition='True'  # Confidence: LOW
)

# T07: Multi-Modal Correlated Threat
Threat(
    SID='T07',
    target=('Process', 'Datastore', 'Dataflow'),
    description='T07: Validation=UNVALIDATED, Confidence=MEDIUM',
    details='Static: docker_bench | Runtime: UNVALIDATED',
    severity='MEDIUM',
    condition='True'  # Confidence: MEDIUM
)

# T10: Multi-Modal Correlated Threat
Threat(
    SID='T10',
    target=('Process', 'Datastore', 'Dataflow'),
    description='T10: Validation=UNVALIDATED, Confidence=MEDIUM',
    details='Static: docker_bench, checkov | Runtime: UNVALIDATED',
    severity='MEDIUM',
    condition='True'  # Confidence: MEDIUM
)


# Annotate elements with detected threats

# --- CORRELATED: Multi-Modal Validated Threats ---
# T01 (CONFIRMED, HIGH confidence)
# T02 (POTENTIAL, MEDIUM confidence)
# T04 (POTENTIAL, MEDIUM confidence)
# T05 (UNVALIDATED, MEDIUM confidence)
# T06 (POTENTIAL, LOW confidence)
# T07 (UNVALIDATED, MEDIUM confidence)
# T10 (UNVALIDATED, MEDIUM confidence)

# Process the threat model (generates STRIDE + custom threats)
tm.process()