from pytm import TM, Boundary, Actor, Process, Datastore, Dataflow, Data, Threat

tm = TM('AWS Supply Chain Threat Model')
tm.description = 'Threat model generated from AWS runtime + config analysis'
tm.isOrdered = True
tm.mergeResponses = True

externalBoundary = Boundary('External Services')

Internet = Process(name='Internet', boundary=externalBoundary)

Internet.description = 'External world (public internet)'
Internet.inBoundary = externalBoundary

storage_scanner = Boundary('storage-scanner')
llm_service = Boundary('llm-service')
loadbalancer = Boundary('loadbalancer')
database_cache = Boundary('database-cache')
quay_app_2 = Boundary('quay-app-2')
quay_app_1 = Boundary('quay-app-1')



# =========================================================================
# CUSTOM THREATS - Multi-Modal Correlated Threats
# =========================================================================

# Define correlated threat definitions
# T01: Multi-Modal Correlated Threat
Threat(
    SID='T01',
    target=('Process', 'Datastore', 'Dataflow'),
    description='T01: Validation=POTENTIAL, Confidence=LOW',
    details='Static: checkov | Runtime: POTENTIAL',
    severity='HIGH',
    condition='True'  # Confidence: LOW
)

# T02: Multi-Modal Correlated Threat
Threat(
    SID='T02',
    target=('Process', 'Datastore', 'Dataflow'),
    description='T02: Validation=POTENTIAL, Confidence=MEDIUM',
    details='Static:  | Runtime: POTENTIAL',
    severity='HIGH',
    condition='True'  # Confidence: MEDIUM
)

# T03: Multi-Modal Correlated Threat
Threat(
    SID='T03',
    target=('Process', 'Datastore', 'Dataflow'),
    description='T03: Validation=POTENTIAL, Confidence=LOW',
    details='Static: checkov | Runtime: POTENTIAL',
    severity='HIGH',
    condition='True'  # Confidence: LOW
)

# T04: Multi-Modal Correlated Threat
Threat(
    SID='T04',
    target=('Process', 'Datastore', 'Dataflow'),
    description='T04: Validation=POTENTIAL, Confidence=MEDIUM',
    details='Static:  | Runtime: POTENTIAL',
    severity='HIGH',
    condition='True'  # Confidence: MEDIUM
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

# T08: Multi-Modal Correlated Threat
Threat(
    SID='T08',
    target=('Process', 'Datastore', 'Dataflow'),
    description='T08: Validation=CONFIRMED, Confidence=HIGH',
    details='Static:  | Runtime: CONFIRMED',
    severity='CRITICAL',
    condition='True'  # Confidence: HIGH
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

# T11: Multi-Modal Correlated Threat
Threat(
    SID='T11',
    target=('Process', 'Datastore', 'Dataflow'),
    description='T11: Validation=NO_VALIDATION, Confidence=MEDIUM',
    details='Static:  | Runtime: NO_VALIDATION',
    severity='MEDIUM',
    condition='True'  # Confidence: MEDIUM
)

# T12: Multi-Modal Correlated Threat
Threat(
    SID='T12',
    target=('Process', 'Datastore', 'Dataflow'),
    description='T12: Validation=NO_VALIDATION, Confidence=MEDIUM',
    details='Static:  | Runtime: NO_VALIDATION',
    severity='MEDIUM',
    condition='True'  # Confidence: MEDIUM
)

# T13: Multi-Modal Correlated Threat
Threat(
    SID='T13',
    target=('Process', 'Datastore', 'Dataflow'),
    description='T13: Validation=NO_VALIDATION, Confidence=MEDIUM',
    details='Static:  | Runtime: NO_VALIDATION',
    severity='MEDIUM',
    condition='True'  # Confidence: MEDIUM
)

# T14: Multi-Modal Correlated Threat
Threat(
    SID='T14',
    target=('Process', 'Datastore', 'Dataflow'),
    description='T14: Validation=NO_VALIDATION, Confidence=MEDIUM',
    details='Static:  | Runtime: NO_VALIDATION',
    severity='MEDIUM',
    condition='True'  # Confidence: MEDIUM
)

# T15: Multi-Modal Correlated Threat
Threat(
    SID='T15',
    target=('Process', 'Datastore', 'Dataflow'),
    description='T15: Validation=NO_VALIDATION, Confidence=MEDIUM',
    details='Static:  | Runtime: NO_VALIDATION',
    severity='MEDIUM',
    condition='True'  # Confidence: MEDIUM
)

# T16: Multi-Modal Correlated Threat
Threat(
    SID='T16',
    target=('Process', 'Datastore', 'Dataflow'),
    description='T16: Validation=NO_VALIDATION, Confidence=MEDIUM',
    details='Static:  | Runtime: NO_VALIDATION',
    severity='MEDIUM',
    condition='True'  # Confidence: MEDIUM
)

# T17: Multi-Modal Correlated Threat
Threat(
    SID='T17',
    target=('Process', 'Datastore', 'Dataflow'),
    description='T17: Validation=NO_VALIDATION, Confidence=MEDIUM',
    details='Static:  | Runtime: NO_VALIDATION',
    severity='MEDIUM',
    condition='True'  # Confidence: MEDIUM
)


# Annotate elements with detected threats

# --- CORRELATED: Multi-Modal Validated Threats ---
# T01 (POTENTIAL, LOW confidence)
# T02 (POTENTIAL, MEDIUM confidence)
# T03 (POTENTIAL, LOW confidence)
# T04 (POTENTIAL, MEDIUM confidence)
# T05 (UNVALIDATED, MEDIUM confidence)
# T07 (UNVALIDATED, MEDIUM confidence)
# T08 (CONFIRMED, HIGH confidence)
# T10 (UNVALIDATED, MEDIUM confidence)
# T11 (NO_VALIDATION, MEDIUM confidence)
# T12 (NO_VALIDATION, MEDIUM confidence)
# T13 (NO_VALIDATION, MEDIUM confidence)
# T14 (NO_VALIDATION, MEDIUM confidence)
# T15 (NO_VALIDATION, MEDIUM confidence)
# T16 (NO_VALIDATION, MEDIUM confidence)
# T17 (NO_VALIDATION, MEDIUM confidence)

# Process the threat model (generates STRIDE + custom threats)
tm.process()