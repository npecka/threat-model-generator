# Auspex Comparison

Replication of the Auspex methodology (Shin et al., 2023) on the CS1 supply chain architecture.

## Methodology

Applied Auspex's publicly described diagram-based architectural threat inference approach to our 8-component supply chain system. Auspex analyzes architecture diagrams to generate threat scenarios using STRIDE and CIA classifications.

## Results

- **Detection**: 14/17 threat types (82%)
- **Scenarios generated**: 32 threat scenarios with STRIDE/CIA classifications
- **Classification**: All 14 detected threat types are **hypothetical** (unverified)

## Missed Threat Types

| Threat | Reason |
|--------|--------|
| T02 (Excessive Permissions) | IAM permissions not visible from architecture diagrams |
| T13 (Model Theft via API) | Requires endpoint analysis beyond diagram scope |
| T17 (Exposed Model Metadata) | Requires configuration inspection |

## Key Distinction

Auspex infers that threat types *could* exist based on architectural patterns. Our methodology confirms whether threat types *actually* exist by examining deployed configurations, access policies, and observed network flows. For example, Auspex flags "Docker Registry may lack authentication" (T05) as a potential risk; our methodology confirms 2 specific instances of anonymous registry access in the deployed infrastructure.

## Data

See `auspex_replication.json` for detailed per-threat comparison.
