# Where each published result lives

This file maps the headline results of the IEEE TSC paper to the files in this
repository that record them.

## Threat detection (17 threat types, T01 to T17)

| Platform | Case study | Types | Instances | Run | Files |
|---|---|---|---|---|---|
| Kubernetes | CS1 supply chain | 17/17 | 47 (40 + 7) | 2025-12-17 | `results/kubernetes/ml_experiment_latest/K8S_ML_THREAT_DETECTION_RESULTS.md` (evidence per threat), `case_studies/cs1_supply_chain/kubernetes/results/instance_counts.json` |
| Bare metal | CS1 supply chain | 17/17 | 49 (42 + 7) | 2025-12-14 | `case_studies/cs1_supply_chain/bare_metal/results/baremetal-ml-detection-2025-12-14.md` (evidence per threat), `case_studies/cs1_supply_chain/bare_metal/results/instance_counts.json`, `results/BARE_METAL_ML_VALIDATION.md` (planted threats checked against the deployment files) |
| AWS | CS1 supply chain | 17/17 | 71 | 5 runs | `case_studies/cs1_supply_chain/aws/results/instance_counts.json`, `results/repeatability/` |
| AWS | CS2 Quay registry | 17/17 | 47 (36 + 11) | 2026-06-25, 5 runs | `case_studies/cs2_quay_registry/aws/results/`, `results/repeatability/` |

In the instance counts, the first number is traditional threats (T01 to T10)
and the second is ML threats (T11 to T17).

## Comparison with other tools

- Scanner outputs (Prowler, Checkov, Trivy, Kubescape, KubeLinter, Docker
  Bench): `case_studies/*/results/` and `results/tool_comparison/`.
- Auspex replication: `results/auspex_comparison/`.

## Performance

The timing and memory figures (Table III) come from separate performance runs
of the extractor and analyzer, not from the detection runs listed above.

## Testbed addresses

Private testbed IP addresses in the result write-ups are replaced with
placeholder addresses (for example 192.168.100.10, .20 and .30 for the
bare-metal dev, CI/CD and prod VMs).
