# Repeatability Validation

n=5 independent runs per case study on AWS to validate detection consistency.

## Results

### CS1: Supply Chain (8 components, 3 EC2 instances)

| Run | Threat Types | Instances | Time (s) |
|-----|-------------|-----------|----------|
| 1 | 17/17 | 71 | 53.2 |
| 2 | 17/17 | 71 | 58.7 |
| 3 | 17/17 | 71 | 49.8 |
| 4 | 17/17 | 71 | 62.1 |
| 5 | 17/17 | 71 | 55.4 |

**Detection**: mean=17.0, std=0.0
**Timing**: mean=55.8s, std=4.6s, median=55.4s

### CS2: Quay Registry (20 components, 7 EC2 instances)

| Run | Threat Types | Instances | Time (s) |
|-----|-------------|-----------|----------|
| 1 | 17/17 | 47 | 72.3 |
| 2 | 17/17 | 47 | 74.1 |
| 3 | 17/17 | 47 | 71.8 |
| 4 | 17/17 | 47 | 73.5 |
| 5 | 17/17 | 47 | 72.9 |

**Detection**: mean=17.0, std=0.0
**Timing**: mean=72.9s, std=0.9s, median=72.9s

## Key Findings

- 100% detection reproducibility across all runs
- CS1 shows higher timing variance from AWS network variability
- Sub-linear scaling: 2.3x infrastructure increase yields ~31% time increase

## Data

See `repeatability_results.json` for raw data.
