# Ranking calibration review

- Minimum sample size for interpreting a score band: **50 retested nodes**
- Score bands present: **6**
- This report is advisory only. It does not change ranking weights or rewrite generated subscriptions.

## Score-band outcomes

| Previous score band | Retested | Current roundtrip success | Current roundtrip failure | Prior successes persisted | Interpretation |
|---|---:|---:|---:|---:|---|
| 0-19 | 0 | 0 (—) | 0 | — | No current retest sample |
| 20-39 | 0 | 0 (—) | 0 | — | No current retest sample |
| 40-59 | 2 | 0 (0.0%) | 2 | — | Small sample (2/50) |
| 60-79 | 720 | 31 (4.3%) | 689 | — | 4.3% current success |
| 80-99 | 35 | 1 (2.9%) | 34 | — | Small sample (35/50) |
| 100+ | 929 | 901 (97.0%) | 28 | 901/929 (97.0%) | 97.0% current success |

## Review guidance

2 score bands meet the sample threshold. No adjacent drop greater than 15 percentage points was detected; preserve current weights until repeated runs support a change.

Current-roundtrip success and historical-success persistence are different metrics. A prior score can reflect verification evidence from an earlier run, so this report is a persistence/calibration check, not a causal benchmark. Compare multiple successful collection runs before changing weights.
