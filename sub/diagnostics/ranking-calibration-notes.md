# Ranking calibration review

- Minimum sample size for interpreting a score band: **50 retested nodes**
- Score bands present: **6**
- This report is advisory only. It does not change ranking weights or rewrite generated subscriptions.

## Score-band outcomes

| Previous score band | Retested | Current roundtrip success | Current roundtrip failure | Prior successes persisted | Interpretation |
|---|---:|---:|---:|---:|---|
| 0-19 | 0 | 0 (—) | 0 | — | No current retest sample |
| 20-39 | 0 | 0 (—) | 0 | — | No current retest sample |
| 40-59 | 9 | 3 (33.3%) | 6 | — | Small sample (9/50) |
| 60-79 | 996 | 24 (2.4%) | 972 | — | 2.4% current success |
| 80-99 | 43 | 1 (2.3%) | 42 | — | Small sample (43/50) |
| 100+ | 1,330 | 1,302 (97.9%) | 28 | 1,302/1,330 (97.9%) | 97.9% current success |

## Review guidance

2 score bands meet the sample threshold. No adjacent drop greater than 15 percentage points was detected; preserve current weights until repeated runs support a change.

Current-roundtrip success and historical-success persistence are different metrics. A prior score can reflect verification evidence from an earlier run, so this report is a persistence/calibration check, not a causal benchmark. Compare multiple successful collection runs before changing weights.
