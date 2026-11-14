# Ranking calibration review

- Minimum sample size for interpreting a score band: **50 retested nodes**
- Score bands present: **6**
- This report is advisory only. It does not change ranking weights or rewrite generated subscriptions.

## Score-band outcomes

| Previous score band | Retested | Current roundtrip success | Current roundtrip failure | Prior successes persisted | Interpretation |
|---|---:|---:|---:|---:|---|
| 0-19 | 0 | 0 (—) | 0 | — | No current retest sample |
| 20-39 | 0 | 0 (—) | 0 | — | No current retest sample |
| 40-59 | 1 | 0 (0.0%) | 1 | — | Small sample (1/50) |
| 60-79 | 655 | 2 (0.3%) | 653 | — | 0.3% current success |
| 80-99 | 44 | 0 (0.0%) | 44 | — | Small sample (44/50) |
| 100+ | 1,406 | 1,354 (96.3%) | 52 | 1,354/1,406 (96.3%) | 96.3% current success |

## Review guidance

2 score bands meet the sample threshold. No adjacent drop greater than 15 percentage points was detected; preserve current weights until repeated runs support a change.

Current-roundtrip success and historical-success persistence are different metrics. A prior score can reflect verification evidence from an earlier run, so this report is a persistence/calibration check, not a causal benchmark. Compare multiple successful collection runs before changing weights.
