# Ranking calibration review

- Minimum sample size for interpreting a score band: **50 retested nodes**
- Score bands present: **6**
- This report is advisory only. It does not change ranking weights or rewrite generated subscriptions.

## Score-band outcomes

| Previous score band | Retested | Current roundtrip success | Current roundtrip failure | Prior successes persisted | Interpretation |
|---|---:|---:|---:|---:|---|
| 0-19 | 0 | 0 (—) | 0 | — | No current retest sample |
| 20-39 | 0 | 0 (—) | 0 | — | No current retest sample |
| 40-59 | 4 | 1 (25.0%) | 3 | — | Small sample (4/50) |
| 60-79 | 1,159 | 30 (2.6%) | 1,129 | — | 2.6% current success |
| 80-99 | 90 | 0 (0.0%) | 90 | — | 0.0% current success |
| 100+ | 1,039 | 1,002 (96.4%) | 37 | 1,002/1,039 (96.4%) | 96.4% current success |

## Review guidance

3 score bands meet the sample threshold. No adjacent drop greater than 15 percentage points was detected; preserve current weights until repeated runs support a change.

Current-roundtrip success and historical-success persistence are different metrics. A prior score can reflect verification evidence from an earlier run, so this report is a persistence/calibration check, not a causal benchmark. Compare multiple successful collection runs before changing weights.
