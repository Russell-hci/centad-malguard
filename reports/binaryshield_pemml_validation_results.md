# BinaryShield PEMML RunPod Validation Results

Generated: `2026-06-26T10:43:27Z`

## Result Framing

BinaryShield was externally evaluated on a reproducible balanced PEMML subset of 10,000 raw PE files: 5,000 malware and 5,000 benign samples.

This is a balanced external subset validation, not full PEMML validation. The earlier 1k+1k run is a smoke test only. No 10k+10k run and no full PEMML run were performed.

## PEMML Metadata Inspection

- Dataset: Practical Security Analytics PE Malware Machine Learning Dataset (PEMML).
- Dataset root: `/path/to/pemml`.
- `samples.csv`: `/path/to/pemml/samples.csv`.
- Source CSV rows: `201549`.
- Label column used by manifest builder: `list` mapped from PEMML values to BinaryShield labels.
- Sample filename column used by manifest builder: `id`.
- Extracted dataset storage: `118G` under `/path/to/pemml`.
- Samples had execute permissions removed before validation.
- Raw PE files and run artifacts remained outside Git under `/workspace`.

## Stage Summary

| Stage | Purpose | Manifest rows | Train/Val/Test | Sanitized evidence | Status |
| --- | --- | ---: | --- | --- | --- |
| 1k+1k | Smoke test | 2000 | 1400/300/300 | `reports/binaryshield/pemml_1k_1k_sanitized_metrics/` | `FAIL` |
| 5k+5k | Balanced 10,000-sample external subset validation | 10000 | 7000/1500/1500 | `reports/binaryshield/pemml_5k_5k_sanitized_metrics/` | `FAIL` |

## 1k+1k Smoke Test

- Manifest: `/path/to/manifests/pemml_1k_1k_manifest.csv`.
- Run directory: `/path/to/runs/pemml_1k_1k`.
- Candidate detector: `byte_histogram_logistic`.
- Detector families: `pe_feature_centroid`, `byte_histogram_centroid`, `hybrid_centroid`, `byte_histogram_logistic`.
- Runtime: not recorded in pipeline log.
- Run storage: `2.5G`.
- Acceptance status: `FAIL`.

| Metric | Clean | Append overlay | Section slack |
| --- | ---: | ---: | ---: |
| Macro F1 | 0.883322 | 0.874999 | 0.863145 |
| Accuracy | 0.883333 | 0.875000 | 0.864662 |
| Worst-class F1 | 0.882155 | 0.874576 | 0.848739 |
| Prediction stability | n/a | 1.000000 | 1.000000 |
| Attack success rate | n/a | 0.000000 | 0.000000 |
| Evaluated transformed samples | n/a | 296 | 266 |

Failed 1k acceptance gates:

- `Slack executable sections unchanged`: observed `0.9925373134328358`, target `>= 1.00`

## 5k+5k Balanced External Subset Validation

- Manifest: `/path/to/manifests/pemml_5k_5k_manifest.csv`.
- Run directory: `/path/to/runs/pemml_5k_5k`.
- Candidate detector: `byte_histogram_logistic`.
- Detector families: `pe_feature_centroid`, `byte_histogram_centroid`, `hybrid_centroid`, `byte_histogram_logistic`.
- Runtime: `6h 22m 40s` (`2026-06-26T04:15:04Z` to `2026-06-26T10:37:44Z`).
- Run storage: `12G`.
- Acceptance status: `FAIL`.

| Metric | Clean | Append overlay | Section slack |
| --- | ---: | ---: | ---: |
| Macro F1 | 0.906000 | 0.894983 | 0.889822 |
| Accuracy | 0.906000 | 0.894983 | 0.891485 |
| Worst-class F1 | 0.905937 | 0.894702 | 0.876712 |
| Prediction stability | n/a | 0.993980 | 0.996986 |
| Attack success rate | n/a | 0.004474 | 0.001691 |
| Evaluated transformed samples | n/a | 1495 | 1327 |

## 5k Detector Comparison

| Detector | Robust-min macro F1 | Min stability | Max attack success | Min worst-class F1 |
| --- | ---: | ---: | ---: | ---: |
| byte_histogram_centroid | 0.662364 | 0.975885 | 0.028921 | 0.659056 |
| byte_histogram_logistic | 0.889822 | 0.993980 | 0.004474 | 0.876712 |
| hybrid_centroid | 0.353073 | 1.000000 | 0.000000 | 0.084942 |
| pe_feature_centroid | 0.353073 | 1.000000 | 0.000000 | 0.084942 |

Candidate detector comparison status: `PASS`.

## 5k Acceptance Status

Overall acceptance status: `FAIL`.

Failed 5k acceptance gates:

- `Slack executable sections unchanged`: observed `0.9984951091045899`, target `>= 1.00`

Interpretation: the 5k+5k PEMML subset run completed and `byte_histogram_logistic` was the strongest detector by robust-min macro F1 among the evaluated detectors. The configured candidate acceptance still failed because the strict section-slack validation gate requires executable sections unchanged for every validation record; the observed rate was `0.9984951091045899`. Metric gates passed, but this should be reported as a bounded external subset result with a structural validation limitation.

## Validation Coverage

| Dataset stage | PE parse success | Feature extraction success | Append region available | Level-2 slack region available |
| --- | ---: | ---: | ---: | ---: |
| 1k+1k | 1.000000 | 1.000000 | 0.992500 | 0.886000 |
| 5k+5k | 1.000000 | 1.000000 | 0.993200 | 0.882500 |

## Limitations

- This is not full PEMML validation.
- This is not family-level validation; family labels were not independently verified.
- This is not Level 3 behavioral preservation; no malware was executed dynamically.
- Section-slack validation is bounded to the static checks implemented in BinaryShield.
- The 5k acceptance report is `FAIL` because of the strict slack executable-section unchanged gate, despite strong detector metrics on evaluated transformed files.
- Raw PE files, transformed binaries, detector artifacts, archives, and run directories are intentionally excluded from Git.
