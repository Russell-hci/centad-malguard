# Final BinaryShield Verified Metrics Summary

Generated: `2026-06-26T11:03:20Z`

This file records the numerical claims used in `reports/final_binaryshield_research_paper.md` and points each group of claims to sanitized project evidence. No raw malware files, transformed binaries, model artifacts, or archives were used to produce this summary.

## Evidence Sources Inspected

- BinaryShield audit docs: `docs/binaryshield_feature_and_detector_audit.md`, `docs/binaryshield_transformation_validation_audit.md`, `docs/binaryshield_acceptance_gates.md`, `docs/binaryshield_final_narrative.md`.
- Dike sanitized evidence: `reports/binaryshield/dike_logistic_candidate_import/`, `reports/binaryshield/dike_logistic_candidate_reports_import/`, `reports/binaryshield/dike_logistic_candidate_card_deck/`, `results/binaryshield/sanitized_metrics/`.
- PEMML sanitized evidence: `reports/binaryshield_pemml_validation_results.md`, `reports/binaryshield/pemml_1k_1k_sanitized_metrics/`, `reports/binaryshield/pemml_5k_5k_sanitized_metrics/`.
- MalGuard image-phase evidence, read-only from the current local checkout: `reports/final_research_report.md`, `reports/executive_summary.md`, and `results/defenses/adversarial_training/mobilenet_v3_small_pgd_adversarial_training_20260601T114339Z/*.csv`.
- FB-MalAT 80/80 evidence: `reports/fb_malat/malguard_x_80_80_verified_result.md`, `reports/fb_malat/malguard_x_80_80_progress.md`, `configs/defense/fb_malat/at_bsl_efficientnet_b0_pgd20_from_pgd10_robustmin.yaml`, and `results/fb_malat/final_evaluations_pgd20_continuation/efficientnet_b0_20260612T200838Z/metrics.csv`.

## Original MalGuard Image-Phase Metrics

| Metric | Baseline MobileNetV3 | PGD-trained MobileNetV3 | Absolute change |
| --- | --- | --- | --- |
| Clean Accuracy | 0.979211 | 0.973477 | -0.005735 |
| Clean Macro F1 | 0.935261 | 0.919019 | -0.016242 |
| FGSM Accuracy eps=0.03 | 0.180645 | 0.828674 | 0.648029 |
| FGSM Macro F1 eps=0.03 | 0.032209 | 0.509615 | 0.477406 |
| PGD-20 Accuracy | 0.002867 | 0.200000 | 0.197133 |
| PGD-20 Macro F1 | 0.000706 | 0.031593 | 0.030887 |
| PGD-20 ASR | 0.997072 | 0.794551 | -0.202521 |
| Model Size MB | 5.934376 | 5.934376 | 0.000000 |

Key interpretation: MobileNetV3 achieved high clean performance but collapsed under PGD-20, while PGD adversarial training improved attacked accuracy without changing model size. PGD-20 macro F1 remained low after defense, so the image-phase result was useful but not sufficient as the final cybersecurity solution.

## FB-MalAT 80/80 Aggregate Image-Space Metrics

The later aggregate 80/80 result used the EfficientNet-B0 PGD-20 continuation from the PGD-10 checkpoint:

```text
checkpoint: results/fb_malat/finalists/efficientnet_pgd20_from_pgd10_epoch1_snapshot_20260612T1955Z/best_model.pth
evaluation: results/fb_malat/final_evaluations_pgd20_continuation/efficientnet_b0_20260612T200838Z/metrics.csv
config: configs/defense/fb_malat/at_bsl_efficientnet_b0_pgd20_from_pgd10_robustmin.yaml
checkpoint_sha256: 789445971574ac98544635e389c6192296f94aa00be4ea68d2cbffa8256ff909
```

| Condition | Accuracy | Precision | Recall | Macro F1 | Attack success rate | Worst-family F1 | Families F1 < 0.80 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Clean | 0.903943 | 0.898258 | 0.931632 | 0.898619 | n/a | 0.000000 | 3 |
| FGSM eps=0.03 | 0.886022 | 0.847590 | 0.889333 | 0.851871 | 0.019826 | 0.000000 | 5 |
| PGD-20 eps=0.03 | 0.870968 | 0.821423 | 0.866379 | 0.827654 | 0.036479 | 0.000000 | 6 |
| PGD-50 eps=0.03 | 0.836559 | 0.798288 | 0.850449 | 0.804148 | 0.074544 | 0.000000 | 7 |

Key interpretation: FB-MalAT achieved above 80% test accuracy and above 80% macro F1 under FGSM, PGD-20, and PGD-50 on the duplicate-aware MalImg image-space evaluation. The process combined EfficientNet-B0 capacity, Balanced Softmax, balanced sampling, PGD-20 adversarial training, continuation from a PGD-10 checkpoint, and robust-min validation over PGD-20 and PGD-50. The result is aggregate image-space robustness only. Worst-family F1 remained 0.0, so it does not prove that every malware family is robust.

## Accepted Dike BinaryShield Metrics

| Dataset | Transformation | Detector | Robust-min macro F1 | Prediction stability | Attack success rate | Evaluated samples | Acceptance |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Dike | append_overlay | byte_histogram_logistic | 0.977220 | 1.000000 | 0.000000 | 1490 | PASS |
| Dike | section_slack | byte_histogram_logistic | 0.980882 | 1.000000 | 0.000000 | 1477 | PASS |

Dike manifest summary: `9932` PE-parseable rows from `11923` label rows, with split counts `{'train': 6952, 'val': 1489, 'test': 1491}`. Acceptance status: `PASS`.

## PEMML 1k+1k And 5k+5k Metrics

| Stage | Rows | Composition | Clean macro F1 | Append robust macro F1 | Slack robust macro F1 | Append stability | Slack stability | Acceptance |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1k+1k smoke | 2,000 | 1,000 malware + 1,000 benign | 0.883322 | 0.874999 | 0.863145 | 1.000000 | 1.000000 | FAIL |
| 5k+5k subset | 10,000 | 5,000 malware + 5,000 benign | 0.906000 | 0.894983 | 0.889822 | 0.993980 | 0.996986 | FAIL |

The 1k+1k run is a smoke test. The 5k+5k run is the final external subset validation in this paper.

## PEMML 5k+5k Final Subset Metrics

| Metric | Value | Interpretation |
| --- | --- | --- |
| Clean macro F1 | 0.906000 | Clean external subset performance |
| Append robust macro F1 | 0.894983 | Robust performance under append-overlay transformation |
| Slack robust macro F1 | 0.889822 | Robust performance under section-slack transformation |
| Append prediction stability | 0.993980 | Fraction of predictions unchanged under append overlay |
| Slack prediction stability | 0.996986 | Fraction of predictions unchanged under section slack |
| Append attack success rate | 0.004474 | Evasion rate among originally correct evaluated samples |
| Slack attack success rate | 0.001691 | Evasion rate among originally correct evaluated samples |
| Candidate acceptance | FAIL | Failed strict slack executable-section validation gate |

Calculated macro-F1 drops from clean:

- Append overlay: `0.011017`.
- Section slack: `0.016178`.

## PEMML 5k+5k Detector Comparison

| Detector | Robust-min macro F1 | Min prediction stability | Max attack success rate | Min worst-class F1 |
| --- | --- | --- | --- | --- |
| byte_histogram_centroid | 0.662364 | 0.975885 | 0.028921 | 0.659056 |
| byte_histogram_logistic | 0.889822 | 0.993980 | 0.004474 | 0.876712 |
| hybrid_centroid | 0.353073 | 1.000000 | 0.000000 | 0.084942 |
| pe_feature_centroid | 0.353073 | 1.000000 | 0.000000 | 0.084942 |

## PEMML Acceptance Caveat

The 5k+5k candidate acceptance status is `FAIL`. The failed gate is `Slack executable sections unchanged`, with observed `0.9984951091045899` against target `>= 1.00`. This does not erase the metric robustness result; it means BinaryShield correctly surfaced a structural-validation issue that must be fixed before claiming a full protocol pass.

## Unavailable Or Bounded Claims

- Full PEMML validation: not run.
- PEMML family-level validation: not available in current sanitized artifacts.
- Dynamic malware behavior preservation / Level 3 validation: not available; no malware was executed.
- Commercial antivirus comparison: not available in current sanitized artifacts.
- Exact family-level robustness for the FB-MalAT 80/80 result: bounded by the reported worst-family F1 of 0.0 and family counts below 0.80.

## PEMML Statistical Evidence

Source: `reports/binaryshield_pemml_statistical_analysis.md` and `reports/binaryshield/pemml_5k_5k_sanitized_metrics/`. Intervals use 2,000 bootstrap samples with seed `1337` on transformation-evaluable paired rows.

| Statistic | Point | 95% CI / p-value | Scope |
| --- | ---: | --- | --- |
| Append transformed macro F1 | 0.894983 | [0.880152, 0.910294] | paired rows |
| Slack transformed macro F1 | 0.889904 | [0.873175, 0.906477] | paired rows |
| Append prediction stability | 0.993980 | [0.989967, 0.997324] | paired rows |
| Slack prediction stability | 0.996986 | [0.993971, 0.999246] | paired rows |
| Append attack success rate | 0.004474 | [0.001479, 0.008240] | originally correct paired rows |
| Slack attack success rate | 0.001691 | [0.000000, 0.004237] | originally correct paired rows |
| Clean minus append macro-F1 delta | 0.002000 | [-0.001516, 0.005996] | paired rows |
| Clean minus slack macro-F1 delta | -0.000082 | [-0.003163, 0.002934] | paired rows |
| Clean vs append correctness | n/a | McNemar exact p=0.507812 | paired rows |
| Clean vs slack correctness | n/a | McNemar exact p=1.000000 | paired rows |

Interpretation: the append/slack changes are small and their paired macro-F1 confidence intervals include zero. Logistic-versus-centroid paired tests on shared transformed rows strongly favored `byte_histogram_logistic`; for example, logistic versus `byte_histogram_centroid` had exact-binomial p-values `2.0285e-51` on append and `2.26181e-52` on slack.

## ClamAV Baseline Status

Source: `reports/binaryshield_clamav_baseline.md`. The ClamAV baseline script exists and is scan-only, but metrics are unavailable because the official signature database could not be installed. FreshClam reported CDN 403/429 cooldown until `2026-06-27 14:17:16`, and no usable `main`, `daily`, or `bytecode` database existed under `/var/lib/clamav`. No ClamAV detection metrics are claimed.

## Slack Failure Root Cause

Source: `reports/binaryshield_slack_failure_root_cause.md` and `reports/binaryshield/pemml_5k_5k_sanitized_metrics/slack_failure_cases.csv`. The PEMML 5k+5k slack gate failure came from 2 failing validation records out of 1329. Both were classified as `out_of_file_slack_append_within_declared_executable_raw_extent`. The transformer now skips slack regions whose byte ranges are not fully present in the source file. The original PEMML 5k+5k acceptance status remains `FAIL` until rerun under the patched transformer.
