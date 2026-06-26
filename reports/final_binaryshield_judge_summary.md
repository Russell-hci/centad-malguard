# Final BinaryShield Judge Summary

## One-Sentence Project Summary

BinaryShield is a PE-aware malware robustness auditing framework that tests whether malware detectors remain stable when raw Windows PE files undergo controlled append-overlay and section-slack transformations, while refusing to overclaim when structural validation fails.

## Why The Project Changed Direction

The project began as CenTaD-MalGuard, an adversarial-robustness study of lightweight malware image classifiers on MalImg. That phase showed a useful security lesson: MobileNetV3 achieved clean accuracy `0.979211`, but PGD-20 accuracy dropped to `0.002867`. PGD adversarial training improved PGD-20 accuracy to `0.200000`, but PGD-20 macro F1 remained only `0.031593`. That made the image pipeline a good research cycle, but not the strongest final cybersecurity solution.

BinaryShield is the final solution because it evaluates raw PE files rather than only malware images.

## What BinaryShield Does

1. Builds safe manifests for raw PE datasets.
2. Trains transparent detectors, including a class-balanced byte-histogram logistic detector.
3. Applies append-overlay and section-slack transformations.
4. Validates that transformed files still satisfy checked PE structural properties.
5. Compares clean and transformed predictions.
6. Exports sanitized metrics, detector comparisons, acceptance reports, and robustness evidence without committing malware.

## Best Confirmed Detector

The strongest detector is `byte_histogram_logistic`:

- 256 normalized byte-frequency features.
- Class-balanced logistic training.
- Train-split standardization.
- Validation threshold calibration.
- Transparent and easier to audit than a neural raw-byte detector.

## Dike Result

On the accepted Dike evidence package, `byte_histogram_logistic` achieved:

- Append robust macro F1: `0.977220`.
- Slack robust macro F1: `0.980882`.
- Append prediction stability: `1.000000`.
- Slack prediction stability: `1.000000`.
- Append attack success rate: `0.000000`.
- Slack attack success rate: `0.000000`.
- Acceptance status: `PASS`.

## PEMML External Subset Result

BinaryShield was externally evaluated on a reproducible balanced PEMML subset of 10,000 raw PE files: 5,000 malware and 5,000 benign samples.

| Metric | Value |
| --- | ---: |
| Clean macro F1 | 0.906000 |
| Append robust macro F1 | 0.894983 |
| Slack robust macro F1 | 0.889822 |
| Append prediction stability | 0.993980 |
| Slack prediction stability | 0.996986 |
| Append attack success rate | 0.004474 |
| Slack attack success rate | 0.001691 |
| Candidate acceptance | FAIL |

The append macro-F1 drop from clean was `0.011017`. The slack macro-F1 drop from clean was `0.016178`.

## Important Caveat

The PEMML candidate failed one strict structural validation gate: `Slack executable sections unchanged` observed `0.9984951091045899`, while the target was `>= 1.00`.

This does not invalidate the robustness metrics, but it prevents the project from claiming a full PEMML protocol pass. It is also a strength of BinaryShield: the framework detected a narrow validation issue instead of hiding it.

## What The Project Does Not Claim

- It does not prove malware behavior preservation.
- It does not claim full PEMML validation.
- It does not claim commercial antivirus superiority.
- It does not claim robustness to all malware evasion.
- It does not claim Level 3 sandbox validation.

## Recommended Judge-Facing Framing

The strongest honest framing is:

> BinaryShield turns malware robustness evaluation into a PE-aware audit workflow. It showed strong robustness metrics on Dike and on a balanced 10,000-sample PEMML subset, while also surfacing a strict slack-validation failure that prevents overclaiming.

## Next Engineering Step

Rerun the PEMML 5k+5k slack validation under the patched slack-region guard. Do not run 10k+10k or full PEMML unless explicitly authorized later.

## Statistical Evidence Added

Paired bootstrap analysis on PEMML 5k+5k transformation-evaluable rows found that the clean-minus-append macro-F1 delta was `0.002000` with 95% CI `[-0.001516, 0.005996]`, and the clean-minus-slack delta was `-0.000082` with 95% CI `[-0.003163, 0.002934]`. Exact paired tests found no significant clean-versus-transformed correctness change for append (`p=0.507812`) or slack (`p=1.000000`). Logistic-versus-centroid paired tests strongly favored `byte_histogram_logistic` on shared transformed rows.

## External Baseline Status

A safe ClamAV baseline script was added, but ClamAV metrics were not generated because FreshClam could not obtain an official signature database on RunPod. The official updater reported CDN 403/429 cooldown until `2026-06-27 14:17:16`, and `/var/lib/clamav` contained no usable `main`, `daily`, or `bytecode` database. The project therefore reports ClamAV as prepared but objectively blocked, not as a missing or fabricated result.

## Slack Failure Root Cause

The strict slack gate failed because 2 of 1329 slack validation records changed the executable-section byte range. Root-cause analysis found out-of-file slack mutations: the selected non-executable slack offsets were beyond EOF, causing `bytearray` assignment to append bytes, while malformed PE headers declared executable raw ranges past EOF. The transformer now skips slack regions whose bytes are not fully present in the source file. The original PEMML 5k+5k status remains `FAIL` until the patched slack evaluation is rerun.
