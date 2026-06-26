# BinaryShield Final Robustness Card

## Scope

BinaryShield was externally evaluated on a reproducible balanced PEMML subset of 10,000 raw PE files: 5,000 malware and 5,000 benign samples. This is subset validation, not full PEMML validation.

## Candidate Detector

`byte_histogram_logistic`: 256 normalized byte-frequency features, train-split standardization, class-balanced logistic regression, and validation-threshold calibration.

## PEMML 5k+5k Metrics

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

## Statistical Evidence

Paired bootstrap intervals on transformation-evaluable rows show small clean-to-transformed macro-F1 deltas whose 95% intervals include zero: clean-minus-append `0.002000` CI `[-0.001516, 0.005996]`; clean-minus-slack `-0.000082` CI `[-0.003163, 0.002934]`. Exact paired tests also found no significant correctness change for clean versus append (`p=0.507812`) or clean versus slack (`p=1.000000`).

## External Baseline

A safe ClamAV baseline script was added, but ClamAV metrics are blocked because no official signature database was available on RunPod. FreshClam reported CDN 403/429 cooldown until `2026-06-27 14:17:16`. No ClamAV detection result is claimed.

## Acceptance Caveat

The strict PEMML slack executable-section preservation gate observed `0.9984951091045899` against target `>= 1.00`, so the PEMML candidate remains a failed acceptance candidate. Root-cause analysis found 2 out-of-file slack mutations on malformed/truncated PE layouts; the transformer now skips slack ranges whose bytes are not fully present in the source file.

## Claim Boundary

BinaryShield supports a bounded claim: under the evaluated append/slack protocol, the learned byte-histogram detector showed high stability on Dike and the PEMML 5k+5k subset, while the audit framework surfaced and explained a narrow structural-validation failure. It does not prove malware functionality preservation, commercial antivirus superiority, full PEMML validation, or universal adversarial robustness.
