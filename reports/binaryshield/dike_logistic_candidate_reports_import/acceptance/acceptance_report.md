# BinaryShield Acceptance Report

**Overall status:** PASS

| Gate | Status | Observed | Target | Evidence |
|---|---|---:|---:|---|
| PE parse success | PASS | 1.0 | >= 0.95 | /tmp/binaryshield_dike_run/reports/dike_append_calibrated_fast/manifest_validation/validation_summary.json |
| Feature extraction success | PASS | 1.0 | >= 0.95 | /tmp/binaryshield_dike_run/reports/dike_append_calibrated_fast/manifest_validation/validation_summary.json |
| Append prediction stability | PASS | 1.0 | >= 0.85 | /tmp/binaryshield_dike_run/results/dike_logistic_candidate/append_eval/metrics_byte_histogram_logistic_append_overlay.json |
| Append transformed F1 | PASS | 0.9772199119373777 | >= 0.85 | /tmp/binaryshield_dike_run/results/dike_logistic_candidate/append_eval/metrics_byte_histogram_logistic_append_overlay.json |
| Append attack success rate | PASS | 0.0 | <= 0.70 | /tmp/binaryshield_dike_run/results/dike_logistic_candidate/append_eval/metrics_byte_histogram_logistic_append_overlay.json |
| Append validation JSON generation | PASS | 1.0 | >= 1.00 | /tmp/binaryshield_dike_run/results/dike_logistic_candidate/append_eval/validation_summary/transformation_validation_summary.json |
| Append transformed PE parse success | PASS | 1.0 | >= 0.98 | /tmp/binaryshield_dike_run/results/dike_logistic_candidate/append_eval/validation_summary/transformation_validation_summary.json |
| Append entry point unchanged | PASS | 1.0 | >= 1.00 | /tmp/binaryshield_dike_run/results/dike_logistic_candidate/append_eval/validation_summary/transformation_validation_summary.json |
| Append executable sections unchanged | PASS | 1.0 | >= 1.00 | /tmp/binaryshield_dike_run/results/dike_logistic_candidate/append_eval/validation_summary/transformation_validation_summary.json |
| Append Robustness Card coverage | PASS | 1.0 | >= 1.00 | /tmp/binaryshield_dike_run/results/dike_logistic_candidate/append_eval/card_summary/robustness_card_summary.json |
| Slack transformed F1 | PASS | 0.9808817438127784 | >= 0.70 | /tmp/binaryshield_dike_run/results/dike_logistic_candidate/slack_eval/metrics_byte_histogram_logistic_section_slack.json |
| Slack validation JSON generation | PASS | 1.0 | >= 1.00 | /tmp/binaryshield_dike_run/results/dike_logistic_candidate/slack_eval/validation_summary/transformation_validation_summary.json |
| Slack transformed PE parse success | PASS | 1.0 | >= 0.90 | /tmp/binaryshield_dike_run/results/dike_logistic_candidate/slack_eval/validation_summary/transformation_validation_summary.json |
| Slack entry point unchanged | PASS | 1.0 | >= 1.00 | /tmp/binaryshield_dike_run/results/dike_logistic_candidate/slack_eval/validation_summary/transformation_validation_summary.json |
| Slack executable sections unchanged | PASS | 1.0 | >= 1.00 | /tmp/binaryshield_dike_run/results/dike_logistic_candidate/slack_eval/validation_summary/transformation_validation_summary.json |
| Slack Robustness Card coverage | PASS | 1.0 | >= 1.00 | /tmp/binaryshield_dike_run/results/dike_logistic_candidate/slack_eval/card_summary/robustness_card_summary.json |
| Multiple detector families | PASS | 4.0 | >= 2 | /tmp/binaryshield_dike_run/results/dike_logistic_candidate/combined_transfer_matrix.json |
| Transfer-style evaluation | PASS | 2.0 | >= 1 transformation | /tmp/binaryshield_dike_run/results/dike_logistic_candidate/combined_transfer_matrix.json |
| Candidate beats strongest baseline | PASS | 6.0 | >= 2 robustness metrics | /tmp/binaryshield_dike_run/reports/dike_logistic_candidate/multi_detector/multi_detector_summary.json |

## Claim Boundary

PASS means the supplied artifacts satisfy BinaryShield's configured gates. It does not imply full malware behavior preservation without Level 3 sandbox evidence.
