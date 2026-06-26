# BinaryShield Sanitized Evidence Tables

These tables are generated only from sanitized metrics and prediction reports. They do not include raw malware bytes, transformed binaries, or unsafe paths.

## Prediction Stability

| transformation | evaluated_samples | stable_predictions | prediction_stability | failed_transformations |
| --- | --- | --- | --- | --- |
| append_overlay | 296 | 296 | 1.0 | 4 |
| section_slack | 266 | 266 | 1.0 | 32 |

## Attack Success Rate

| transformation | clean_correct_samples | attack_successes | attack_success_rate |
| --- | --- | --- | --- |
| append_overlay | 259 | 0 | 0.0 |
| section_slack | 230 | 0 | 0.0 |

## Validation Coverage

| transformation | validation_json_count | expected_count | validation_json_generation_rate | pe_parse_transformed_rate | entry_point_unchanged_rate | executable_sections_unchanged_rate | level_2_or_higher_rate |
| --- | --- | --- | --- | --- | --- | --- | --- |
| append_overlay | 296 | 296 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| section_slack | 268 | 268 | 1.0 | 1.0 | 1.0 | 0.9925373134328358 | 0.9925373134328358 |

## Accepted-vs-Baseline Deltas

| metric | status | candidate | strongest_baseline | delta_candidate_minus_baseline |
| --- | --- | --- | --- | --- |
| robust_min_macro_f1 | BEATS_BASELINE | 0.8631452581032413 | 0.6728907232815525 | 0.19025453482168875 |
| transformed_accuracy | BEATS_BASELINE | 0.8646616541353384 | 0.6729323308270677 | 0.19172932330827064 |
| transformed_macro_f1 | BEATS_BASELINE | 0.8631452581032413 | 0.6728907232815525 | 0.19025453482168875 |
| prediction_stability | DOES_NOT_BEAT_BASELINE | 1.0 | 1.0 | 0.0 |
| attack_success_rate | DOES_NOT_BEAT_BASELINE | 0.0 | 0.0 | 0.0 |
| transformed_worst_class_f1 | BEATS_BASELINE | 0.8487394957983193 | 0.6494464944649447 | 0.19929300133337458 |
| transformed_classes_below_f1_050 | DOES_NOT_BEAT_BASELINE | 0.0 | 0.0 | 0.0 |
| transformed_classes_below_f1_080 | BEATS_BASELINE | 0.0 | 2.0 | -2.0 |

## Logistic Coefficients

Status: `PASS`

Weights apply to standardized normalized byte-frequency bins. Positive weights move the logit toward the positive label stored in the detector; negative weights move it toward the negative label.
