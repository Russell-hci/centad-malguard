# BinaryShield Sanitized Evidence Tables

These tables are generated only from sanitized metrics and prediction reports. They do not include raw malware bytes, transformed binaries, or unsafe paths.

## Prediction Stability

| transformation | evaluated_samples | stable_predictions | prediction_stability | failed_transformations |
| --- | --- | --- | --- | --- |
| append_overlay | 1495 | 1486 | 0.9939799331103679 | 5 |
| section_slack | 1327 | 1323 | 0.9969856819894499 | 171 |

## Attack Success Rate

| transformation | clean_correct_samples | attack_successes | attack_success_rate |
| --- | --- | --- | --- |
| append_overlay | 1341 | 6 | 0.0044742729306487695 |
| section_slack | 1183 | 2 | 0.0016906170752324597 |

## Validation Coverage

| transformation | validation_json_count | expected_count | validation_json_generation_rate | pe_parse_transformed_rate | entry_point_unchanged_rate | executable_sections_unchanged_rate | level_2_or_higher_rate |
| --- | --- | --- | --- | --- | --- | --- | --- |
| append_overlay | 1495 | 1495 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| section_slack | 1329 | 1329 | 1.0 | 1.0 | 1.0 | 0.9984951091045899 | 0.9984951091045899 |

## Accepted-vs-Baseline Deltas

| metric | status | candidate | strongest_baseline | delta_candidate_minus_baseline |
| --- | --- | --- | --- | --- |
| robust_min_macro_f1 | BEATS_BASELINE | 0.8898221822459005 | 0.662363979190804 | 0.22745820305509645 |
| transformed_accuracy | BEATS_BASELINE | 0.8914845516201959 | 0.6623963828183873 | 0.2290881688018086 |
| transformed_macro_f1 | BEATS_BASELINE | 0.8899039436567784 | 0.662363979190804 | 0.22753996446597435 |
| prediction_stability | DOES_NOT_BEAT_BASELINE | 0.9939799331103679 | 1.0 | -0.006020066889632081 |
| attack_success_rate | DOES_NOT_BEAT_BASELINE | 0.0044742729306487695 | 0.0 | 0.0044742729306487695 |
| transformed_worst_class_f1 | BEATS_BASELINE | 0.8767123287671234 | 0.6590563165905632 | 0.21765601217656017 |
| transformed_classes_below_f1_050 | DOES_NOT_BEAT_BASELINE | 0.0 | 0.0 | 0.0 |
| transformed_classes_below_f1_080 | BEATS_BASELINE | 0.0 | 2.0 | -2.0 |

## Logistic Coefficients

Status: `PASS`

Weights apply to standardized normalized byte-frequency bins. Positive weights move the logit toward the positive label stored in the detector; negative weights move it toward the negative label.
