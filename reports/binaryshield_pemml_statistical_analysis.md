# BinaryShield PEMML Statistical Analysis

Run directory: `/path/to/runs/pemml_5k_5k`
Bootstrap samples: `2000`
Seed: `1337`

Important scope note: the run artifacts provide paired clean/transformed predictions for transformation-evaluable rows. Full-test clean macro F1 remains the point estimate reported in the main PEMML evidence; paired confidence intervals below are computed on the rows where both clean and transformed predictions are available.

## Confidence Intervals

| condition | metric | point | ci_low | ci_high | bootstrap_samples | seed |
| --- | --- | --- | --- | --- | --- | --- |
| append | clean_macro_f1_paired | 0.896982 | 0.881536 | 0.91227 | 2000 | 1337 |
| append | transformed_macro_f1 | 0.894983 | 0.880152 | 0.910294 | 2000 | 1337 |
| append | prediction_stability | 0.99398 | 0.989967 | 0.997324 | 2000 | 1337 |
| append | attack_success_rate | 0.00447427 | 0.00147929 | 0.00824001 | 2000 | 1337 |
| slack | clean_macro_f1_paired | 0.889822 | 0.872478 | 0.907014 | 2000 | 1337 |
| slack | transformed_macro_f1 | 0.889904 | 0.873175 | 0.906477 | 2000 | 1337 |
| slack | prediction_stability | 0.996986 | 0.993971 | 0.999246 | 2000 | 1337 |
| slack | attack_success_rate | 0.00169062 | 0 | 0.00423738 | 2000 | 1337 |

## Paired Deltas

| comparison | metric | point | ci_low | ci_high | bootstrap_samples | seed |
| --- | --- | --- | --- | --- | --- | --- |
| clean_minus_append | macro_f1_delta | 0.00199965 | -0.00151565 | 0.00599578 | 2000 | 1337 |
| clean_minus_slack | macro_f1_delta | -8.17614e-05 | -0.00316265 | 0.00293367 | 2000 | 1337 |
| append_minus_slack | macro_f1_delta | -0.00219628 | -0.00590364 | 0.00084986 | 2000 | 1337 |

## Prediction Flip Analysis

| condition | n | clean_correct_to_transformed_incorrect | clean_incorrect_to_transformed_correct | unchanged_correct | unchanged_incorrect | total_prediction_flips | total_label_correctness_flips |
| --- | --- | --- | --- | --- | --- | --- | --- |
| append | 1495 | 6 | 3 | 1335 | 151 | 9 | 9 |
| slack | 1327 | 2 | 2 | 1181 | 142 | 4 | 4 |

## McNemar Tests

| comparison | n | b_clean_correct_transformed_incorrect | c_clean_incorrect_transformed_correct | p_value_exact_binomial | method | b_a_correct_b_incorrect | c_a_incorrect_b_correct |
| --- | --- | --- | --- | --- | --- | --- | --- |
| clean_vs_append | 1495 | 6 | 3 | 0.507812 | exact two-sided binomial McNemar test | nan | nan |
| byte_histogram_logistic_vs_byte_histogram_centroid_append | 1495 | nan | nan | 2.0285e-51 | exact two-sided binomial McNemar test | 390 | 77 |
| byte_histogram_logistic_vs_hybrid_centroid_append | 1495 | nan | nan | 2.92566e-109 | exact two-sided binomial McNemar test | 637 | 79 |
| byte_histogram_logistic_vs_pe_feature_centroid_append | 1495 | nan | nan | 2.92566e-109 | exact two-sided binomial McNemar test | 637 | 79 |
| clean_vs_slack | 1327 | 2 | 2 | 1 | exact two-sided binomial McNemar test | nan | nan |
| byte_histogram_logistic_vs_byte_histogram_centroid_slack | 1327 | nan | nan | 2.26181e-52 | exact two-sided binomial McNemar test | 370 | 66 |
| byte_histogram_logistic_vs_hybrid_centroid_slack | 1327 | nan | nan | 6.49731e-115 | exact two-sided binomial McNemar test | 638 | 71 |
| byte_histogram_logistic_vs_pe_feature_centroid_slack | 1327 | nan | nan | 6.49731e-115 | exact two-sided binomial McNemar test | 638 | 71 |

## Interpretation

The append and slack drops are small in point-estimate terms. The paired intervals and McNemar tests should be interpreted within the transformation-evaluable subsets, not as full-test clean-performance intervals. Detector-vs-detector tests compare transformed correctness on shared sample IDs and do not imply commercial antivirus superiority.
