# BinaryShield Multi-Detector Summary

**Candidate detector:** byte_histogram_logistic

**Baseline detectors:** byte_histogram_centroid, hybrid_centroid, pe_feature_centroid

**Detector count:** 4

**Transformation count:** 2

## Detector Aggregates

| Detector | Transformations | Robust-Min Macro F1 | Transformed Macro F1 Min | Prediction Stability Min | Attack Success Rate Max |
|---|---:|---:|---:|---:|---:|
| byte_histogram_centroid | 1 | 0.6711756767484323 | 0.6711756767484323 | 0.9993288590604027 | 0.0008244023083264633 |
| byte_histogram_logistic | 2 | 0.9772199119373777 | 0.9772199119373777 | 1.0 | 0.0 |
| hybrid_centroid | 1 | 0.5952271492456221 | 0.5952271492456221 | 1.0 | 0.0 |
| pe_feature_centroid | 1 | 0.5952271492456221 | 0.5952271492456221 | 1.0 | 0.0 |

## Candidate Comparison

**Status:** PASS

**Metrics beaten:** 6 / 2 required

| Metric | Status | Candidate | Strongest Baseline |
|---|---|---:|---:|
| robust_min_macro_f1 | BEATS_BASELINE | 0.9772199119373777 | 0.6711756767484323 |
| transformed_accuracy | BEATS_BASELINE | 0.9919463087248322 | 0.8604026845637583 |
| transformed_macro_f1 | BEATS_BASELINE | 0.9772199119373777 | 0.6711756767484323 |
| prediction_stability | DOES_NOT_BEAT_BASELINE | 1.0 | 1.0 |
| attack_success_rate | DOES_NOT_BEAT_BASELINE | 0.0 | 0.0 |
| transformed_worst_class_f1 | BEATS_BASELINE | 0.9589041095890412 | 0.4549019607843138 |
| transformed_classes_below_f1_050 | BEATS_BASELINE | 0.0 | 1.0 |
| transformed_classes_below_f1_080 | BEATS_BASELINE | 0.0 | 1.0 |

## Claim Boundary

This summary compares detectors only on the supplied transfer matrix. It does not validate malware behavior preservation beyond the validation records used during evaluation.
