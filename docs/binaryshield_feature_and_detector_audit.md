# BinaryShield Feature And Detector Audit

This audit is derived from source code only. It does not infer undocumented feature behavior from report text.

## PE Feature Extraction

Source: `binaryshield/pe_features.py`

`parse_pe(path)` reads the file bytes, validates a DOS `MZ` header, reads the PE offset from `0x3C`, validates `PE\0\0`, parses the COFF header, and supports PE32 (`0x10B`) and PE32+ (`0x20B`) optional headers.

Top-level record fields:

- `path`: parsed path string.
- `sha256`: SHA-256 of the full input file.
- `file_size`: full byte length.
- `machine`: COFF machine value.
- `timestamp`: COFF timestamp.
- `number_of_sections`: COFF section count.
- `characteristics`: COFF characteristics.
- `optional_header_magic`: PE32 or PE32+ optional-header magic.
- `address_of_entry_point`: optional-header entry point RVA.
- `image_base`: PE image base.
- `section_alignment`: optional-header section alignment.
- `file_alignment`: optional-header file alignment.
- `subsystem`: optional-header subsystem.
- `dll_characteristics`: optional-header DLL characteristics.
- `overlay_offset`: minimum of maximum declared section raw end and file size.
- `overlay_size`: bytes after `overlay_offset`.
- `file_entropy`: Shannon entropy over the full file bytes.
- `sections`: list of parsed section records.

Per-section fields:

- `name`: section name decoded as ASCII with replacement.
- `virtual_size`
- `virtual_address`
- `raw_size`
- `raw_pointer`
- `characteristics`
- `entropy`: Shannon entropy over available raw section bytes.
- `raw_end`: `raw_pointer + raw_size`.
- `is_executable`: true when `IMAGE_SCN_MEM_EXECUTE` or `IMAGE_SCN_CNT_CODE` is set.
- `slack_start`: `raw_pointer + min(max(virtual_size, 0), raw_size)` when `raw_size > 0`.
- `slack_size`: `max(0, raw_end - slack_start)`.

`PEFeatureRecord.to_vector()` emits 21 numeric features:

- `file_size`
- `machine`
- `timestamp`
- `number_of_sections`
- `characteristics`
- `optional_header_magic`
- `address_of_entry_point`
- `image_base`
- `section_alignment`
- `file_alignment`
- `subsystem`
- `dll_characteristics`
- `overlay_size`
- `overlay_ratio`
- `file_entropy`
- `executable_section_count`
- `total_raw_section_size`
- `max_section_entropy`
- `mean_section_entropy`
- `total_slack_size`
- `slack_ratio`

Potential dataset-artifact risks: `timestamp`, `overlay_size`, `overlay_ratio`, `file_size`, section counts, and byte distribution can encode collection/source artifacts. This is why the Dike result requires second-dataset validation.

## Byte-Level Features

Sources: `binaryshield/byte_loader.py`, `binaryshield/models/byte_histogram.py`

`load_bytes(path, max_bytes=2_000_000)` reads raw bytes, optionally truncating to the first `max_bytes`. The byte histogram detectors call `byte_histogram(path, max_bytes)` with `max_bytes` supplied by the CLI. The CLI default is `None`, so accepted Dike training/evaluation uses full files unless the external command supplied `--max-bytes`.

`byte_histogram()` emits exactly 256 features, one per byte value `0..255`.

The histogram values are normalized frequencies, not raw counts:

```text
count(byte_value) / total_count
```

No byte value outside `0..255` contributes to the histogram. If the file had no counted bytes, the denominator falls back to `1.0`.

`hybrid_vector()` prefixes the 21 PE features with `pe_` and adds 256 byte histogram features named `byte_hist_000` through `byte_hist_255`, for 277 total hybrid features when all PE vector keys are present.

## Preprocessing, Scaling, Imputation, Clipping

- PE centroid detectors use raw numeric PE features with missing values filled as `0.0` during distance calculations.
- Byte-histogram centroid detectors use normalized byte frequencies directly.
- Hybrid centroid detectors use raw PE numeric features plus normalized byte frequencies directly. There is no scaling between PE and byte histogram dimensions.
- `PEFeatureSklearnDetector.random_forest()` wraps `StandardScaler()` and `RandomForestClassifier(class_weight="balanced")`.
- `ByteHistogramLogisticDetector` computes train-split mean and standard deviation over byte-frequency histograms, replaces scales below `1e-8` with `1.0`, and trains on standardized features.
- Logistic sigmoid inputs are clipped to `[-40, 40]` for numerical stability.
- No imputation is needed for byte histograms because every vector has 256 values.

## Train/Validation/Test Leakage Audit

Training script: `scripts/binaryshield_train_pe_baseline.py`

- Training uses only manifest rows with `split == "train"`.
- Validation uses manifest rows with `split == "val"`, falling back to `test` only if no validation rows exist.
- Detectors with `calibrate()` use validation paths and labels for threshold calibration only.
- Evaluation script `scripts/binaryshield_eval_pe_baseline.py` defaults to `split="test"`.

No direct train/test feature fitting leakage was found in source for the accepted byte-histogram logistic detector. Remaining risk is dataset-level leakage or artifacts in the Dike collection, not a code path that fits on test rows.

## Detector Input Format And Dimensions

- PE-feature centroid: file paths -> parse PE -> 21-feature dict.
- PE-feature sklearn: file paths -> parse PE -> 21-feature vector sorted by feature name.
- Byte-histogram centroid: file paths -> 256 normalized byte-frequency vector.
- Calibrated byte-histogram: file paths -> 256 normalized byte-frequency vector.
- Byte-histogram logistic: file paths -> 256 normalized byte-frequency vector -> train-standardized vector.
- Hybrid centroid: file paths -> 277-feature dict, consisting of 21 PE features plus 256 byte histogram features.
- Feature-record detectors: BODMAS-style `.npz` rows, not raw PE transformation features.
- Torch detectors: optional raw-byte or hybrid neural paths, not part of the accepted Dike logistic claim.

## Detector Audit

### PE-Feature Centroid Detector

Source: `binaryshield/models/pe_feature_centroid.py`

- Detector name: `pe_feature_centroid`.
- Feature input: 21 PE structural features from `parse_pe().to_vector()`.
- Training: computes a mean vector per label.
- Prediction: nearest centroid by Euclidean distance.
- Threshold/calibration: none.
- Class balancing: none.
- Dependencies: Python standard library.
- Saved artifact: JSON with centroids, feature names, class names, detector name.
- Strengths: simple, transparent, dependency-light.
- Weaknesses: unscaled raw PE features can dominate distance; weak on imbalanced Dike results.

### Byte-Histogram Centroid Detector

Source: `binaryshield/models/byte_histogram.py`

- Detector name: `byte_histogram_centroid`.
- Feature input: 256 normalized byte-frequency bins.
- Training: computes a mean histogram per label.
- Prediction: nearest centroid by Euclidean distance.
- Threshold/calibration: none.
- Class balancing: none.
- Dependencies: Python standard library.
- Saved artifact: JSON with centroids, class names, detector name, `max_bytes`.
- Strengths: transparent raw-byte baseline.
- Weaknesses: nearest-centroid decision is weak under class imbalance and non-linear class structure.

### Hybrid Centroid Detector

Source: `binaryshield/models/byte_histogram.py`

- Detector name: `hybrid_centroid`.
- Feature input: 21 PE features plus 256 byte histogram bins.
- Training: computes a mean hybrid vector per label.
- Prediction: nearest centroid by Euclidean distance.
- Threshold/calibration: none.
- Class balancing: none.
- Dependencies: Python standard library.
- Saved artifact: JSON with centroids, feature names, class names, detector name, `max_bytes`.
- Strengths: combines PE structure and raw-byte distribution.
- Weaknesses: no scaling, so PE numeric magnitudes can dominate byte frequencies.

### Calibrated Byte-Histogram Detector

Source: `binaryshield/models/byte_histogram.py`

- Detector name: `byte_histogram_calibrated`.
- Feature input: 256 normalized byte-frequency bins.
- Training: computes class centroids.
- Prediction: binary score is distance to positive centroid minus distance to negative centroid.
- Threshold logic: threshold is selected from validation score midpoints.
- Calibration logic: chooses threshold that maximizes validation macro F1, then accuracy.
- Class balancing: indirect only, through macro-F1 threshold selection.
- Dependencies: Python standard library.
- Saved artifact: JSON with centroids, binary labels, threshold, validation metrics, detector name, `max_bytes`.
- Strengths: improves centroid behavior on imbalanced binary tasks without heavy dependencies.
- Weaknesses: still centroid-based and less expressive than logistic regression.

### Class-Balanced Byte-Histogram Logistic Detector

Source: `binaryshield/models/byte_histogram.py`

- Detector name: `byte_histogram_logistic`.
- Feature input: 256 normalized byte-frequency bins.
- Training: custom NumPy logistic training for binary labels only.
- Prediction: standardized histogram dot weights plus bias; positive label if score is above calibrated threshold.
- Threshold logic: validation threshold selected from logit score midpoints.
- Calibration logic: maximizes validation macro F1, then accuracy.
- Class balancing: inverse-frequency sample weights: positive samples get `n / (2 * positives)` and negative samples get `n / (2 * negatives)`.
- Dependencies: NumPy.
- Saved artifact: JSON with weights, bias, train mean, train scale, class labels, threshold, validation metrics, hyperparameters.
- Strengths: transparent linear model, train-split standardization, explicit imbalance handling, strong accepted Dike result.
- Weaknesses: coefficients are standardized-feature weights; magnitude depends on train-set scaling. Strong Dike performance may reflect Dike-specific artifacts and needs second-dataset validation.

## Assumptions And Unresolved Risks

- Exact external command lines for the accepted run are reconstructed from scripts and imported paths; the raw run log is not present.
- Logistic coefficient values are unavailable in the sanitized package because the saved detector JSON was blocked from import.
- Family-level validation is not established.
- Level 3 behavioral preservation is not established.
