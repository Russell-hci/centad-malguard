# BinaryShield Implementation Report

## Status

This repository now contains the first implementation layer for **MalGuard-X BinaryShield**, a PE-aware malware robustness auditor and defense prototype. The implementation is intentionally safe by default: it can parse, transform, validate, and audit benign or approved external PE files without storing raw malware in Git.

## Implemented Components

| Component | Path | Status |
|---|---|---|
| PE parser and static feature extractor | `binaryshield/pe_features.py` | Implemented |
| BODMAS metadata/raw-binary helper | `binaryshield/bodmas.py` | Implemented |
| SOREL-20M disarmed-binary helper | `binaryshield/sorel.py` | Implemented |
| DikeDataset raw PE/OLE manifest helper | `binaryshield/dike.py` | Implemented |
| Generic labelled raw PE metadata manifest helper | `binaryshield/metadata_manifest.py` | Implemented |
| PE-derived feature-record loader | `binaryshield/feature_records.py` | Implemented |
| Raw byte loader and chunker | `binaryshield/byte_loader.py` | Implemented |
| Mutation-region detector | `binaryshield/mutation_regions.py` | Implemented |
| Append-overlay transformation | `binaryshield/transformations.py` | Implemented |
| Slack-space transformation | `binaryshield/transformations.py` | Implemented |
| Level 1/2/3 validation record | `binaryshield/validation.py` | Implemented |
| Malware Robustness Card generator | `binaryshield/robustness_card.py` | Implemented |
| Manifest loader for external datasets | `binaryshield/datasets.py` | Implemented |
| PE-feature sklearn baseline | `binaryshield/models/pe_feature_model.py` | Implemented |
| Raw-byte histogram centroid baseline | `binaryshield/models/byte_histogram.py` | Implemented, pure Python |
| Validation-calibrated raw-byte histogram detector | `binaryshield/models/byte_histogram.py` | Implemented, pure Python |
| Class-balanced raw-byte histogram logistic detector | `binaryshield/models/byte_histogram.py` | Implemented, pure Python + NumPy |
| Hybrid PE-feature + byte-histogram centroid baseline | `binaryshield/models/byte_histogram.py` | Implemented, pure Python |
| PE-derived feature-record centroid baseline | `binaryshield/models/feature_record_centroid.py` | Implemented, pure Python + NumPy |
| PE-derived feature-record sklearn baseline | `binaryshield/models/feature_record_sklearn.py` | Implemented, Colab real-data evaluated |
| Repo-output safety guard for raw-PE transformations | `binaryshield/safety.py` | Implemented |
| Sanitized artifact exporter | `binaryshield/artifact_export.py` | Implemented |
| Raw-byte neural baseline | `binaryshield/models/byte_cnn.py` | Implemented, requires PyTorch |
| Hybrid BinaryShield neural detector | `binaryshield/models/hybrid_binaryshield.py` | Implemented, requires PyTorch |
| CAR-FP-MalAT objective description | `binaryshield/training/car_fp_malat.py` | Implemented |
| Class-adaptive weight update | `binaryshield/training/adaptive_weights.py` | Implemented |
| Optional PyTorch raw/hybrid training pipeline | `binaryshield/training/torch_pipeline.py` | Implemented, requires PyTorch |
| CAR-FP-MalAT paired clean/transformed training | `binaryshield/training/torch_pipeline.py` | Implemented, Colab smoke-tested |
| Transformation robustness evaluation | `binaryshield/evaluation/evaluate_transformations.py` | Implemented |
| Multi-detector evaluation matrix | `binaryshield/evaluation/evaluate_transfer.py` | Implemented |
| Source-selected transfer attack evaluation | `binaryshield/evaluation/transfer_attack.py` | Implemented |
| Multi-detector candidate-vs-baseline summary | `binaryshield/evaluation/multi_detector_summary.py` | Implemented |
| Transformation validation summary | `binaryshield/evaluation/validation_summary.py` | Implemented |
| Consolidated Robustness Card deck | `binaryshield/evaluation/card_deck.py` | Implemented |
| Synthetic benign PE fixture generator | `scripts/binaryshield_make_fixture.py` | Implemented |
| Single-file audit CLI | `scripts/binaryshield_audit.py` | Implemented |
| Manifest builder | `scripts/binaryshield_build_manifest.py` | Implemented |
| BODMAS sanitized manifest builder | `scripts/binaryshield_build_bodmas_manifest.py` | Implemented |
| DikeDataset manifest builder | `scripts/binaryshield_build_dike_manifest.py` | Implemented |
| Generic labelled raw PE metadata manifest builder | `scripts/binaryshield_build_metadata_manifest.py` | Implemented |
| Manifest validation sweep | `scripts/binaryshield_validate_manifest.py` | Implemented |
| PE-derived feature-record training | `scripts/binaryshield_train_feature_records.py` | Implemented |
| PE-derived feature-record evaluation | `scripts/binaryshield_eval_feature_records.py` | Implemented |
| PE-feature baseline training | `scripts/binaryshield_train_pe_baseline.py` | Implemented |
| PE-feature transformation evaluation | `scripts/binaryshield_eval_pe_baseline.py` | Implemented |
| Strongest-of-N evaluation | `scripts/binaryshield_eval_strongest_n.py` | Implemented |
| Multi-detector transfer-style evaluation | `scripts/binaryshield_eval_transfer.py` | Implemented |
| Source-selected transfer attack CLI | `scripts/binaryshield_eval_transfer_attack.py` | Implemented |
| Raw-byte / hybrid PyTorch training CLI | `scripts/binaryshield_train_torch_detector.py` | Implemented, requires PyTorch |
| Multi-detector summary CLI | `scripts/binaryshield_multi_detector_report.py` | Implemented |
| Transformation validation summary CLI | `scripts/binaryshield_summarize_transform_validations.py` | Implemented |
| End-to-end multi-detector pipeline runner | `scripts/binaryshield_run_pipeline.py` | Implemented |
| BODMAS external workspace preparer | `scripts/binaryshield_prepare_bodmas_workspace.py` | Implemented |
| SOREL external workspace preparer | `scripts/binaryshield_prepare_sorel_workspace.py` | Implemented |
| SOREL readiness checker | `scripts/binaryshield_sorel_readiness.py` | Implemented |
| SOREL bounded subset downloader | `scripts/binaryshield_download_sorel_subset.py` | Implemented |
| Real-data readiness checker | `scripts/binaryshield_realdata_readiness.py` | Implemented |
| Sanitized external-run artifact importer | `scripts/binaryshield_export_sanitized_artifacts.py` | Implemented |
| Consolidated Robustness Card deck CLI | `scripts/binaryshield_build_card_deck.py` | Implemented |
| Colab GPU runbook | `docs/binaryshield_colab_runbook.md` | Implemented |

## Validation Levels

BinaryShield does not claim full behavior preservation by default.

| Level | Meaning | Evidence |
|---:|---|---|
| 1 | Structural PE validity | Original and transformed files parse as PE, hash changed, entry point unchanged, section table valid. |
| 2 | Constrained behavior-preserving assumption | Level 1 plus executable sections unchanged and modifications limited to append/slack regions. |
| 3 | Sandbox-confirmed behavior preservation | Level 2 plus sandbox execution/behavior validation, if approved infrastructure exists. |

## Safety Boundary

- Raw PE malware datasets must be stored outside Git.
- Transformed malware binaries must be stored outside Git.
- Public demo should use benign PE fixtures or sanitized robustness cards.
- Transformation-producing CLIs now refuse to write transformed outputs inside the repository when evaluated samples are external to the repository, unless `--allow-repo-output` is explicitly supplied for controlled non-malware fixtures.
- Real raw-PE runs should use an external result directory such as `/path/to/external/bodmas/results/...`; Git should receive only sanitized summaries, metrics, validation JSON, and robustness cards.
- External raw-run artifacts should be imported through `scripts/binaryshield_export_sanitized_artifacts.py`, which allowlists text report artifacts and blocks binaries, archives, checkpoints, datasets, detector/model artifacts including detector JSON files, and token-like content.
- Imported card folders can be consolidated into a single reviewable card deck using `scripts/binaryshield_build_card_deck.py`.

## Generalizability Design

BinaryShield is implemented as a framework, not a single-model trick. The evaluation layer can test the same validated PE transformations against multiple detector families:

1. PE-feature centroid baseline.
2. Raw-byte histogram centroid baseline.
3. Hybrid PE-feature + raw-byte histogram centroid baseline.
4. PE-feature sklearn baseline, when scikit-learn is available.
5. Raw-byte neural baseline, when PyTorch is available.
6. Hybrid BinaryShield neural detector, when PyTorch is available.

The framework should claim model generalizability only after multi-detector and transfer-style evaluations demonstrate it.

The acceptance report now includes an explicit candidate-improvement gate:

> BinaryShield should only be claimed as an improved final defense if the candidate detector beats the strongest baseline on at least two robustness metrics.

The checked metrics include robust-min macro F1, transformed accuracy, transformed macro F1, prediction stability, attack success rate, worst-class F1, and weak-class counts.

The acceptance report also checks transformation validity evidence:

- validation JSON generation rate;
- transformed PE parse success;
- entry point unchanged;
- executable sections unchanged;
- separate append and slack thresholds.

## Current Claim Boundary

Validated now:

- BinaryShield can parse PE files, extract static features, identify mutation regions, apply append/slack transformations, validate structural preservation, and generate audit cards.
- BinaryShield can build a manifest over external PE files without copying those files into Git.
- BinaryShield can run a dependency-light PE-feature centroid baseline and append-transformation evaluation on synthetic benign PE fixtures.
- Raw-byte and hybrid neural detector training code is implemented. It is compile-validated locally and smoke-tested on a Colab T4 GPU using synthetic benign PE fixtures.
- Hybrid transformed-training is implemented as clean + append-transformed training views and smoke-tested on a Colab T4 GPU.
- Three dependency-free detector families can now be trained and evaluated in one end-to-end pipeline: PE-feature centroid, raw-byte histogram centroid, and hybrid centroid.
- A fourth dependency-free detector family, validation-calibrated raw-byte histogram classification, is implemented. It calibrates the malware/benign threshold on validation macro F1 to address class imbalance without requiring scikit-learn or PyTorch.
- Multi-detector transfer-style evaluation and candidate-vs-baseline acceptance gating are implemented and smoke-tested locally and on Colab.
- Source-selected transfer attack evaluation is implemented: transformations are selected against one source detector, then the same transformed files are evaluated against other detectors.
- Transformation validation summaries are generated from per-sample JSON records and fed into acceptance gates.
- BODMAS-specific sanitized manifest tooling is implemented for both feature-vector records and raw malware binaries.
- A generic metadata-to-manifest builder is implemented for approved labelled raw PE datasets such as MOTIF, RawMal-TF, DikeDataset, mentor-provided datasets, or any source with path-based or SHA-256-based metadata.
- PE-derived feature-record training/evaluation is implemented for BODMAS `bodmas.npz` style data. This supports malware/benign clean classification evidence, but not PE-preserving transformation evidence unless raw binaries are also present.
- The public BODMAS feature-vector dataset has been evaluated on Colab. The strongest feature-record model tested so far, ExtraTrees, reached 97.84% test accuracy, 97.83% macro F1, and 97.65% worst-class F1 for malware/benign detection.
- A real-data readiness checker now reports whether BODMAS feature-vector and raw-PE tracks are ready, including missing files, local storage constraints, and safe next commands.
- Public BODMAS access did not provide original raw PE binaries during the Colab check. Because private raw BODMAS access is not being requested, BODMAS is treated as a PE-derived feature-vector track only.
- SOREL-20M public AWS access has been verified. SOREL binary objects are zlib-compressed; after decompression, the bounded sampled objects start with `MZ` and parse as PE files.
- A bounded 40-sample SOREL-20M disarmed-malware subset has been evaluated through the raw BinaryShield path with append and slack transformations where available.
- On that bounded SOREL subset, parse success and feature extraction success were both 100%, append-region availability was 100%, and Level-2 slack availability was 60%.
- The SOREL append/slack acceptance evidence passes structural transformation gates, card coverage gates, multi-detector gates, and transfer-style evaluation gates.
- The SOREL evidence remains a single-label malware-only transformation-stability smoke test. It does not prove malware/benign raw-binary classification or family-level robustness.
- A larger 200-sample SOREL-20M disarmed-malware subset has been evaluated through the append-overlay raw BinaryShield path.
- On the 200-sample SOREL run, PE parse success and feature extraction success were both 100%, Level-2 append availability was 99%, and Level-2 slack availability was 61%.
- The 200-sample SOREL append run evaluated 30 held-out transformed samples across three detector families: PE-feature centroid, raw-byte histogram centroid, and hybrid centroid.
- The corrected 200-sample SOREL append validation shows 100% validation JSON generation, 100% transformed PE parse success, 100% entry point preservation, 100% executable-section preservation, and 100% Level-2-or-higher validation for evaluated transformations.
- The 200-sample SOREL append run generated 450 Malware Robustness Cards across three detector families; all imported artifacts are sanitized reports, not raw or transformed PE binaries.
- DikeDataset has been validated as the first meaningful raw malware/benign PE/OLE route. The manifest builder processed 11,923 labelled rows and produced 9,932 PE-valid manifest rows after skipping 1,991 files that failed PE parsing.
- The Dike PE-valid manifest contains 8,970 malware samples and 962 benign samples split into 6,952 train, 1,489 validation, and 1,491 test rows.
- On Dike, manifest-level PE parse and feature extraction success are both 100%. Append-region availability is 99.99%, and Level-2 slack availability measured during manifest validation is 98.79%.
- The Dike append-only test run evaluated 1,490 transformed samples and generated 100% validation JSON coverage and 100% Malware Robustness Card coverage for evaluated append transformations.
- Five dependency-light detector variants have now been evaluated on Dike evidence: PE-feature centroid, raw-byte histogram centroid, hybrid centroid, validation-calibrated raw-byte histogram, and class-balanced raw-byte histogram logistic detection.
- The validation-calibrated raw-byte histogram candidate was an intermediate improvement, but did not satisfy the final macro-F1 target.
- The class-balanced raw-byte histogram logistic candidate is the current accepted BinaryShield defense on Dike. It reached 97.72% append macro F1, 98.09% slack macro F1, 100% prediction stability, 0% attack success rate, and passed the configured acceptance report across append, slack, multi-detector, transfer-style, validation, and card-coverage gates.

Not yet validated:

- Malware-family performance on raw PE binaries with reliable family labels.
- CAR-FP-MalAT training effectiveness on real raw-PE data with a nontrivial robustness gap.
- Level 3 sandbox behavior preservation.
- AutoAttack-style or semantic malware-transformation robustness beyond the evaluated PE append/slack threat model.
- Generalization to a second raw malware/benign dataset at the same quality level.

## Real-Data Evidence Status

### BODMAS Public Feature-Vector Track

Public BODMAS is currently useful for PE-derived malware/benign clean classification, not raw-binary transformation robustness.

| Evidence | Result |
|---|---:|
| Candidate model | ExtraTrees feature-record detector |
| Test accuracy | 97.84% |
| Test macro F1 | 97.83% |
| Worst-class F1 | 97.65% |
| Feature baseline accuracy | 72.55% |
| Feature baseline macro F1 | 72.54% |
| Gate status | `PARTIAL_PASS` |

Evidence files:

```text
reports/binaryshield/bodmas_feature_real/feature_record_gate_report/feature_record_gate_report.md
reports/binaryshield/bodmas_feature_real/feature_record_gate_report/feature_record_gate_report.json
```

Claim boundary:

> This validates clean malware/benign classification on public BODMAS PE-derived feature vectors only. It does not validate raw PE transformations, behavior preservation, transfer robustness, or CAR-FP-MalAT effectiveness.

### SOREL-20M Bounded Raw/Disarmed PE Track

SOREL-20M is now the primary raw/disarmed PE route because public BODMAS raw binaries are unavailable.

#### 40-Sample Append + Slack Smoke Evidence

| Gate | Result |
|---|---:|
| Sample count | 40 |
| PE parse success | 100% |
| Feature extraction success | 100% |
| Append region availability | 100% |
| Level-2 slack availability | 60% |
| Append transformed PE parse success | 100% |
| Append entry point unchanged | 100% |
| Append executable sections unchanged | 100% |
| Slack transformed PE parse success | 100% on eligible generated records |
| Slack entry point unchanged | 100% on eligible generated records |
| Slack executable sections unchanged | 100% on eligible generated records |
| Robustness Card deck coverage | 288 cards |
| Detector families evaluated | 3 |
| Transformations evaluated | append overlay and section slack |

Evidence files:

```text
reports/binaryshield/sorel_subset_validation/validation_summary.json
reports/binaryshield/sorel_subset_multidetector_with_slack_adjusted/acceptance/acceptance_report.md
reports/binaryshield/sorel_subset_multidetector_with_slack_adjusted/acceptance/acceptance_report.json
reports/binaryshield/sorel_subset_with_slack_card_deck/robustness_card_deck.md
reports/binaryshield/sorel_subset_with_slack_card_deck/robustness_card_deck.json
```

The adjusted SOREL acceptance report is still `FAIL` overall because the candidate-improvement gate correctly remains unmet:

> On the bounded single-label malware-only smoke subset, all simple detectors are already perfectly stable, so the candidate cannot honestly beat the strongest baseline on two robustness metrics.

This is a scientific limitation of the current evidence, not an implementation failure.

#### 200-Sample Append-Only Validation Evidence

The larger SOREL run validates the raw PE audit pipeline on 200 public disarmed malware samples. This run is append-only; slack-space transformation remains validated by the smaller 40-sample smoke run.

| Gate | Result |
|---|---:|
| Sample count | 200 |
| PE parse success | 100% |
| Feature extraction success | 100% |
| Level-2 append availability | 99% |
| Level-2 slack availability measured during manifest validation | 61% |
| Held-out transformed evaluation samples | 30 |
| Append transformed PE parse success | 100% |
| Append entry point unchanged | 100% |
| Append executable sections unchanged | 100% |
| Append Level-2-or-higher validation | 100% |
| Append validation JSON generation | 100% |
| Append Robustness Card coverage | 100% |
| Detector families evaluated | 3 |
| Transfer-style evaluation present | yes |
| Robustness Cards generated | 450 |
| Candidate beats strongest baseline | no |

Detector-level append metrics on the held-out malware-only test split:

| Detector | Clean Accuracy | Transformed Accuracy | Robust-Min Macro F1 | Prediction Stability | Attack Success Rate |
|---|---:|---:|---:|---:|---:|
| PE-feature centroid | 100% | 100% | 100% | 100% | 0% |
| Raw-byte histogram centroid | 100% | 100% | 100% | 100% | 0% |
| Hybrid centroid | 100% | 100% | 100% | 100% | 0% |

Evidence files:

```text
reports/binaryshield/sorel200_validation/validation_summary.json
reports/binaryshield/sorel200_append_multidetector/manifest_validation/validation_summary.json
reports/binaryshield/sorel200_append_multidetector/acceptance/acceptance_report.md
reports/binaryshield/sorel200_append_multidetector/acceptance/acceptance_report.json
reports/binaryshield/sorel200_append_multidetector/multi_detector/multi_detector_summary.md
reports/binaryshield/sorel200_append_multidetector/multi_detector/multi_detector_summary.json
reports/binaryshield/sorel200_append_multidetector_import/hybrid_centroid_append_eval/validation_summary/transformation_validation_summary.json
reports/binaryshield/sorel200_append_card_deck/robustness_card_deck.md
reports/binaryshield/sorel200_append_card_deck/robustness_card_deck.json
reports/binaryshield/sorel200_run_summary.json
```

Safety review:

- The sanitized artifact exporter copied only text/CSV/JSON/Markdown summaries into the repository.
- Raw SOREL disarmed PE files and transformed PE files remained in the external Colab workspace.
- Local safety scans found no `.exe`, `.bin`, `.dll`, `.sys`, archive, checkpoint, pickle/joblib, `.npz`, or detector JSON artifacts inside the imported SOREL200 report paths.
- Token scanning found no obvious credential patterns in the imported SOREL200 report paths.
- The sanitizer status is `REVIEW_REQUIRED` because it blocked 453 unsafe remote artifacts before import, which is the expected behavior for transformed binaries and detector artifacts.

Claim boundary:

> The 200-sample SOREL run validates BinaryShield as a real PE-aware robustness auditing pipeline for public disarmed malware samples. It does not yet prove an improved final detector, malware/benign raw-binary classification, malware-family robustness, or Level 3 behavior preservation.

### DikeDataset Raw Malware/Benign PE/OLE Track

DikeDataset is now the strongest available raw malware/benign route because public BODMAS raw binaries are unavailable and SOREL's public raw-binary route is malware-only. Raw Dike files were kept outside Git under `/tmp/dike_repo_probe`, and only sanitized report artifacts were imported.

Manifest evidence:

| Evidence | Result |
|---|---:|
| Label rows read | 11,923 |
| PE-valid manifest rows | 9,932 |
| Files skipped due to PE parse failure | 1,991 |
| Malware samples | 8,970 |
| Benign samples | 962 |
| Train / validation / test rows | 6,952 / 1,489 / 1,491 |
| Manifest PE parse success | 100% |
| Feature extraction success | 100% |
| Append region availability | 99.99% |
| Level-2 slack availability measured during validation | 98.79% |

Detector comparison on the held-out Dike test split:

| Detector | Transform | Clean Accuracy | Clean Macro F1 | Transformed Accuracy | Transformed Macro F1 | Robust-Min Macro F1 | Stability | ASR | Worst-Class F1 |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| PE-feature centroid | append | 86.04% | 59.52% | 86.04% | 59.52% | 59.52% | 100.00% | 0.00% | 26.76% |
| Raw-byte histogram centroid | append | 81.41% | 67.29% | 81.34% | 67.12% | 67.12% | 99.93% | 0.08% | 45.49% |
| Hybrid centroid | append | 86.04% | 59.52% | 86.04% | 59.52% | 59.52% | 100.00% | 0.00% | 26.76% |
| Validation-calibrated raw-byte histogram | append | 88.05% | 69.83% | 87.79% | 68.82% | 68.82% | 99.73% | 0.30% | 44.51% |
| Class-balanced byte-histogram logistic | append | 99.19% | 97.72% | 99.19% | 97.72% | 97.72% | 100.00% | 0.00% | 95.89% |
| Class-balanced byte-histogram logistic | slack | 99.32% | 98.09% | 99.32% | 98.09% | 98.09% | 100.00% | 0.00% | 96.55% |

Candidate-improvement result:

| Gate | Result |
|---|---|
| Candidate beats strongest baseline on at least two robustness metrics | PASS, 6 metrics beaten |
| Append transformed F1 >= 85% | PASS, 97.72% observed |
| Append validation JSON coverage | PASS, 100% |
| Append transformed PE parse success | PASS, 100% |
| Append entry point unchanged | PASS, 100% |
| Append executable sections unchanged | PASS, 100% |
| Append Robustness Card coverage | PASS, 100% |
| Slack transformed F1 >= 85% | PASS, 98.09% observed |
| Slack validation JSON coverage | PASS, 100% |
| Slack transformed PE parse success | PASS, 100% |
| Slack entry point unchanged | PASS, 100% |
| Slack executable sections unchanged | PASS, 100% |
| Slack Robustness Card coverage | PASS, 100% |
| Overall acceptance report | PASS |

Evidence files:

```text
reports/binaryshield/dike_manifest_summary.json
reports/binaryshield/dike_append_multidetector_reports_import/multi_detector/multi_detector_summary.json
reports/binaryshield/dike_append_multidetector_reports_import/acceptance/acceptance_report.json
reports/binaryshield/dike_append_card_deck/robustness_card_deck.md
reports/binaryshield/dike_calibrated_candidate_import/baseline/metrics.json
reports/binaryshield/dike_calibrated_candidate_import/append_eval/metrics_byte_histogram_calibrated_append_overlay.json
reports/binaryshield/dike_calibrated_candidate_import/append_eval/validation_summary/transformation_validation_summary.json
reports/binaryshield/dike_calibrated_candidate_import/append_eval/card_summary/robustness_card_summary.json
reports/binaryshield/dike_calibrated_candidate_reports_import/multi_detector/multi_detector_summary.json
reports/binaryshield/dike_calibrated_candidate_reports_import/acceptance/acceptance_report.json
reports/binaryshield/dike_logistic_candidate_import/append_eval/metrics_byte_histogram_logistic_append_overlay.json
reports/binaryshield/dike_logistic_candidate_import/slack_eval/metrics_byte_histogram_logistic_section_slack.json
reports/binaryshield/dike_logistic_candidate_import/strongest_n_append_rerun/strongest_of_n_summary.json
reports/binaryshield/dike_logistic_candidate_reports_import/multi_detector/multi_detector_summary.json
reports/binaryshield/dike_logistic_candidate_reports_import/acceptance/acceptance_report.json
reports/binaryshield/dike_logistic_candidate_card_deck/robustness_card_deck.md
```

Safety review:

- Raw and transformed Dike binaries remained outside Git.
- The sanitized exporter blocked transformed `.bin` files and detector JSON model artifacts.
- Local safety scans found no `.exe`, `.bin`, `.dll`, `.sys`, archive, checkpoint, pickle/joblib, `.npz`, or detector JSON artifacts inside the imported Dike report paths.
- Token scanning found no obvious credential patterns in the imported Dike report paths.

Claim boundary:

> Dike validates BinaryShield on a meaningful raw malware/benign PE/OLE task and supports the class-balanced byte-histogram logistic detector as the current accepted BinaryShield defense under Level-2 append/slack transformations. It does not prove Level 3 behavior preservation, semantic malware-equivalence preservation, or robustness beyond the evaluated static PE-level transformations.

## Next Implementation Step

The next highest-value gap is no longer dataset acquisition, append-only malware-only scaling, or basic detector quality. The current SOREL evidence shows that the audit pipeline works structurally, and the Dike evidence now provides a target-passing raw malware/benign detector under append and slack Level-2 transformations. The remaining scientific gaps are stronger external validation, family-level labels, and Level 3 behavior-preservation evidence.

The next implementation step should harden the evidence package while keeping raw binaries outside Git:

1. reproduce the Dike logistic run on the final judging machine or Colab runtime;
2. run a second raw malware/benign dataset if one is legally available;
3. add a family-labelled raw/disarmed PE track if reliable family labels are available;
4. add optional Level 3 sandbox validation only if approved infrastructure exists.

BinaryShield now has a generic metadata manifest builder for that step:

```bash
python3 scripts/binaryshield_build_metadata_manifest.py \
  --metadata /content/drive/MyDrive/malware-robustness-data/rawpe/metadata.csv \
  --binaries-dir /content/drive/MyDrive/malware-robustness-data/rawpe/binaries \
  --output /content/drive/MyDrive/malware-robustness-data/rawpe/manifests/rawpe_manifest.csv \
  --summary-output reports/binaryshield/rawpe_manifest_summary.json \
  --path-column rel_path \
  --sha256-column sha256 \
  --label-column label \
  --family-column family \
  --relative-to /content/drive/MyDrive/malware-robustness-data/rawpe/binaries \
  --require-pe-parse
```

Use either `--path-column` or `--sha256-column` depending on the dataset layout. Use both only when the metadata provides both and path matching should be attempted before SHA matching.

Optional SOREL scaling remains useful for engineering confidence and report coverage, but it should be presented as PE audit scaling, not as proof of improved malware detection:

```bash
python3 scripts/binaryshield_download_sorel_subset.py \
  --workspace /content/drive/MyDrive/malware-robustness-data/sorel20m_subset \
  --max-samples 500 \
  --max-object-mb 2

python3 scripts/binaryshield_build_manifest.py \
  --input-dir /content/drive/MyDrive/malware-robustness-data/sorel20m_subset/binaries \
  --output /content/drive/MyDrive/malware-robustness-data/sorel20m_subset/manifests/sorel_raw_malware_manifest.csv \
  --label malware \
  --relative-to /content/drive/MyDrive/malware-robustness-data/sorel20m_subset/binaries \
  --require-pe-parse

python3 scripts/binaryshield_validate_manifest.py \
  --manifest /content/drive/MyDrive/malware-robustness-data/sorel20m_subset/manifests/sorel_raw_malware_manifest.csv \
  --root-dir /content/drive/MyDrive/malware-robustness-data/sorel20m_subset/binaries \
  --output-dir reports/binaryshield/sorel_raw_validation

python3 scripts/binaryshield_run_pipeline.py \
  --manifest /content/drive/MyDrive/malware-robustness-data/sorel20m_subset/manifests/sorel_raw_malware_manifest.csv \
  --root-dir /content/drive/MyDrive/malware-robustness-data/sorel20m_subset/binaries \
  --output-dir /content/drive/MyDrive/malware-robustness-data/sorel20m_subset/results/sorel_raw_multidetector \
  --report-dir /content/drive/MyDrive/malware-robustness-data/sorel20m_subset/reports/sorel_raw_multidetector \
  --target label \
  --model-types centroid byte_histogram_centroid hybrid_centroid \
  --candidate-model-type hybrid_centroid \
  --strongest-n 20

python3 scripts/binaryshield_export_sanitized_artifacts.py \
  --source-dir /content/drive/MyDrive/malware-robustness-data/sorel20m_subset/results/sorel_raw_multidetector \
  --destination-dir reports/binaryshield/sorel_raw_multidetector_import

python3 scripts/binaryshield_build_card_deck.py \
  --cards-root reports/binaryshield/sorel_raw_multidetector_import \
  --output-dir reports/binaryshield/sorel_raw_multidetector_card_deck \
  --title "SOREL-20M Raw/Disarmed PE Malware Robustness Card Deck"
```

To prove raw malware/benign classification, add a legal benign raw PE source or a public raw benign/malware PE dataset in external storage. Until then, the raw-binary claim should remain limited to disarmed-malware transformation validation and detector-stability auditing.

## Safe Demo Commands

```bash
python3 scripts/binaryshield_make_fixture.py
python3 scripts/binaryshield_audit.py --input binaryshield_outputs/fixtures/minimal_pe.exe --output-dir binaryshield_outputs/audit
```

## Verified Local Smoke Tests

The following checks were run locally on synthetic benign PE fixtures:

```bash
python3 -m compileall binaryshield scripts/binaryshield_*.py tests
python3 -m unittest tests.test_binaryshield_core tests.test_binaryshield_evaluation tests.test_binaryshield_acceptance tests.test_binaryshield_multi_detector_summary
python3 scripts/binaryshield_build_manifest.py --input-dir binaryshield_outputs/demo_dataset --output reports/binaryshield/demo_manifest.csv --relative-to binaryshield_outputs/demo_dataset --label-from-parent --family-from-parent --require-pe-parse
python3 scripts/binaryshield_validate_manifest.py --manifest reports/binaryshield/demo_manifest.csv --root-dir binaryshield_outputs/demo_dataset --output-dir reports/binaryshield/demo_manifest_validation
python3 scripts/binaryshield_train_pe_baseline.py --manifest reports/binaryshield/demo_manifest.csv --root-dir binaryshield_outputs/demo_dataset --output-dir results/binaryshield/demo_pe_feature_baseline --target label --model-type centroid
python3 scripts/binaryshield_eval_pe_baseline.py --manifest reports/binaryshield/demo_manifest.csv --root-dir binaryshield_outputs/demo_dataset --model results/binaryshield/demo_pe_feature_baseline/pe_feature_detector.json --split test --transformation append_overlay --output-dir results/binaryshield/demo_pe_feature_eval
python3 scripts/binaryshield_eval_strongest_n.py --manifest reports/binaryshield/demo_manifest.csv --root-dir binaryshield_outputs/demo_dataset --model results/binaryshield/demo_pe_feature_baseline/pe_feature_detector.json --split test --transformation append_overlay --n 3 --output-dir results/binaryshield/demo_strongest_n
python3 scripts/binaryshield_eval_transfer.py --manifest reports/binaryshield/demo_manifest.csv --root-dir binaryshield_outputs/demo_dataset --models results/binaryshield/demo_pe_feature_baseline/pe_feature_detector.json --split test --transformations append_overlay section_slack --output-dir results/binaryshield/demo_transfer_eval
python3 scripts/binaryshield_run_pipeline.py --manifest reports/binaryshield/demo_manifest.csv --root-dir binaryshield_outputs/demo_dataset --output-dir results/binaryshield/pipeline_multidetector_smoke --report-dir reports/binaryshield/pipeline_multidetector_smoke --target label --model-types centroid byte_histogram_centroid hybrid_centroid --candidate-model-type hybrid_centroid --strongest-n 2
```

Generated Git-safe artifacts:

| Artifact | Purpose |
|---|---|
| `reports/binaryshield/demo_validation.json` | Single-file Level 2 validation record. |
| `reports/binaryshield/demo_robustness_card.md` | Single-file Malware Robustness Card. |
| `reports/binaryshield/demo_manifest.csv` | Safe manifest format example. |
| `reports/binaryshield/demo_manifest_validation/validation_summary.json` | Parse/feature validation summary. |
| `reports/binaryshield/demo_manifest_validation/validation_rows.csv` | Per-sample validation rows. |
| `reports/binaryshield/demo_pe_feature_baseline_metrics.json` | Synthetic PE-feature baseline smoke-test metrics. |
| `reports/binaryshield/demo_transformation_metrics.json` | Synthetic append-transformation robustness smoke-test metrics. |
| `reports/binaryshield/demo_predictions_append_overlay.csv` | Synthetic transformed prediction rows. |
| `reports/binaryshield/demo_strongest_of_n_summary.json` | Synthetic strongest-of-N evaluation summary. |
| `reports/binaryshield/demo_transfer_matrix.json` | Synthetic multi-transformation detector evaluation matrix. |
| `reports/binaryshield/pipeline_multidetector_smoke/multi_detector/multi_detector_summary.md` | Synthetic three-detector comparison summary with candidate-vs-baseline gate. |
| `reports/binaryshield/pipeline_multidetector_smoke/acceptance/acceptance_report.md` | Synthetic acceptance report showing which gates pass/fail without overclaiming. |
| `reports/binaryshield/transfer_attack_smoke/transfer_attack_matrix.json` | Synthetic source-selected transfer attack matrix. |
| `reports/binaryshield/transfer_attack_smoke/selected_transformations.csv` | Selected transformed files and source-detector selection reasons. |
| `reports/binaryshield/transfer_attack_smoke/validation_summary/transformation_validation_summary.md` | Structural validation summary for source-selected transfer transforms. |
| `reports/binaryshield/card_deck_smoke/robustness_card_deck.md` | Consolidated synthetic Malware Robustness Card deck covering generated cards across detector and transformation views. |

The synthetic baseline metrics are **not** evidence of real malware robustness. They only verify that the BinaryShield data, model, transformation, validation, and reporting interfaces execute end-to-end.

The synthetic acceptance report now verifies that append/slack transformation records satisfy the structural goals on the benign fixture dataset:

- validation JSON generation: 100%;
- transformed PE parse success: 100%;
- entry point unchanged: 100%;
- executable sections unchanged: 100%.

These are structural PE-preservation checks only; they are not Level 3 sandbox behavior evidence.

## Verified Colab GPU Smoke Test

Colab session type:

```text
Hardware: T4
PyTorch: 2.11.0+cu128
CUDA available: true
GPU: Tesla T4
```

The Colab smoke run verified:

- BinaryShield source bundle unpacked successfully when macOS metadata files were excluded.
- `compileall` passed remotely.
- unit tests passed remotely.
- synthetic PE fixture manifest/validation ran remotely.
- one-epoch `raw_byte_cnn` training ran on CUDA.
- one-epoch `hybrid_binaryshield` training ran on CUDA.
- one-epoch `hybrid_binaryshield` transformed-training smoke run completed on CUDA with clean + append-transformed training views.
- one-epoch `hybrid_binaryshield` CAR-FP-MalAT smoke run completed on CUDA with paired clean/transformed views, class weights, and consistency loss.
- append-transformation evaluation ran against both torch checkpoints.
- the updated three-detector dependency-free pipeline ran successfully in a fresh Colab T4 session.
- the BODMAS manifest builder and PE-derived feature-record training/evaluation tests ran successfully in a fresh Colab T4 session.
- Colab summary artifacts were downloaded only as JSON/Markdown reports, not transformed binaries.

Downloaded summary artifacts:

| Artifact | Purpose |
|---|---|
| `reports/binaryshield/colab_smoke/results/binaryshield/colab_raw_byte_cnn/training_summary.json` | Raw-byte GPU smoke training summary. |
| `reports/binaryshield/colab_smoke/results/binaryshield/colab_hybrid_binaryshield/training_summary.json` | Hybrid GPU smoke training summary. |
| `reports/binaryshield/colab_smoke/results/binaryshield/colab_raw_byte_cnn_append_eval/metrics_torch_raw_byte_cnn_append_overlay.json` | Raw-byte append-evaluation smoke metrics. |
| `reports/binaryshield/colab_smoke/results/binaryshield/colab_hybrid_binaryshield_append_eval/metrics_torch_hybrid_binaryshield_append_overlay.json` | Hybrid append-evaluation smoke metrics. |
| `reports/binaryshield/colab_transformed_training/training_summary.json` | Hybrid transformed-training GPU smoke summary. |
| `reports/binaryshield/colab_transformed_training/metrics_torch_hybrid_binaryshield_append_overlay.json` | Hybrid transformed-training append-evaluation smoke metrics. |
| `reports/binaryshield/colab_car_fp_malat_smoke/training_summary.json` | CAR-FP-MalAT paired clean/transformed GPU smoke summary. |
| `reports/binaryshield/colab_multidetector_smoke/pipeline_summary.json` | Colab three-detector pipeline smoke summary. |
| `reports/binaryshield/colab_multidetector_smoke/multi_detector_summary.md` | Colab multi-detector candidate-vs-baseline summary. |
| `reports/binaryshield/colab_multidetector_smoke/acceptance_report.md` | Colab acceptance gate report for the synthetic smoke run. |

These artifacts prove executable GPU code paths, not real malware robustness.

Additional Colab command result:

```text
REMOTE_BINARYSHIELD_BODMAS_TOOLING_SMOKE_OK
REMOTE_BINARYSHIELD_VALIDATION_GATE_SMOKE_OK
REMOTE_BINARYSHIELD_TRANSFER_ATTACK_SMOKE_OK
REMOTE_BINARYSHIELD_CAR_FP_MALAT_SMOKE_OK
```

This verifies the BODMAS manifest, feature-record tooling, multi-detector pipeline, transformation-validation acceptance gates, source-selected transfer attack code paths, and CAR-FP-MalAT paired training code path on Colab. It does not mean the real BODMAS dataset has been downloaded or evaluated.

## Verified Public BODMAS Feature-Vector Evaluation

The public BODMAS Google Drive folder was downloaded and evaluated on Google Colab T4. It contained:

- `bodmas.npz`
- `bodmas_metadata.csv`
- `bodmas_malware_category.csv`

It did not contain the original raw PE malware binaries. Therefore, the completed evaluation is clean PE-derived feature-vector classification only, not raw-PE transformation robustness.

Dataset scale:

| Item | Value |
|---|---:|
| Records | 134,435 |
| Feature dimension | 2,381 |
| Benign records | 77,142 |
| Malware records | 57,293 |

Results:

| Model | Test Accuracy | Test Macro F1 | Worst-Class F1 |
|---|---:|---:|---:|
| Feature centroid | 72.55% | 72.54% | 71.99% |
| ExtraTrees feature-record detector | 97.84% | 97.83% | 97.65% |

Evidence:

- `reports/binaryshield/bodmas_realdata_status.md`
- `reports/binaryshield/bodmas_feature_real/bodmas_feature_extra_trees_summary.json`
- `results/binaryshield/bodmas_feature_real/feature_record_extra_trees_label_test_metrics.json`

Claim boundary:

> BinaryShield has been validated on public BODMAS PE-derived feature vectors for malware/benign clean classification. Public BODMAS did not provide raw PE binaries during the Colab check, so raw-PE transformation robustness is now validated only on the bounded SOREL-20M disarmed-malware subset, not on BODMAS.

## PyTorch Training Commands

After installing a GPU-enabled PyTorch runtime and preparing a raw PE manifest outside Git, the same training CLI can train raw-byte or hybrid detectors. For SOREL this is currently a malware-only track unless a legal raw benign PE source is added:

```bash
python3 scripts/binaryshield_train_torch_detector.py \
  --manifest /content/drive/MyDrive/malware-robustness-data/sorel20m_subset/manifests/sorel_raw_malware_manifest.csv \
  --root-dir /content/drive/MyDrive/malware-robustness-data/sorel20m_subset/binaries \
  --output-dir /content/drive/MyDrive/malware-robustness-data/sorel20m_subset/results/sorel_raw_byte_cnn \
  --model-type raw_byte_cnn \
  --target label

python3 scripts/binaryshield_train_torch_detector.py \
  --manifest /content/drive/MyDrive/malware-robustness-data/sorel20m_subset/manifests/sorel_raw_malware_manifest.csv \
  --root-dir /content/drive/MyDrive/malware-robustness-data/sorel20m_subset/binaries \
  --output-dir /content/drive/MyDrive/malware-robustness-data/sorel20m_subset/results/sorel_hybrid_binaryshield \
  --model-type hybrid_binaryshield \
  --target label
```
