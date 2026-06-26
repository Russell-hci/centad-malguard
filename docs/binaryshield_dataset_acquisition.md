# BinaryShield Dataset Acquisition Runbook

## Purpose

BinaryShield needs raw Windows PE files or PE-derived records to move from image-only malware research to a real malware robustness auditor. This runbook defines the safe dataset route without placing malware, transformed malware, private datasets, model artifacts, or credentials in Git.

## Current Dataset Route

Use this order:

1. **BODMAS public feature vectors** as the completed PE-derived clean classification track.
2. **DikeDataset** as the current primary raw malware/benign PE/OLE route.
3. **SOREL-20M subset** as the primary raw/disarmed malware-only PE route because BODMAS raw binary access is not being requested.
4. **A family-labelled raw/disarmed PE dataset route** such as MOTIF, RawMal-TF, or another approved source if family/type raw-binary labels are needed.
5. **MalwareBazaar** only as a small controlled recent-sample stress test if curated datasets are insufficient.
6. **Benign PE fixtures** for public demo and safe local validation.

This route keeps the project moving without weakening claim boundaries. BODMAS already provides strong public PE-derived feature evidence; SOREL-20M is the next practical source for raw/disarmed PE transformation validation.

The current highest-value gap is no longer basic dataset access or detector quality. DikeDataset now provides a meaningful raw malware/benign task, and the class-balanced byte-histogram logistic detector satisfies the append/slack macro-F1 target under Level-2 PE-preserving transformations. The remaining gaps are external raw malware/benign validation, family-level raw-binary labels, and optional Level 3 sandbox behavior preservation.

## Storage Rules

Never store raw malware inside the repository.

Recommended external layout:

```text
/path/to/external/data/
  bodmas/
    features/
    metadata/
    manifests/
    results/
  sorel20m_subset/
    binaries/
    compressed_binaries/
    metadata/
    features/
    manifests/
    results/
    reports/
  malwarebazaar_spotcheck/
```

The repository may contain:

- sanitized manifests;
- hashes;
- aggregate metrics;
- validation JSON summaries;
- robustness cards;
- implementation code;
- claim-boundary reports.

The repository must not contain:

- malware binaries;
- transformed malware binaries;
- zipped malware samples;
- dataset archives such as `.npz` if they are large/private;
- credentials or API tokens;
- model/checkpoint artifacts;
- instructions framed as commercial antivirus evasion.

Transformation-producing commands should write to external output directories. After an external raw run, import only sanitized artifacts:

```bash
python3 scripts/binaryshield_export_sanitized_artifacts.py \
  --source-dir /path/to/external/sorel20m_subset/results/sorel_raw_multidetector \
  --destination-dir reports/binaryshield/sorel_raw_multidetector_import
```

Then build a reviewable Malware Robustness Card deck:

```bash
python3 scripts/binaryshield_build_card_deck.py \
  --cards-root reports/binaryshield/sorel_raw_multidetector_import \
  --output-dir reports/binaryshield/sorel_raw_multidetector_card_deck \
  --title "SOREL-20M Subset Malware Robustness Card Deck"
```

## BODMAS Public Feature-Vector Track

BODMAS public access currently provides:

- `bodmas.npz` feature vectors for benign and malicious PE records;
- `bodmas_metadata.csv`;
- `bodmas_malware_category.csv`.

The public folder did not contain original raw PE malware binaries when evaluated on Colab. Since private raw BODMAS access will not be requested, BODMAS should now be treated as PE-derived feature-vector evidence, not the primary raw-binary route.

The public BODMAS feature-vector track produced:

| Model | Test Accuracy | Test Macro F1 | Worst-Class F1 |
|---|---:|---:|---:|
| Feature centroid | 72.55% | 72.54% | 71.99% |
| ExtraTrees feature-record detector | 97.84% | 97.83% | 97.65% |

Formal evidence:

```text
reports/binaryshield/bodmas_feature_real/feature_record_gate_report/feature_record_gate_report.md
reports/binaryshield/bodmas_feature_real/bodmas_feature_extra_trees_summary.md
reports/binaryshield/bodmas_realdata_status.md
```

Valid claim:

> BinaryShield validates strong clean malware/benign classification on public BODMAS PE-derived feature vectors.

Invalid claim:

> BinaryShield validates raw PE transformation robustness on BODMAS.

That stronger claim requires raw PE binaries, which are not available in the public BODMAS release.

## SOREL-20M Subset Route

SOREL-20M is now the recommended raw/disarmed PE route for BinaryShield. It provides public AWS Open Data access to a large PE malware corpus and avoids waiting for private BODMAS raw-binary access. Use a bounded subset only; do not sync the full binary tree.

Prepare an external workspace:

```bash
python3 scripts/binaryshield_prepare_sorel_workspace.py \
  --workspace /path/to/external/sorel20m_subset
```

On Colab/Drive:

```bash
python3 scripts/binaryshield_prepare_sorel_workspace.py \
  --workspace /content/drive/MyDrive/malware-robustness-data/sorel20m_subset
```

Check readiness:

```bash
python3 scripts/binaryshield_sorel_readiness.py \
  --workspace /path/to/external/sorel20m_subset \
  --output-dir reports/binaryshield/sorel_readiness
```

List SOREL sources from an environment with AWS CLI:

```bash
aws s3 ls --no-sign-request s3://sorel-20m/09-DEC-2020/binaries/
aws s3 ls --no-sign-request s3://sorel-20m/09-DEC-2020/processed-data/
aws s3 ls --no-sign-request s3://sorel-20m/09-DEC-2020/lightGBM-features/
```

After a controlled subset of disarmed PE files exists in `binaries/`, build a sanitized raw manifest:

```bash
python3 scripts/binaryshield_download_sorel_subset.py \
  --workspace /content/drive/MyDrive/malware-robustness-data/sorel20m_subset \
  --max-samples 100 \
  --max-object-mb 2
```

SOREL binary objects are zlib-compressed in the public bucket. The downloader stores decompressed `MZ` PE files under `binaries/` inside the external workspace and optionally keeps compressed objects only if `--keep-compressed` is passed. Do not copy either form into Git.

Then build a sanitized raw manifest:

```bash
python3 scripts/binaryshield_build_manifest.py \
  --input-dir /path/to/external/sorel20m_subset/binaries \
  --output /path/to/external/sorel20m_subset/manifests/sorel_raw_malware_manifest.csv \
  --label malware \
  --relative-to /path/to/external/sorel20m_subset/binaries \
  --require-pe-parse
```

Validate parse and mutation-region readiness:

```bash
python3 scripts/binaryshield_validate_manifest.py \
  --manifest /path/to/external/sorel20m_subset/manifests/sorel_raw_malware_manifest.csv \
  --root-dir /path/to/external/sorel20m_subset/binaries \
  --output-dir reports/binaryshield/sorel_raw_validation
```

Run the multi-detector raw robustness pipeline only after validation passes:

```bash
python3 scripts/binaryshield_run_pipeline.py \
  --manifest /path/to/external/sorel20m_subset/manifests/sorel_raw_malware_manifest.csv \
  --root-dir /path/to/external/sorel20m_subset/binaries \
  --output-dir /path/to/external/sorel20m_subset/results/sorel_raw_multidetector \
  --report-dir /path/to/external/sorel20m_subset/reports/sorel_raw_multidetector \
  --target label \
  --model-types centroid byte_histogram_centroid hybrid_centroid \
  --candidate-model-type hybrid_centroid \
  --strongest-n 20
```

Import only sanitized outputs:

```bash
python3 scripts/binaryshield_export_sanitized_artifacts.py \
  --source-dir /path/to/external/sorel20m_subset/results/sorel_raw_multidetector \
  --destination-dir reports/binaryshield/sorel_raw_multidetector_import
```

SOREL raw binaries are disarmed malware samples. This supports raw/disarmed malware transformation validation and prediction-stability auditing. It does not by itself support malware/benign raw-binary classification unless a legal benign raw PE source is added.

## Generic Labelled Raw PE Route

BinaryShield now includes a dataset-agnostic metadata manifest builder for approved labelled raw PE datasets. Use this route for MOTIF, RawMal-TF, DikeDataset, internal mentor-provided datasets, or any future dataset that provides:

- a metadata CSV;
- raw PE files stored outside Git;
- either a relative file path column or a SHA-256 column;
- label and optional family/type columns.

Path-based metadata example:

```bash
python3 scripts/binaryshield_build_metadata_manifest.py \
  --metadata /content/drive/MyDrive/malware-robustness-data/rawpe/metadata.csv \
  --binaries-dir /content/drive/MyDrive/malware-robustness-data/rawpe/binaries \
  --output /content/drive/MyDrive/malware-robustness-data/rawpe/manifests/rawpe_manifest.csv \
  --summary-output reports/binaryshield/rawpe_manifest_summary.json \
  --path-column rel_path \
  --label-column label \
  --family-column family \
  --split-column split \
  --relative-to /content/drive/MyDrive/malware-robustness-data/rawpe/binaries \
  --require-pe-parse
```

SHA-based metadata example:

```bash
python3 scripts/binaryshield_build_metadata_manifest.py \
  --metadata /content/drive/MyDrive/malware-robustness-data/rawpe/metadata.csv \
  --binaries-dir /content/drive/MyDrive/malware-robustness-data/rawpe/binaries \
  --output /content/drive/MyDrive/malware-robustness-data/rawpe/manifests/rawpe_manifest.csv \
  --summary-output reports/binaryshield/rawpe_manifest_summary.json \
  --sha256-column sha256 \
  --label-column label \
  --family-column family \
  --relative-to /content/drive/MyDrive/malware-robustness-data/rawpe/binaries \
  --require-pe-parse
```

Use `--compute-hash` only when filenames are not hashes and the dataset is small enough to hash safely in the external workspace. Do not run hash indexing over a very large raw malware corpus unless the storage/runtime cost is acceptable.

After manifest generation, the normal BinaryShield pipeline applies:

```bash
python3 scripts/binaryshield_validate_manifest.py \
  --manifest /content/drive/MyDrive/malware-robustness-data/rawpe/manifests/rawpe_manifest.csv \
  --root-dir /content/drive/MyDrive/malware-robustness-data/rawpe/binaries \
  --output-dir reports/binaryshield/rawpe_validation

python3 scripts/binaryshield_run_pipeline.py \
  --manifest /content/drive/MyDrive/malware-robustness-data/rawpe/manifests/rawpe_manifest.csv \
  --root-dir /content/drive/MyDrive/malware-robustness-data/rawpe/binaries \
  --output-dir /content/drive/MyDrive/malware-robustness-data/rawpe/results/rawpe_multidetector \
  --report-dir /content/drive/MyDrive/malware-robustness-data/rawpe/reports/rawpe_multidetector \
  --target label \
  --model-types centroid byte_histogram_centroid hybrid_centroid \
  --candidate-model-type hybrid_centroid \
  --strongest-n 20
```

For family/type robustness, use `--target family` only if each class has enough samples for train/validation/test splits. Sparse family datasets should be reported as case-study robustness cards rather than high-confidence aggregate model benchmarks.

Recommended role of possible datasets:

| Source | Role | Claim Boundary |
|---|---|---|
| MOTIF | family-labelled disarmed malware case studies | Good for family robustness cards, usually too sparse for broad deep training. |
| RawMal-TF | family/type-labelled raw malware route if files are obtainable | Promising for family/type robustness, but size/provenance/safety must be audited before use. |
| DikeDataset | current malware/benign raw PE/OLE route | Valid for raw malware/benign PE/OLE auditing under Level 1/2 transformations; current logistic detector satisfies the append/slack macro-F1 target. |
| Mentor-provided benign PE set | malware/benign raw-binary evaluation paired with SOREL malware | Valid only for static detection under the approved collection policy. |

## DikeDataset Raw Malware/Benign Route

DikeDataset is currently the best practical raw malware/benign route for BinaryShield. Keep the cloned dataset outside Git. The local evaluated copy used:

```text
/tmp/dike_repo_probe
```

Raw files:

```text
/tmp/dike_repo_probe/files/benign
/tmp/dike_repo_probe/files/malware
```

Labels:

```text
/tmp/dike_repo_probe/labels/benign.csv
/tmp/dike_repo_probe/labels/malware.csv
```

Build the sanitized manifest:

```bash
python3 scripts/binaryshield_build_dike_manifest.py \
  --dataset-root /tmp/dike_repo_probe \
  --output /tmp/binaryshield_dike_run/manifests/dike_pe_manifest.csv \
  --summary-output reports/binaryshield/dike_manifest_summary.json \
  --relative-to /tmp/dike_repo_probe/files \
  --require-pe-parse
```

Current manifest evidence:

| Evidence | Result |
|---|---:|
| Label rows | 11,923 |
| PE-valid manifest rows | 9,932 |
| Skipped due to PE parse failure | 1,991 |
| Malware samples | 8,970 |
| Benign samples | 962 |
| Train / validation / test rows | 6,952 / 1,489 / 1,491 |

Run the append-only multi-detector audit:

```bash
python3 scripts/binaryshield_run_pipeline.py \
  --manifest /tmp/binaryshield_dike_run/manifests/dike_pe_manifest.csv \
  --root-dir /tmp/dike_repo_probe/files \
  --output-dir /tmp/binaryshield_dike_run/results/dike_append_multidetector_fast \
  --report-dir /tmp/binaryshield_dike_run/reports/dike_append_multidetector_fast \
  --target label \
  --model-types centroid byte_histogram_centroid hybrid_centroid \
  --candidate-model-type hybrid_centroid \
  --skip-strongest-n \
  --skip-slack
```

Run the accepted class-balanced byte-histogram logistic candidate:

```bash
python3 scripts/binaryshield_train_pe_baseline.py \
  --manifest /tmp/binaryshield_dike_run/manifests/dike_pe_manifest.csv \
  --root-dir /tmp/dike_repo_probe/files \
  --output-dir /tmp/binaryshield_dike_run/results/dike_logistic_candidate/baseline \
  --target label \
  --model-type byte_histogram_logistic \
  --max-bytes 200000

python3 scripts/binaryshield_eval_pe_baseline.py \
  --manifest /tmp/binaryshield_dike_run/manifests/dike_pe_manifest.csv \
  --root-dir /tmp/dike_repo_probe/files \
  --model /tmp/binaryshield_dike_run/results/dike_logistic_candidate/baseline/byte_histogram_logistic_detector.json \
  --target label \
  --transformation append_overlay \
  --output-dir /tmp/binaryshield_dike_run/results/dike_logistic_candidate/append_eval

python3 scripts/binaryshield_eval_pe_baseline.py \
  --manifest /tmp/binaryshield_dike_run/manifests/dike_pe_manifest.csv \
  --root-dir /tmp/dike_repo_probe/files \
  --model /tmp/binaryshield_dike_run/results/dike_logistic_candidate/baseline/byte_histogram_logistic_detector.json \
  --target label \
  --transformation section_slack \
  --output-dir /tmp/binaryshield_dike_run/results/dike_logistic_candidate/slack_eval
```

Current accepted logistic candidate result:

| Metric | Result |
|---|---:|
| Validation clean accuracy | 99.26% |
| Validation clean macro F1 | 97.89% |
| Append accuracy | 99.19% |
| Append macro F1 | 97.72% |
| Append robust-min macro F1 | 97.72% |
| Append prediction stability | 100.00% |
| Append attack success rate | 0.00% |
| Append worst-class F1 | 95.89% |
| Slack accuracy | 99.32% |
| Slack macro F1 | 98.09% |
| Slack robust-min macro F1 | 98.09% |
| Slack prediction stability | 100.00% |
| Slack attack success rate | 0.00% |
| Slack worst-class F1 | 96.55% |
| Candidate beats strongest baseline gate | PASS, 6 metrics beaten |
| Absolute append/slack macro F1 target | PASS |

Import only sanitized artifacts:

```bash
python3 scripts/binaryshield_export_sanitized_artifacts.py \
  --source-dir /tmp/binaryshield_dike_run/results/dike_logistic_candidate \
  --destination-dir reports/binaryshield/dike_logistic_candidate_import

python3 scripts/binaryshield_export_sanitized_artifacts.py \
  --source-dir /tmp/binaryshield_dike_run/reports/dike_logistic_candidate \
  --destination-dir reports/binaryshield/dike_logistic_candidate_reports_import
```

Claim boundary:

> Dike validates BinaryShield on a meaningful raw malware/benign PE/OLE task and supports the class-balanced byte-histogram logistic detector as the accepted BinaryShield defense under evaluated Level-2 append/slack transformations. It does not prove Level 3 behavior preservation, semantic malware-equivalence preservation, or robustness to all possible PE transformations.

## MalwareBazaar Fallback

MalwareBazaar can provide recent malware samples, but it should remain a controlled fallback because it involves live malware.

Use only if:

- SOREL subset access is blocked or insufficient;
- samples are downloaded only into external storage;
- samples are not committed, redistributed, or copied into reports;
- only hashes, aggregate metrics, validation summaries, and robustness cards are published;
- the project avoids any claim that resembles commercial antivirus evasion.

Recommended role:

> A small recent-malware stress test, not the primary training dataset.

## Go / No-Go Gates

| Gate | Required Before Claiming Progress |
|---|---|
| Parse success | >= 95% on evaluated valid PE files |
| Feature success | >= 95% |
| Append validation | >= 98% transformed PE parse success |
| Slack validation | >= 90% transformed PE parse success when slack exists |
| Entry point unchanged | 100% for append/slack |
| Executable sections unchanged | 100% for append/slack |
| Validation JSON | 100% of transformed samples |
| Robustness cards | 100% of audited samples |
| Multi-detector coverage | at least two detector families, preferably three |
| Safety | 0 malware or transformed malware binaries committed |

## Claim Boundary

After SOREL or any other raw PE evaluation, the project may claim only what the evidence supports:

- **Level 1:** structural PE validity.
- **Level 2:** constrained PE-preserving transformation with executable sections unchanged.
- **Level 3:** sandbox-confirmed behavior preservation only if sandbox validation is actually run.

Do not claim real-world malware behavior preservation from Level 1 or Level 2 alone.
