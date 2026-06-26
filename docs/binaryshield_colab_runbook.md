# BinaryShield Colab Runbook

## Purpose

Use Google Colab for BinaryShield compute tasks when the local interpreter lacks PyTorch or GPU support.

Do not place authentication tokens in repository files, notebooks, scripts, logs, or command history. Authenticate through the Colab CLI or browser flow only.

## Current Verified Colab State

Verified on 18 June 2026:

- `colab new --gpu T4` successfully created a T4 runtime.
- Remote Python version: 3.12.13.
- Remote PyTorch version: 2.11.0+cu128.
- CUDA available: true.
- GPU: Tesla T4.
- BinaryShield compile and unit tests passed after packaging with macOS metadata excluded.
- One-epoch raw-byte and hybrid BinaryShield smoke training ran on synthetic benign PE fixtures.
- One-epoch hybrid BinaryShield transformed-training smoke run completed with clean + append-transformed training views.

This is infrastructure validation only. The synthetic smoke metrics are not malware-robustness evidence.

## Create A GPU Session

```bash
colab new --gpu T4
colab sessions
```

Use the returned session id in subsequent commands.

## Build A Clean Source Bundle

Use `COPYFILE_DISABLE=1` on macOS to avoid AppleDouble `._*.py` metadata files.

```bash
COPYFILE_DISABLE=1 tar \
  --exclude='__pycache__' \
  --exclude='*.pyc' \
  --exclude='._*' \
  --exclude='.DS_Store' \
  -czf /tmp/binaryshield_src.tgz \
  binaryshield \
  scripts/binaryshield_*.py \
  tests \
  configs/binaryshield_*.yaml \
  docs/binaryshield_implementation_report.md \
  docs/binaryshield_dataset_acquisition.md \
  reports/binaryshield \
  README.md \
  .gitignore
```

Upload:

```bash
colab upload --session <SESSION_ID> /tmp/binaryshield_src.tgz /content/binaryshield_src.tgz
```

## Remote Smoke Test

Run a Python script through:

```bash
colab exec --session <SESSION_ID> --file /path/to/local_script.py
```

The script should:

1. unpack `/content/binaryshield_src.tgz`;
2. run `python -m compileall binaryshield scripts tests`;
3. run `python -m unittest tests.test_binaryshield_core tests.test_binaryshield_evaluation`;
4. generate synthetic PE fixtures;
5. train `raw_byte_cnn` for one epoch;
6. train `hybrid_binaryshield` for one epoch;
7. evaluate both under append transformation;
8. download only JSON/CSV/Markdown summaries.

Do not download transformed PE binaries into the repository.

## Real Dataset Run

For BODMAS or another approved PE dataset:

- store raw PE files outside the repo;
- preferably use Google Drive or another external volume;
- build sanitized manifests;
- copy only aggregate metrics, validation summaries, and robustness cards back into the repo.
- use external output directories for transformation-producing runs. The CLIs will refuse repo-local transformed outputs when samples are external unless `--allow-repo-output` is explicitly supplied for controlled non-malware fixtures.
- use the sanitized artifact exporter before copying Colab/Drive outputs back into Git.

Before downloading, prepare an external workspace:

```bash
python3 scripts/binaryshield_prepare_bodmas_workspace.py \
  --workspace /content/drive/MyDrive/malware-robustness-data/bodmas
```

Check readiness:

```bash
python3 scripts/binaryshield_realdata_readiness.py \
  --workspace /content/drive/MyDrive/malware-robustness-data/bodmas \
  --output-dir reports/binaryshield/realdata_readiness
```

Minimum sequence:

```bash
python3 scripts/binaryshield_validate_manifest.py ...
python3 scripts/binaryshield_train_pe_baseline.py ...
python3 scripts/binaryshield_train_torch_detector.py --model-type raw_byte_cnn ...
python3 scripts/binaryshield_train_torch_detector.py --model-type hybrid_binaryshield --transformed-training ...
python3 scripts/binaryshield_eval_transfer.py ...
python3 scripts/binaryshield_eval_strongest_n.py ...
```

For raw PE transformation evaluation, use output paths under the external workspace, for example:

```bash
python3 scripts/binaryshield_run_pipeline.py \
  --manifest /content/drive/MyDrive/malware-robustness-data/bodmas/manifests/bodmas_raw_manifest.csv \
  --root-dir /content/drive/MyDrive/malware-robustness-data/bodmas/binaries \
  --output-dir /content/drive/MyDrive/malware-robustness-data/bodmas/results/bodmas_raw_multidetector \
  --report-dir reports/binaryshield/bodmas_raw_multidetector \
  --target family \
  --model-types centroid byte_histogram_centroid hybrid_centroid \
  --candidate-model-type hybrid_centroid \
  --strongest-n 20
```

After the run, copy only sanitized artifacts into the repository report tree:

```bash
python3 scripts/binaryshield_export_sanitized_artifacts.py \
  --source-dir /content/drive/MyDrive/malware-robustness-data/bodmas/results/bodmas_raw_multidetector \
  --destination-dir reports/binaryshield/bodmas_raw_multidetector_import
```

The exporter blocks `.exe`, `.bin`, `.dll`, `.sys`, `.npz`, `.pt`, `.pth`, `.joblib`, archives, detector/model JSON files, and token-like content. Review `sanitized_artifact_export_summary.md` before making any public claim.

Generate a consolidated card deck:

```bash
python3 scripts/binaryshield_build_card_deck.py \
  --cards-root reports/binaryshield/bodmas_raw_multidetector_import \
  --output-dir reports/binaryshield/bodmas_raw_multidetector_card_deck \
  --title "BODMAS Raw PE Malware Robustness Card Deck"
```

## DikeDataset Raw PE/OLE Run

DikeDataset is the current practical raw malware/benign route. Use Colab or external disk for longer reruns, and keep the dataset outside the repository.

Recommended external Colab layout:

```text
/content/drive/MyDrive/malware-robustness-data/dike/
  DikeDataset/
  manifests/
  results/
  reports/
```

Build the manifest after cloning or uploading the dataset:

```bash
python3 scripts/binaryshield_build_dike_manifest.py \
  --dataset-root /content/drive/MyDrive/malware-robustness-data/dike/DikeDataset \
  --output /content/drive/MyDrive/malware-robustness-data/dike/manifests/dike_pe_manifest.csv \
  --summary-output reports/binaryshield/dike_manifest_summary.json \
  --relative-to /content/drive/MyDrive/malware-robustness-data/dike/DikeDataset/files \
  --require-pe-parse
```

Run the accepted class-balanced byte-histogram logistic candidate:

```bash
python3 scripts/binaryshield_train_pe_baseline.py \
  --manifest /content/drive/MyDrive/malware-robustness-data/dike/manifests/dike_pe_manifest.csv \
  --root-dir /content/drive/MyDrive/malware-robustness-data/dike/DikeDataset/files \
  --output-dir /content/drive/MyDrive/malware-robustness-data/dike/results/dike_logistic_candidate/baseline \
  --target label \
  --model-type byte_histogram_logistic \
  --max-bytes 200000

python3 scripts/binaryshield_eval_pe_baseline.py \
  --manifest /content/drive/MyDrive/malware-robustness-data/dike/manifests/dike_pe_manifest.csv \
  --root-dir /content/drive/MyDrive/malware-robustness-data/dike/DikeDataset/files \
  --model /content/drive/MyDrive/malware-robustness-data/dike/results/dike_logistic_candidate/baseline/byte_histogram_logistic_detector.json \
  --target label \
  --transformation append_overlay \
  --output-dir /content/drive/MyDrive/malware-robustness-data/dike/results/dike_logistic_candidate/append_eval

python3 scripts/binaryshield_eval_pe_baseline.py \
  --manifest /content/drive/MyDrive/malware-robustness-data/dike/manifests/dike_pe_manifest.csv \
  --root-dir /content/drive/MyDrive/malware-robustness-data/dike/DikeDataset/files \
  --model /content/drive/MyDrive/malware-robustness-data/dike/results/dike_logistic_candidate/baseline/byte_histogram_logistic_detector.json \
  --target label \
  --transformation section_slack \
  --output-dir /content/drive/MyDrive/malware-robustness-data/dike/results/dike_logistic_candidate/slack_eval
```

The current local Dike logistic result is the accepted BinaryShield raw malware/benign defense under evaluated Level-2 append/slack transformations:

| Metric | Result |
|---|---:|
| Append macro F1 | 97.72% |
| Append accuracy | 99.19% |
| Append prediction stability | 100.00% |
| Append attack success rate | 0.00% |
| Slack macro F1 | 98.09% |
| Slack accuracy | 99.32% |
| Slack prediction stability | 100.00% |
| Slack attack success rate | 0.00% |
| Candidate beats strongest baseline gate | PASS, 6 metrics beaten |
| Absolute append/slack macro F1 target | PASS |

Next Colab target:

> Reproduce the Dike logistic result on the target judging machine or Colab runtime, complete strongest-of-N evaluation, and import only sanitized metrics, validation summaries, and Malware Robustness Cards back into the repository.

For non-BODMAS labelled raw PE datasets, build the manifest with the generic metadata route instead of writing a dataset-specific script:

```bash
python3 scripts/binaryshield_build_metadata_manifest.py \
  --metadata /content/drive/MyDrive/malware-robustness-data/rawpe/metadata.csv \
  --binaries-dir /content/drive/MyDrive/malware-robustness-data/rawpe/binaries \
  --output /content/drive/MyDrive/malware-robustness-data/rawpe/manifests/rawpe_manifest.csv \
  --summary-output reports/binaryshield/rawpe_manifest_summary.json \
  --path-column rel_path \
  --label-column label \
  --family-column family \
  --relative-to /content/drive/MyDrive/malware-robustness-data/rawpe/binaries \
  --require-pe-parse
```

If the dataset metadata identifies files by SHA-256 rather than relative path, replace `--path-column rel_path` with `--sha256-column sha256`. Add `--compute-hash` only for controlled small subsets where filenames are not hashes.

## Current Public BODMAS Result

On 19 June 2026, the public BODMAS folder was downloaded on Colab. It contained `bodmas.npz`, `bodmas_metadata.csv`, and `bodmas_malware_category.csv`, but not original raw PE malware binaries.

The public feature-vector track was evaluated successfully:

| Model | Test Accuracy | Test Macro F1 | Worst-Class F1 |
|---|---:|---:|---:|
| Feature centroid | 72.55% | 72.54% | 71.99% |
| ExtraTrees feature-record detector | 97.84% | 97.83% | 97.65% |

This is clean PE-derived feature-vector classification evidence only. Raw-PE robustness claims still require original raw binaries or another approved raw PE dataset.

## Claim Boundary

Colab verifies that the BinaryShield implementation can run on GPU. It does not by itself prove real malware robustness. Real claims require BODMAS/SOREL/raw PE evaluation artifacts.
