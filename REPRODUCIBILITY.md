# Reproducibility

This repository publishes code and sanitized evidence for BinaryShield, but it does not redistribute malware datasets.

## Datasets Used But Not Redistributed

- MalImg: image-space malware classification phase.
- DikeDataset: initial raw-PE BinaryShield evidence package.
- PE Malware Machine Learning Dataset (PEMML): external raw-PE subset validation.

The final PEMML claim is a balanced 10,000-sample subset: 5,000 malware and 5,000 benign samples. It is not full PEMML validation.

## High-Level Reproduction Steps

1. Obtain datasets from their official or authorized sources.
2. Store raw datasets outside the Git repository.
3. Build a sanitized manifest with sample IDs, labels, splits, and hashes.
4. Train/evaluate BinaryShield detectors on clean PE files.
5. Run append-overlay and section-slack transformations.
6. Validate transformed files structurally.
7. Export sanitized metrics and robustness cards.
8. Run paired statistical analysis over prediction CSVs.
9. Commit only sanitized Markdown/CSV/JSON reports.

## Example Commands

```bash
python3 scripts/binaryshield_build_pemml_manifest.py   --samples-csv /path/to/pemml/samples.csv   --dataset-root /path/to/pemml   --output /path/to/manifests/pemml_5k_5k_manifest.csv   --summary-output reports/binaryshield/pemml_5k_5k_manifest_summary.json   --mode balanced-subset   --malware-count 5000   --benign-count 5000   --seed 1337

python3 scripts/binaryshield_run_pipeline.py   --manifest /path/to/manifests/pemml_5k_5k_manifest.csv   --root-dir /path/to/pemml/samples   --output-dir /path/to/runs/pemml_5k_5k/results   --report-dir /path/to/runs/pemml_5k_5k/reports   --target label   --model-types centroid byte_histogram_centroid hybrid_centroid byte_histogram_logistic   --candidate-model-type byte_histogram_logistic   --skip-strongest-n

python3 scripts/binaryshield_statistical_analysis.py   --run-dir /path/to/runs/pemml_5k_5k   --output-dir reports/binaryshield/pemml_5k_5k_sanitized_metrics   --report-output reports/binaryshield_pemml_statistical_analysis.md
```

## Why Raw Paths Are Absent

Raw sample paths are intentionally omitted from public reports. Users must provide local dataset locations at runtime. This protects safety, privacy, and portability.

## Non-Reproduced Items

The original PEMML 5k+5k acceptance remains `FAIL` because the expensive full pipeline was not rerun after the slack transformer patch. ClamAV metrics are unavailable because the official signature database could not be obtained during the final attempt.
