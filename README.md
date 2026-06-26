# BinaryShield: PE-Aware Malware Robustness Auditing

BinaryShield is a PE-aware robustness audit framework for static malware detectors. It evaluates detector stability under controlled append-overlay and section-slack PE transformations, validates transformed files structurally, compares detector families, computes statistical evidence, and exports sanitized robustness reports.

BinaryShield does not ship malware samples, does not execute malware, and does not claim universal evasion resistance.

## Why This Project Exists

Clean malware detector accuracy can hide fragility. The original CenTaD-MalGuard image-space cycle showed this clearly: a MobileNetV3 malware-image classifier reached high clean performance but collapsed under PGD attacks. BinaryShield is the final project direction because it moves the audit closer to real Windows PE files and makes validation failures visible rather than hiding them.

## Key Results

| Evidence track | Result | Boundary |
| --- | --- | --- |
| MalGuard image-space baseline | MobileNetV3 clean accuracy `0.979211`, clean macro F1 `0.935261`; PGD-20 accuracy `0.002867`, PGD-20 macro F1 `0.000706` | Clean image accuracy did not imply robustness |
| First PGD adversarial training | PGD-20 macro F1 improved to `0.031593` | Still weak family-balanced robustness |
| FB-MalAT image-space continuation | Aggregate 80/80 target reached under FGSM, PGD-20, and PGD-50 | Worst-family F1 remained `0.000000`; image-space only |
| Dike PE evidence | `byte_histogram_logistic` append robust-min macro F1 `0.977220`, slack robust-min macro F1 `0.980882`, stability `1.000000`, ASR `0.000000`, acceptance `PASS` | Initial accepted raw-PE evidence |
| PEMML external subset | 10,000 raw PE files: 5,000 malware + 5,000 benign. Clean macro F1 `0.906000`, append robust macro F1 `0.894983`, slack robust macro F1 `0.889822`, append stability `0.993980`, slack stability `0.996986` | External subset validation, not full PEMML |
| PEMML statistical analysis | Append delta `0.002000`, CI `[-0.001516, 0.005996]`; slack delta `-0.000082`, CI `[-0.003163, 0.002934]`; McNemar p-values `0.507812` and `1.000000` | Append/slack degradation was not statistically significant on paired evaluable rows |
| PEMML acceptance gate | Candidate acceptance `FAIL` due to original strict slack structural gate | Root cause identified and patched; expensive full rerun intentionally not performed |
| ClamAV baseline | Scan-only baseline script implemented | Official signature database unavailable due FreshClam CDN 403/429 cooldown; no ClamAV metrics claimed |

## What BinaryShield Does

- Builds sanitized manifests for PE datasets.
- Extracts PE structural features and 256-bin normalized byte histograms.
- Trains transparent detector families, including centroid baselines and class-balanced byte-histogram logistic regression.
- Applies deterministic append-overlay and section-slack transformations.
- Validates transformed files structurally with static PE checks.
- Computes clean/transformed metrics, prediction stability, attack success rate, confidence intervals, paired tests, and detector comparisons.
- Exports sanitized Markdown/CSV/JSON evidence without committing raw malware.

## Repository Layout

```text
binaryshield/        Core PE parsing, transformation, validation, model, dataset, and evaluation code
scripts/             BinaryShield command-line tools
tests/               Fixture and synthetic-data tests
docs/                Source-grounded audits and claim boundaries
reports/             Final paper, judge summary, robustness card, RCA, and sanitized metrics
assets/figures/      Safe figures used by the final paper
requirements.txt     Python dependencies
```

## Important Reports

- `reports/final_binaryshield_research_paper.md`
- `reports/final_binaryshield_judge_summary.md`
- `reports/final_binaryshield_verified_metrics_summary.md`
- `reports/binaryshield_final_robustness_card.md`
- `reports/binaryshield_pemml_statistical_analysis.md`
- `reports/binaryshield_slack_failure_root_cause.md`
- `reports/binaryshield_clamav_baseline.md`

## Public Release Scope

Included:

- BinaryShield source code.
- CLI scripts for manifests, training/evaluation, evidence export, statistical analysis, ClamAV scan-only baselines, and RCA.
- Tests that use fixtures or synthetic data rather than private malware datasets.
- Source-grounded audits and final reports.
- Sanitized Dike and PEMML evidence summaries.
- Safe generated figures.

Excluded:

- Raw malware and benign PE datasets.
- Transformed binaries.
- PEMML/Dike archives.
- ClamAV databases.
- Model checkpoints and local run folders.
- Virtual environments, caches, logs, and private filesystem paths.

## Safety And Ethics

Use BinaryShield only for defensive evaluation and research. Do not execute malware on a normal workstation. Use isolated, purpose-built malware-analysis environments for any dynamic analysis. Keep raw datasets outside this repository. Do not upload malware samples to third-party scanners unless you understand their sharing policies.

The ClamAV integration is scan-only and non-destructive. It must not be run with `--remove`, `--move`, `--copy`, quarantine options, or any workflow that modifies original samples.

## Reproducibility

Datasets used but not redistributed:

- MalImg for the image-space phase.
- DikeDataset for initial PE evidence.
- PE Malware Machine Learning Dataset (PEMML) for external PE subset validation.

The final PEMML result is a balanced 10,000-sample subset: 5,000 malware and 5,000 benign samples. It is not full PEMML validation.

High-level reproduction flow:

1. Obtain datasets from official or authorized sources.
2. Store raw datasets outside the Git repository.
3. Build a sanitized manifest with sample IDs, labels, splits, and hashes.
4. Train/evaluate BinaryShield detectors on clean PE files.
5. Run append-overlay and section-slack transformations.
6. Validate transformed files structurally.
7. Export sanitized metrics and robustness cards.
8. Run paired statistical analysis over prediction CSVs.
9. Commit only sanitized Markdown/CSV/JSON reports.

Example PEMML subset commands:

```bash
python3 scripts/binaryshield_build_pemml_manifest.py   --samples-csv /path/to/pemml/samples.csv   --dataset-root /path/to/pemml   --output /path/to/manifests/pemml_5k_5k_manifest.csv   --summary-output reports/binaryshield/pemml_5k_5k_manifest_summary.json   --mode balanced-subset   --malware-count 5000   --benign-count 5000   --seed 1337

python3 scripts/binaryshield_run_pipeline.py   --manifest /path/to/manifests/pemml_5k_5k_manifest.csv   --root-dir /path/to/pemml/samples   --output-dir /path/to/runs/pemml_5k_5k/results   --report-dir /path/to/runs/pemml_5k_5k/reports   --target label   --model-types centroid byte_histogram_centroid hybrid_centroid byte_histogram_logistic   --candidate-model-type byte_histogram_logistic   --skip-strongest-n

python3 scripts/binaryshield_statistical_analysis.py   --run-dir /path/to/runs/pemml_5k_5k   --output-dir reports/binaryshield/pemml_5k_5k_sanitized_metrics   --report-output reports/binaryshield_pemml_statistical_analysis.md
```

## Run Tests

```bash
python3 -m pip install -r requirements.txt
python3 -m compileall binaryshield scripts tests
python3 -m unittest discover -s tests -p 'test_binaryshield*.py'
```

Some tests use optional analysis dependencies such as pandas and scikit-learn. In a minimal Python environment, those tests are skipped with an explicit message until `requirements.txt` is installed.

## Claim Boundaries

BinaryShield is an audit framework, not an antivirus product. It does not prove malware functionality preservation, does not prove universal adversarial robustness, does not claim full PEMML validation, does not claim commercial antivirus superiority, and does not include Level 3 dynamic sandbox validation.

License: not specified yet.
