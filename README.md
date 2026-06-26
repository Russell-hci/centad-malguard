# BinaryShield: PE-Aware Malware Robustness Auditing

BinaryShield is a PE-aware robustness audit framework for static malware detectors. It evaluates detector stability under controlled append-overlay and section-slack PE transformations, validates transformed files structurally, compares detector families, computes statistical evidence, and exports sanitized robustness reports.

BinaryShield does not ship malware samples, does not execute malware, and does not claim universal evasion resistance.

## Problem

Clean malware detector accuracy can hide fragility. The project began with CenTaD-MalGuard image-space experiments, where a MobileNetV3 malware-image classifier achieved strong clean performance but collapsed under PGD attacks. BinaryShield is the final project direction because it moves the audit closer to raw Windows PE files and makes validation failures visible instead of hiding them.

## Key Findings

| Evidence track | Result | Boundary |
| --- | --- | --- |
| MalGuard image-space baseline | MobileNetV3 clean accuracy `0.979211`, clean macro F1 `0.935261`; PGD-20 accuracy `0.002867`, PGD-20 macro F1 `0.000706` | Shows clean accuracy did not imply robustness |
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
- Trains transparent detector families including centroid baselines and class-balanced byte-histogram logistic regression.
- Applies deterministic append-overlay and section-slack transformations.
- Validates transformed files structurally with static PE checks.
- Computes clean/transformed metrics, prediction stability, attack success rate, confidence intervals, paired tests, and detector comparisons.
- Exports sanitized Markdown/CSV/JSON evidence without committing raw malware.

## Public Repository Contents

- `binaryshield/`: PE parsing, transformation, validation, evaluation, detector, and dataset helper code.
- `scripts/`: command-line tools for manifests, training/evaluation, evidence export, statistical analysis, ClamAV scan-only baselines, and RCA.
- `tests/`: synthetic and fixture-based tests that do not require private malware datasets.
- `docs/`: source-grounded audits, acceptance gates, detector explanations, and final narrative.
- `reports/`: final paper, judge summary, verified metrics, robustness card, ClamAV blocker, slack RCA, and sanitized evidence tables.
- `assets/figures/`: safe generated figures for the final report.

## Intentionally Excluded

This public release excludes raw malware, benign PE datasets, transformed binaries, PEMML/Dike archives, ClamAV databases, model checkpoints, virtual environments, local run folders, logs, and private filesystem paths.

## Run Tests

```bash
python3 -m pip install -r requirements.txt
python3 -m compileall binaryshield scripts tests
python3 -m unittest discover -s tests -p 'test_binaryshield*.py'
```

## Reproduce With Your Own PE Dataset

Provide your own authorized dataset outside the repository, then build a manifest and run the pipeline. Example shape:

```bash
python3 scripts/binaryshield_build_pemml_manifest.py   --samples-csv /path/to/pemml/samples.csv   --dataset-root /path/to/pemml   --output /path/to/manifests/pemml_5k_5k_manifest.csv   --summary-output reports/binaryshield/pemml_5k_5k_manifest_summary.json   --mode balanced-subset   --malware-count 5000   --benign-count 5000   --seed 1337

python3 scripts/binaryshield_run_pipeline.py   --manifest /path/to/manifests/pemml_5k_5k_manifest.csv   --root-dir /path/to/pemml/samples   --output-dir /path/to/runs/pemml_5k_5k/results   --report-dir /path/to/runs/pemml_5k_5k/reports   --target label   --model-types centroid byte_histogram_centroid hybrid_centroid byte_histogram_logistic   --candidate-model-type byte_histogram_logistic   --skip-strongest-n
```

Use external storage for datasets and runs. Commit only sanitized reports.

## Safety And Ethics

Use BinaryShield only for defensive evaluation and research. Do not execute malware outside an approved isolated environment. Do not upload malware samples to third-party scanners unless you understand the sharing policies. See `SECURITY_AND_ETHICS.md`.

## Claim Boundaries

BinaryShield is an audit framework, not an antivirus product. It does not prove malware functionality preservation, does not prove universal adversarial robustness, does not claim full PEMML validation, does not claim commercial antivirus superiority, and does not include Level 3 dynamic sandbox validation.

License: not specified yet.
