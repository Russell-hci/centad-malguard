# MalGuard-X

**Family-balanced adversarial robustness for malware image classification.**

MalGuard-X evaluates a malware-family classifier under adversarial attack and strengthens it using family-balanced adversarial training. The core finding is direct: a detector can look excellent on clean malware images and still fail almost completely under PGD attack. MalGuard-X improves aggregate robustness by optimizing adversarial macro F1, not only clean accuracy.

## 60-Second Summary

**Problem:** High clean accuracy is not enough for cybersecurity ML. A standard MobileNetV3 malware image classifier reached **97.92% clean accuracy**, then collapsed to **0.29% accuracy** and **0.07% macro F1** under PGD-20.

**Initial defense:** Vanilla PGD adversarial training improved average robustness, but PGD-20 macro F1 remained only **3.16%**, showing severe family-level collapse.

**Solution:** MalGuard-X uses Family-Balanced Malware Adversarial Training (FB-MalAT): Balanced Softmax Loss, balanced sampling, PGD-10 warm-up, PGD-20 continuation, and robust-min checkpoint selection across PGD-20 and PGD-50.

**Result:** The verified MalGuard-X finalist achieved above **80% accuracy** and above **80% macro F1** under FGSM, PGD-20, and PGD-50 on the duplicate-aware MalImg image-space evaluation.

| Condition | Accuracy | Macro F1 | Worst-Family F1 | Families F1 < 0.50 | Families F1 < 0.80 |
|---|---:|---:|---:|---:|---:|
| Clean | 90.39% | 89.86% | 0.00 | 2 | 3 |
| FGSM eps=0.03 | 88.60% | 85.19% | 0.00 | 3 | 5 |
| PGD-20 eps=0.03 | 87.10% | 82.77% | 0.00 | 4 | 6 |
| PGD-50 eps=0.03 | 83.66% | 80.41% | 0.00 | 4 | 7 |

The strongest improvement was PGD-20 macro F1: **3.16% -> 82.77%** compared with the earlier vanilla PGD-adversarially-trained MobileNetV3 defense.

## What Makes It Different

MalGuard-X treats class imbalance as a robustness failure, not just a dataset inconvenience. In malware-family classification, a model that protects only the largest families is unsafe: attackers can exploit fragile families even if aggregate accuracy looks acceptable.

The project contribution is:

- a duplicate-aware MalImg evaluation protocol using SHA-256 image-content grouping;
- FGSM and PGD evidence showing that clean malware classifiers can collapse under attack;
- a family-balanced adversarial training pipeline that optimizes robust macro F1;
- robust-min checkpoint selection using PGD-20 and PGD-50 validation macro F1;
- a static demonstration interface for communicating the attack-defense-explanation story;
- explicit claim boundaries around the evaluated image-space threat model.

## Architecture

```mermaid
flowchart LR
  A["MalImg malware image"] --> B["Duplicate-aware split"]
  B --> C["Standard detector baseline"]
  C --> D["FGSM / PGD evaluation"]
  D --> E["Vanilla PGD adversarial training"]
  E --> F["Family-level failure diagnosis"]
  F --> G["FB-MalAT: balanced softmax + balanced sampling"]
  G --> H["PGD-10 warm-up"]
  H --> I["PGD-20 continuation"]
  I --> J["Robust-min checkpoint selection"]
  J --> K["MalGuard-X finalist"]
  K --> L["Robustness metrics + demo"]
```

## Key Results

### Standard MobileNetV3

| Condition | Accuracy | Macro F1 |
|---|---:|---:|
| Clean | 97.92% | 93.53% |
| FGSM eps=0.03 | 18.06% | 3.22% |
| PGD-20 eps=0.03 | 0.29% | 0.07% |

### Vanilla PGD-Adversarially-Trained MobileNetV3

| Condition | Accuracy | Macro F1 |
|---|---:|---:|
| Clean | 97.35% | 91.90% |
| FGSM eps=0.03 | 82.87% | 50.96% |
| PGD-20 eps=0.03 | 20.00% | 3.16% |

### Final MalGuard-X

| Condition | Accuracy | Macro F1 |
|---|---:|---:|
| Clean | 90.39% | 89.86% |
| FGSM eps=0.03 | 88.60% | 85.19% |
| PGD-20 eps=0.03 | 87.10% | 82.77% |
| PGD-50 eps=0.03 | 83.66% | 80.41% |

Finalist checkpoint metadata:

```text
checkpoint: results/fb_malat/finalists/efficientnet_pgd20_from_pgd10_epoch1_snapshot_20260612T1955Z/best_model.pth
evaluation: results/fb_malat/final_evaluations_pgd20_continuation/efficientnet_b0_20260612T200838Z/metrics.csv
checkpoint_sha256: 789445971574ac98544635e389c6192296f94aa00be4ea68d2cbffa8256ff909
```

Large checkpoints and raw datasets are excluded from Git. The hash above identifies the verified local finalist artifact.

## Demo

The repository includes a static guided demo:

```bash
python3 -m http.server 8765
```

Open:

```text
http://localhost:8765/demo/malguard-x/
```

The demo follows:

```text
clean detection -> attack launched -> detector fooled -> defense activated -> prediction recovered -> explanation and evidence
```

The demo uses precomputed assets where available. It is intended for communication and judging, not for running new training experiments in the browser.

## Repository Structure

```text
README.md                  Public project overview
PROJECT_REPORT.md          Sanitized research report
attacks/                   FGSM and PGD attack code
configs/                   Baseline, attack, defense, and evaluation configs
datasets/splits_duplicate_aware/
                            Official duplicate-aware train/val/test split CSVs
defenses/                  Vanilla PGD-AT and FB-MalAT training code
demo/malguard-x/           Static guided demonstration app
evaluation/                Metrics, latency, benchmark, and confusion-matrix helpers
fb_malat/                  Balanced Softmax and family robustness utilities
models/                    MobileNetV3 and EfficientNet-B0 adapters
preprocessing/             Dataset loading, transforms, duplicate-aware splitting
scripts/                   Dataset download, evaluation, Grad-CAM, and archive helpers
training/                  Clean baseline training pipeline
utils/                     Config loading, reproducibility, experiment metadata
```

## Quick Start

Create an environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Install the correct CUDA-enabled `torch` and `torchvision` wheels for your machine separately if GPU training is needed. The requirements file intentionally avoids pinning PyTorch so it does not overwrite CUDA-enabled installations.

Run the static demo:

```bash
python3 -m http.server 8765
```

Train a clean duplicate-aware baseline:

```bash
python training/train.py --config configs/mobilenet_duplicate_aware.yaml
```

Evaluate a trained checkpoint under FGSM/PGD using the corresponding config:

```bash
python attacks/evaluate_fgsm.py --config configs/fgsm.yaml
python attacks/evaluate_pgd.py --config configs/pgd.yaml
```

Run stable FB-MalAT training:

```bash
python defenses/fb_malat_training.py --config configs/defense/fb_malat/at_bsl_efficientnet_b0_pgd10.yaml
python defenses/fb_malat_training.py --config configs/defense/fb_malat/at_bsl_efficientnet_b0_pgd20_from_pgd10_robustmin.yaml
```

Evaluate a MalGuard-X checkpoint:

```bash
python scripts/evaluate_fb_malat_checkpoint.py \
  --checkpoint results/fb_malat/finalists/efficientnet_pgd20_from_pgd10_epoch1_snapshot_20260612T1955Z/best_model.pth \
  --model efficientnet_b0
```

## Reproducibility Notes

- Official conclusions use `datasets/splits_duplicate_aware/`.
- Exact image-content duplicates are grouped by SHA-256 before splitting.
- FGSM and PGD perturbations are bounded in raw `[0, 1]` pixel space.
- Attack Success Rate is computed only over samples correctly classified before attack.
- Final model selection used validation metrics, not test-set tuning.
- Large generated artifacts are excluded from Git: raw data, processed data, checkpoints, logs, and result directories.

## Claim Boundary

Valid claim:

> MalGuard-X achieved above 80% test accuracy and above 80% macro F1 under FGSM, PGD-20, and PGD-50 on the official duplicate-aware MalImg image-space evaluation.

Limitations:

- The result is an aggregate robustness result; worst-family F1 remains 0.0.
- The evaluated threat model is image-space perturbation, not guaranteed functionality-preserving executable malware transformation.
- AutoAttack and broader adaptive attack evaluations are not included in this public final result.
- MalImg results may not generalize to raw-byte, dynamic-analysis, or API-sequence malware detectors.

## Report

See [PROJECT_REPORT.md](PROJECT_REPORT.md) for the full sanitized project report.
