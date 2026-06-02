# Project Handover for New Codex Session

## 1. Executive Summary

### Project Title

**Improving the Robustness of Lightweight Deep Learning Models Against Adversarial Attacks in Malware Classification**

### Research Question

Can lightweight malware image classifiers remain accurate and robust under adversarial attack conditions while still being efficient enough for deployment on resource-constrained devices?

### Current Project Status

The project has completed the core experimental arc through **Phase 3 Stage 5: PGD adversarial training**.

The official project protocol now uses:

- The real MalImg dataset.
- Duplicate-aware train/validation/test splits based on image-content SHA-256 hashes.
- MobileNetV3 Small and EfficientNet-B0 clean baselines.
- Validated FGSM robustness evaluation.
- Validated PGD robustness evaluation.
- PGD adversarial training for MobileNetV3.

The official defense target is **MobileNetV3 Small**. EfficientNet-B0 is retained as a comparison baseline, not as a defense-training target.

### Most Important Findings So Far

1. **Duplicate leakage existed in the original stratified split.**
   - File paths did not overlap across splits, but exact image-content duplicates appeared across train/validation/test.
   - This was corrected by generating duplicate-aware splits that keep all identical content hashes in the same split.
   - The duplicate-aware split is now the official protocol.

2. **Both lightweight baselines are highly accurate on clean duplicate-aware MalImg data.**
   - MobileNetV3 Small: `97.9211%` clean accuracy, `0.935261` macro F1.
   - EfficientNet-B0: `96.0573%` clean accuracy, `0.879898` macro F1.
   - MobileNetV3 is the stronger clean baseline and has the smaller deployment footprint.

3. **Both models are severely vulnerable to adversarial attacks.**
   - FGSM at `eps=0.03` reduced MobileNetV3 accuracy to `18.0645%`.
   - PGD-20 at `eps=0.03`, `alpha=0.003` reduced MobileNetV3 accuracy to `0.2867%`.
   - PGD is the official primary robustness benchmark.

4. **PGD adversarial training substantially improves robustness but does not fully solve it.**
   - Adversarially trained MobileNetV3 clean accuracy: `97.3477%`.
   - FGSM `eps=0.03` accuracy improved from `18.0645%` to `82.8674%`.
   - PGD-20 accuracy improved from `0.2867%` to `20.0000%`.
   - PGD-20 macro F1 remains low at `0.031593`, so robustness is improved but still uneven across malware families.

### What Remains To Be Done

The central research question has enough evidence for a strong report, but several presentation-quality and validation tasks remain:

- Write the final research report using the official duplicate-aware protocol and results.
- Add a consolidated robustness-efficiency benchmark table across clean, FGSM, PGD, and defense results.
- Optionally generate Grad-CAM visualizations as an explainability phase, but Grad-CAM has not been implemented yet.
- Optionally rerun final official experiments with `CUBLAS_WORKSPACE_CONFIG=:4096:8` set before Python starts for stricter CUDA determinism.
- Avoid adding new datasets or architectures unless the current results/report are complete.

## 2. Repository Overview

### Major Directories

| Path | Purpose |
|---|---|
| `attacks/` | FGSM and PGD attack construction/evaluation utilities. Uses `torchattacks` and a normalization wrapper so perturbations are defined in raw pixel space. |
| `configs/` | YAML experiment configs for baselines, duplicate-aware baselines, FGSM, PGD, and MobileNetV3 adversarial training. |
| `defenses/` | PGD adversarial training implementation for MobileNetV3. |
| `evaluation/` | Classification metrics, confusion matrices, latency/throughput measurement, parameter count, model size, and benchmark helpers. |
| `models/` | Model adapters for MobileNetV3 Small and EfficientNet-B0. |
| `preprocessing/` | Dataset verification, dataset loading, transforms, standard splitting, duplicate-aware splitting, and split manifest generation. |
| `scripts/` | Dataset download, Runpod setup, and artifact archiving scripts. |
| `training/` | Clean baseline training pipeline. |
| `utils/` | Config loading, experiment metadata, hashing, logging, and reproducibility utilities. |
| `project_docs/` | Original project proposal/planning/reference documents. |
| `runpod_artifacts/archives/` | Timestamped compressed archives of results, reports, configs, manifests, and artifacts. |
| `results/` | Local synchronized results currently include defense outputs. Earlier baseline/attack outputs are also preserved inside archives. |

### Important Scripts

| Script | Purpose |
|---|---|
| `scripts/download_dataset.py` | Downloads `ikrambenabd/malimg-original` from Kaggle using Kaggle CLI. |
| `preprocessing/check_dataset.py` | Verifies dataset integrity, counts samples/classes, detects corrupt images, writes dataset manifest. |
| `preprocessing/split_dataset.py` | Generates standard or duplicate-aware train/validation/test CSV splits and split manifests. |
| `training/train.py` | Trains clean MobileNetV3/EfficientNet-B0 baselines with checkpointing, early stopping, scheduling, metadata, and test benchmarking. |
| `attacks/evaluate_fgsm.py` | Runs FGSM evaluation for configured models/epsilons. |
| `attacks/validate_fgsm.py` | Produces FGSM validation artifacts: perturbation stats, example inspection, and sanity checks. |
| `attacks/evaluate_pgd.py` | Runs PGD evaluation for configured models/settings. |
| `defenses/adversarial_training.py` | Runs PGD adversarial training/fine-tuning for MobileNetV3. |
| `scripts/setup_runpod.sh` | Validates Runpod environment, installs dependencies, checks CUDA/PyTorch/GPU/Kaggle/project imports. |
| `scripts/archive_results.sh` | Archives `results`, `reports`, `configs`, and `manifests` into timestamped `.tar.gz` bundles with SHA-256 checksums. |

### Important Configs

| Config | Purpose |
|---|---|
| `configs/mobilenet_duplicate_aware.yaml` | Official MobileNetV3 duplicate-aware clean baseline config. |
| `configs/efficientnet_duplicate_aware.yaml` | Official EfficientNet-B0 duplicate-aware clean baseline config. |
| `configs/fgsm.yaml` | Official FGSM evaluation config for duplicate-aware baseline checkpoints. |
| `configs/pgd.yaml` | Official PGD evaluation config for duplicate-aware baseline checkpoints. |
| `configs/adversarial_training_mobilenet.yaml` | Official MobileNetV3 PGD adversarial training config. |

### Important Manifests

Manifests are archived in the latest canonical artifact:

`runpod_artifacts/archives/experiment_artifacts_20260601T120030Z.tar.gz`

Important archived manifest paths:

- `manifests/dataset_manifest.json`
- `manifests/split_manifest.json`
- `manifests/split_manifest_duplicate_aware.json`
- `manifests/runpod_environment_20260601T093345Z.txt`

### Non-Obvious Implementation Decisions

1. **Attacks operate in raw pixel space, not normalized tensor space.**
   - Dataloaders return ImageNet-normalized tensors.
   - `attacks.fgsm.denormalize_images(...)` converts tensors back to `[0,1]`.
   - `attacks.fgsm.NormalizedModel` wraps the classifier so `torchattacks` sees raw images while the model still receives normalized inputs internally.
   - This is crucial: `eps=0.03` means raw pixel-space perturbation, not normalized-space perturbation.

2. **Attack Success Rate is computed only over clean-correct samples.**
   - ASR denominator is the number of samples the model classified correctly before attack.
   - This avoids counting already-wrong clean predictions as attack successes.

3. **Duplicate-aware splitting is now official.**
   - The original split is archived only as leakage-sensitivity analysis.
   - All official baseline, attack, and defense conclusions should use duplicate-aware splits.

4. **MobileNetV3 adversarial training is implemented as adversarial fine-tuning from the official clean baseline checkpoint.**
   - This tests whether the deployable clean baseline can be hardened.
   - It is faster than training from ImageNet weights and preserves the official clean baseline lineage.

## 3. Experimental History

### Phase 1: Research Planning

#### Literature Review Findings

The project was framed around malware image classification, where binary malware files are converted into grayscale/RGB image-like representations and classified by CNN-family models. Prior work indicates that malware image classifiers can achieve high clean accuracy but are vulnerable to gradient-based adversarial perturbations, particularly white-box first-order methods.

Key takeaways:

- Clean accuracy alone is not sufficient for a cybersecurity classifier.
- Lightweight architectures are important for deployability on constrained devices.
- FGSM is useful as a fast sensitivity probe.
- PGD is a stronger iterative benchmark and should be treated as the primary robustness metric.
- Adversarial training is the most appropriate first defense to test, before adding architectural novelty.

#### Selected Dataset

Selected dataset: **MalImg**

Kaggle slug:

`ikrambenabd/malimg-original`

Rationale:

- Established malware image dataset.
- Class-folder structure is straightforward.
- Size is manageable for repeated experiments.
- Contains 25 malware families and about 9.3k images.

#### Selected Architectures

1. **MobileNetV3 Small**
   - Primary lightweight deployment candidate.
   - Low parameter count and small model size.

2. **EfficientNet-B0**
   - Lightweight comparison model with higher capacity.
   - Used to compare robustness-efficiency tradeoffs.

#### Selected Attacks

1. **FGSM**
   - Fast one-step gradient attack.
   - Used to measure sensitivity to perturbation magnitude.

2. **PGD**
   - Iterative first-order attack.
   - Official primary robustness benchmark.

#### Selected Defense

**PGD adversarial training** for MobileNetV3 only.

Rationale:

- Directly targets the strongest evaluated attack.
- Keeps architecture unchanged, preserving deployment footprint.
- Tests whether robustness can improve without unacceptable clean accuracy or efficiency loss.

### Phase 2: Infrastructure and Reproducibility

#### Infrastructure Work Completed

Implemented/reconstructed:

- Kaggle dataset acquisition script.
- Dataset verification and corruption checking.
- Dataset manifest generation.
- Stratified split generation.
- Duplicate-aware split generation.
- Malware image dataset class and dataloaders.
- Image transforms with ImageNet normalization.
- MobileNetV3 Small adapter.
- EfficientNet-B0 adapter.
- Clean training pipeline.
- Evaluation utilities:
  - accuracy
  - precision
  - recall
  - macro F1
  - per-class metrics
  - confusion matrix
  - parameter count
  - model size
  - latency
  - throughput

#### Reproducibility Work Completed

Added:

- `requirements.txt`
- `scripts/setup_runpod.sh`
- `scripts/archive_results.sh`
- structured run logs
- experiment metadata JSON
- dataset manifest support
- split manifest support
- config-driven baseline/attack/defense execution
- seed-setting utilities in `utils/reproducibility.py`
- environment metadata tracking in `utils/experiment.py`

Metadata records include:

- timestamp
- git commit hash
- dirty git state
- hardware/CUDA/PyTorch/Python versions
- config contents and config hash
- dataset/split manifest paths
- checkpoint path
- metrics path
- run log path

#### Runpod Preparation

Final execution environment:

- GPU: NVIDIA RTX PRO 6000 Blackwell Server Edition
- VRAM: about 96 GB
- vCPU: 32 in the later/final pod
- RAM: 188 GB
- Python: 3.12.3
- PyTorch: 2.8.0+cu128
- CUDA runtime reported by PyTorch: 12.8
- cuDNN: 91002

The project initially used a Runpod pod that was later terminated/recreated due to CPU availability and pod migration constraints. The repo and artifacts were restored on the new pod, and experiments continued there.

### Phase 3 Experiments

#### Experiment A: Standard Split Baseline

Objective:

Train MobileNetV3 and EfficientNet-B0 on the first stratified split.

Conclusion:

The standard split had no file-path overlap, but later duplicate-content analysis found exact SHA-256 image-content duplicates crossing train/validation/test. Therefore these results are **not official** and should only be treated as leakage-sensitivity analysis.

#### Experiment B: Duplicate Analysis

Objective:

Determine whether the standard split leaked duplicate image content across splits.

Protocol:

- Compute/inspect image-content hashes.
- Compare content hashes across train/validation/test.
- Report affected families and overlap.

Conclusion:

Exact duplicate-content leakage existed. This was a significant methodological issue and was resolved before robustness experiments.

#### Experiment C: Duplicate-Aware Split

Objective:

Create official train/validation/test splits with no exact content-hash overlap.

Protocol:

- Group samples by image SHA-256 content hash within each malware family.
- Assign each duplicate group wholly to one split.
- Preserve approximate 70/15/15 train/validation/test proportions.
- Preserve all 25 families in each split where possible.
- Validate:
  - no path overlap
  - no content-hash overlap
  - no missing classes

Conclusion:

Duplicate-aware splits became the official dataset protocol.

#### Experiment D: Duplicate-Aware Clean Baselines

Objective:

Train official MobileNetV3 and EfficientNet-B0 clean baselines on duplicate-aware splits.

Protocol:

- Image size: 224
- Batch size: 32
- Optimizer: Adam
- Scheduler: cosine
- Head training: 5 epochs
- Fine-tuning: 5 epochs
- ImageNet normalization
- Transfer learning from torchvision pretrained weights
- Early stopping enabled

Results:

| Model | Accuracy | Macro F1 | Parameters | Model Size |
|---|---:|---:|---:|---:|
| MobileNetV3 Small | 0.979211 | 0.935261 | 1,543,481 | 5.934 MB |
| EfficientNet-B0 | 0.960573 | 0.879898 | 4,039,573 | 15.57 MB |

Conclusion:

MobileNetV3 is the official primary model because it has better clean accuracy, better macro F1, and a much smaller deployment footprint than EfficientNet-B0.

#### Experiment E: FGSM Evaluation

Objective:

Measure first-order one-step adversarial sensitivity.

Protocol:

- Dataset: duplicate-aware test split.
- Attack: FGSM using `torchattacks`.
- Perturbation space: raw pixel `[0,1]`.
- Normalization wrapper used.
- Epsilons: `0.01`, `0.03`, `0.05`, `0.10`.
- ASR over clean-correct samples only.

Key results:

| Model | Epsilon | Accuracy | Macro F1 | ASR |
|---|---:|---:|---:|---:|
| MobileNetV3 | 0.01 | 0.036559 | 0.033417 | 0.962665 |
| MobileNetV3 | 0.03 | 0.180645 | 0.032209 | 0.816252 |
| MobileNetV3 | 0.05 | 0.265233 | 0.026792 | 0.729136 |
| MobileNetV3 | 0.10 | 0.241577 | 0.023899 | 0.753294 |
| EfficientNet-B0 | 0.01 | 0.134767 | 0.145350 | 0.862687 |
| EfficientNet-B0 | 0.03 | 0.273835 | 0.028603 | 0.714925 |
| EfficientNet-B0 | 0.05 | 0.258781 | 0.024567 | 0.730597 |
| EfficientNet-B0 | 0.10 | 0.305376 | 0.020173 | 0.682090 |

Conclusion:

Both models are highly vulnerable to FGSM. EfficientNet-B0 has higher attacked accuracy at some epsilons, but macro F1 remains near zero under stronger FGSM, indicating poor family-balanced robustness.

#### Experiment F: FGSM Validation

Objective:

Validate that severe FGSM degradation was not an implementation artifact.

Validation performed:

- checked normalization handling
- checked epsilon scaling
- checked clipping/range validity
- checked perturbation magnitudes
- generated perturbation statistics
- generated example visualizations
- inspected confidence/prediction changes

Conclusion:

FGSM implementation is scientifically sound. Perturbations are bounded correctly in raw pixel space. Severe degradation reflects genuine model vulnerability, not a normalization or clipping bug.

#### Experiment G: PGD Evaluation

Objective:

Measure iterative first-order robustness. PGD is the official primary robustness benchmark.

Protocol:

- Dataset: duplicate-aware test split.
- Attack: PGD using `torchattacks`.
- Perturbation space: raw pixel `[0,1]`.
- Normalization wrapper used.
- Random start enabled.
- Primary benchmark:
  - `eps=0.03`
  - `alpha=0.003`
  - steps: `10`, `20`
- Extended sweep:
  - `eps=0.01`, `alpha=0.001`, steps=20
  - `eps=0.05`, `alpha=0.005`, steps=20
  - `eps=0.10`, `alpha=0.010`, steps=20
- ASR over clean-correct samples only.

Primary PGD results:

| Model | Attack | Accuracy | Macro F1 | ASR |
|---|---|---:|---:|---:|
| MobileNetV3 | PGD-10 | 0.007168 | 0.003873 | 0.992679 |
| MobileNetV3 | PGD-20 | 0.002867 | 0.000706 | 0.997072 |
| EfficientNet-B0 | PGD-10 | 0.089606 | 0.008013 | 0.906716 |
| EfficientNet-B0 | PGD-20 | 0.150538 | 0.015908 | 0.843284 |

Extended PGD sweep:

| Model | Eps | Steps | Accuracy | Macro F1 | ASR |
|---|---:|---:|---:|---:|---:|
| MobileNetV3 | 0.01 | 20 | 0.000000 | 0.000000 | 1.000000 |
| MobileNetV3 | 0.05 | 20 | 0.016487 | 0.002255 | 0.983163 |
| MobileNetV3 | 0.10 | 20 | 0.029391 | 0.006478 | 0.969985 |
| EfficientNet-B0 | 0.01 | 20 | 0.000000 | 0.000000 | 1.000000 |
| EfficientNet-B0 | 0.05 | 20 | 0.329749 | 0.036150 | 0.656716 |
| EfficientNet-B0 | 0.10 | 20 | 0.435842 | 0.060281 | 0.546269 |

Conclusion:

PGD shows severe vulnerability. MobileNetV3 is essentially broken under the primary PGD benchmark. EfficientNet-B0 is more robust by attacked accuracy, but macro F1 remains very low.

#### Experiment H: PGD Adversarial Training

Objective:

Determine whether robustness can be improved without unacceptable losses in clean accuracy or deployment efficiency.

Protocol:

- Model: MobileNetV3 Small.
- Initialization: official duplicate-aware MobileNetV3 clean baseline checkpoint.
- Training attack: PGD, `eps=0.03`, `alpha=0.003`, `steps=10`, random start.
- Batch mix: 50% clean, 50% adversarial.
- Fine-tuning LR: `1e-4`.
- Epochs: 5.
- Evaluation:
  - clean duplicate-aware test split
  - FGSM eps `0.01`, `0.03`, `0.05`, `0.10`
  - PGD primary benchmark steps `10`, `20`

Important failed/secondary approach:

- A conservative LR `1e-5` pilot improved FGSM but did not improve the primary PGD benchmark.
- It is archived but **not** the official defense result.
- The LR `1e-4` run is the official defense result.

Official defense results:

| Metric | Baseline MobileNetV3 | Adv-Trained MobileNetV3 | Change |
|---|---:|---:|---:|
| Clean Accuracy | 0.979211 | 0.973477 | -0.005735 |
| Clean Macro F1 | 0.935261 | 0.919019 | -0.016242 |
| FGSM Accuracy, eps=0.03 | 0.180645 | 0.828674 | +0.648029 |
| FGSM Macro F1, eps=0.03 | 0.032209 | 0.509615 | +0.477406 |
| FGSM ASR, eps=0.03 | 0.816252 | 0.148748 | -0.667504 |
| PGD-10 Accuracy | 0.007168 | 0.429391 | +0.422222 |
| PGD-20 Accuracy | 0.002867 | 0.200000 | +0.197133 |
| PGD-10 Macro F1 | 0.003873 | 0.118194 | +0.114320 |
| PGD-20 Macro F1 | 0.000706 | 0.031593 | +0.030887 |
| PGD-10 ASR | 0.992679 | 0.558910 | -0.433769 |
| PGD-20 ASR | 0.997072 | 0.794551 | -0.202521 |
| Parameters | 1,543,481 | 1,543,481 | 0 |
| Model Size MB | 5.934376 | 5.934376 | 0 |
| Latency ms | 1.258716 | 1.161543 | -0.097173 |
| Throughput samples/s | 794.460337 | 860.923714 | +66.463376 |

Conclusion:

PGD adversarial training meaningfully improves robustness while preserving clean accuracy and deployment footprint. However, PGD-20 macro F1 remains low, so family-balanced adversarial robustness is not solved.

## 4. Official Experimental Protocol

### Dataset

Dataset name:

**MalImg**

Kaggle slug:

`ikrambenabd/malimg-original`

Official dataset root on Runpod:

`/workspace/malware-robustness-project/datasets/raw/malimg/malimg_paper_dataset_imgs`

Relative dataset root:

`datasets/raw/malimg/malimg_paper_dataset_imgs`

Expected dataset characteristics:

- 9,339 samples
- 25 malware families
- 0 corrupt files in the official dataset manifest
- class imbalance is present

### Duplicate-Aware Split Methodology

Official split:

`datasets/splits_duplicate_aware/`

Manifest:

`manifests/split_manifest_duplicate_aware.json`

Method:

1. Load all image paths and class labels from class-folder structure.
2. Use SHA-256 image-content hashes from the dataset manifest.
3. For each family, group files by content hash.
4. Assign each content-hash group to exactly one split.
5. Greedily approximate 70/15/15 train/validation/test ratios per class.
6. Validate:
   - no file-path overlap
   - no content-hash overlap
   - all 25 families appear in train/validation/test

Official split strategy name:

`duplicate_aware_content_hash`

Official duplicate-aware split counts:

| Split | Samples |
|---|---:|
| Train | 6,539 |
| Validation | 1,405 |
| Test | 1,395 |

Official split validation:

- File-path overlap: `0` for train/test, train/validation, and validation/test.
- Content-hash overlap: `0` for train/test, train/validation, and validation/test.
- Missing classes: none in train, validation, or test.

### Models

#### MobileNetV3 Small

Implementation:

`models/mobilenet.py`

Torchvision architecture:

`mobilenet_v3_small`

Classifier head is replaced to match the 25 MalImg classes.

Official clean config:

`configs/mobilenet_duplicate_aware.yaml`

Key hyperparameters:

- batch size: 32
- image size: 224
- optimizer: Adam
- head epochs: 5
- fine-tune epochs: 5
- head LR: `0.001`
- fine-tune LR: `0.0001`
- scheduler: cosine
- early stopping patience: 3
- weighted loss: false
- seed: 42

#### EfficientNet-B0

Implementation:

`models/efficientnet.py`

Torchvision architecture:

`efficientnet_b0`

Classifier head is replaced to match the 25 MalImg classes.

Official clean config:

`configs/efficientnet_duplicate_aware.yaml`

Same general training protocol as MobileNetV3, with model-specific adapter logic.

### Attacks

#### FGSM Protocol

Config:

`configs/fgsm.yaml`

Implementation:

`attacks/evaluate_fgsm.py`

Attack library:

`torchattacks==3.5.1`

Settings:

- epsilons: `0.01`, `0.03`, `0.05`, `0.10`
- raw pixel-space perturbations
- images clipped/ranged to `[0,1]`
- normalization wrapper applies ImageNet normalization inside the model
- duplicate-aware test split only
- ASR over clean-correct samples only

#### PGD Protocol

Config:

`configs/pgd.yaml`

Implementation:

`attacks/evaluate_pgd.py`

Attack library:

`torchattacks==3.5.1`

Primary benchmark:

- `eps=0.03`
- `alpha=0.003`
- steps: `10`, `20`
- random start: true
- raw pixel-space perturbations
- normalization wrapper
- duplicate-aware test split only
- ASR over clean-correct samples only

Extended sweep:

- `eps=0.01`, `alpha=0.001`, steps=20
- `eps=0.05`, `alpha=0.005`, steps=20
- `eps=0.10`, `alpha=0.010`, steps=20

### Defense

Official defense:

**MobileNetV3 PGD adversarial training**

Config:

`configs/adversarial_training_mobilenet.yaml`

Implementation:

`defenses/adversarial_training.py`

Protocol:

- initialize from official duplicate-aware MobileNetV3 checkpoint
- 50% clean samples and 50% PGD adversarial samples within each training batch
- PGD training attack:
  - `eps=0.03`
  - `alpha=0.003`
  - steps=10
  - random start=true
- fine-tune all layers
- fine-tune LR: `0.0001`
- epochs: 5
- clean validation monitoring
- clean test evaluation after training
- FGSM and PGD evaluation using the same official attack protocol

## 5. Official Results

### Official Duplicate-Aware Baseline

| Model | Accuracy | Macro F1 | Parameters | Model Size |
|---|---:|---:|---:|---:|
| MobileNetV3 Small | 0.979211 | 0.935261 | 1,543,481 | 5.934 MB |
| EfficientNet-B0 | 0.960573 | 0.879898 | 4,039,573 | 15.57 MB |

Official baseline:

**MobileNetV3 Small on duplicate-aware splits**

Reason:

It is more accurate, has higher macro F1, and is much smaller than EfficientNet-B0.

### Official FGSM Results

| Model | Epsilon | Accuracy | Macro F1 | ASR |
|---|---:|---:|---:|---:|
| MobileNetV3 | 0.01 | 0.036559 | 0.033417 | 0.962665 |
| MobileNetV3 | 0.03 | 0.180645 | 0.032209 | 0.816252 |
| MobileNetV3 | 0.05 | 0.265233 | 0.026792 | 0.729136 |
| MobileNetV3 | 0.10 | 0.241577 | 0.023899 | 0.753294 |
| EfficientNet-B0 | 0.01 | 0.134767 | 0.145350 | 0.862687 |
| EfficientNet-B0 | 0.03 | 0.273835 | 0.028603 | 0.714925 |
| EfficientNet-B0 | 0.05 | 0.258781 | 0.024567 | 0.730597 |
| EfficientNet-B0 | 0.10 | 0.305376 | 0.020173 | 0.682090 |

### Official PGD Results

Primary PGD benchmark:

| Model | Attack | Accuracy | Macro F1 | ASR |
|---|---|---:|---:|---:|
| MobileNetV3 | PGD-10 | 0.007168 | 0.003873 | 0.992679 |
| MobileNetV3 | PGD-20 | 0.002867 | 0.000706 | 0.997072 |
| EfficientNet-B0 | PGD-10 | 0.089606 | 0.008013 | 0.906716 |
| EfficientNet-B0 | PGD-20 | 0.150538 | 0.015908 | 0.843284 |

Official conclusion:

PGD nearly destroys both baseline models. EfficientNet-B0 is more robust by attacked accuracy, but neither model retains meaningful family-balanced robustness.

### Official Adversarial Training Results

| Metric | Baseline MobileNetV3 | Adv-Trained MobileNetV3 | Change |
|---|---:|---:|---:|
| Clean Accuracy | 0.979211 | 0.973477 | -0.005735 |
| Clean Macro F1 | 0.935261 | 0.919019 | -0.016242 |
| FGSM Accuracy, eps=0.03 | 0.180645 | 0.828674 | +0.648029 |
| FGSM Macro F1, eps=0.03 | 0.032209 | 0.509615 | +0.477406 |
| PGD-10 Accuracy | 0.007168 | 0.429391 | +0.422222 |
| PGD-20 Accuracy | 0.002867 | 0.200000 | +0.197133 |
| PGD-10 Macro F1 | 0.003873 | 0.118194 | +0.114320 |
| PGD-20 Macro F1 | 0.000706 | 0.031593 | +0.030887 |
| Parameters | 1,543,481 | 1,543,481 | 0 |
| Model Size MB | 5.934376 | 5.934376 | 0 |

Official defense result:

PGD adversarial training improves robustness substantially while preserving deployment efficiency, but PGD-20 macro F1 remains low.

## 6. Research Conclusions

### What Has Been Demonstrated

1. Lightweight malware image classifiers can be highly accurate on clean MalImg data.
2. Clean accuracy does not imply adversarial robustness.
3. MobileNetV3 is the best clean lightweight baseline in this project.
4. PGD reveals substantially stronger vulnerability than FGSM.
5. EfficientNet-B0 is somewhat more robust under PGD by accuracy, but its macro F1 remains poor and it is larger.
6. PGD adversarial training can improve MobileNetV3 robustness without increasing model size or inference cost.
7. Adversarial training does not fully solve the problem, especially under PGD-20 and macro-F1 evaluation.

### Evidence Supporting These Findings

- Duplicate-aware MobileNetV3 clean accuracy: `0.979211`.
- MobileNetV3 PGD-20 baseline accuracy: `0.002867`.
- MobileNetV3 PGD-20 adversarially trained accuracy: `0.200000`.
- MobileNetV3 clean accuracy after defense: `0.973477`.
- Model size and parameter count unchanged after defense.

### Duplicate Leakage Discovery and Resolution

The original stratified split had no file-path overlap, but content hashing revealed exact duplicate images across splits. This would inflate estimates of generalization and could contaminate robustness evaluation. The project therefore switched to duplicate-aware content-hash grouping. All official results after this discovery use duplicate-aware splits.

### Limitations

- MalImg is an image representation of malware binaries; results may not generalize to raw-byte, dynamic-analysis, or API-sequence malware classifiers.
- MalImg is class-imbalanced.
- Only exact duplicate image-content leakage was addressed; near-duplicate or family-level correlations may remain.
- Only white-box FGSM and PGD were evaluated.
- No black-box transfer attacks yet.
- Only MobileNetV3 received adversarial training.
- Grad-CAM/explainability has not been implemented yet.
- PGD-20 macro F1 after defense remains low, suggesting robustness may be concentrated in some families.

### Caveats

The observed non-monotonicity in some attack sweeps is expected in adversarial evaluation on imbalanced multi-class data. At high epsilons, predictions can collapse toward majority-class regions, so accuracy can rise while macro F1 remains very low. Macro F1 should be emphasized alongside accuracy.

## 7. Reproducibility Notes

### Runpod Environment

Final official environment:

- GPU: NVIDIA RTX PRO 6000 Blackwell Server Edition
- VRAM: about 96 GB
- Python: 3.12.3
- PyTorch: 2.8.0+cu128
- CUDA runtime reported by PyTorch: 12.8
- cuDNN: 91002
- GPU compute capability: major 12, minor 0
- Multiprocessors: 188

The final pod had 32 vCPU and 188 GB RAM.

### Python Dependencies

Pinned dependencies are in:

`requirements.txt`

Important packages:

- `torchattacks==3.5.1`
- `numpy==2.1.3`
- `pandas==2.2.3`
- `scikit-learn==1.5.2`
- `matplotlib==3.9.2`
- `seaborn==0.13.2`
- `pillow==11.0.0`
- `PyYAML==6.0.2`
- `kaggle==2.2.0`

Do not reinstall CPU-only PyTorch over the CUDA-enabled Runpod image. `requirements.txt` intentionally does not pin `torch` or `torchvision`; these should come from the CUDA base image.

### Manifests and Metadata

Experiments write:

- `experiment_metadata.json`
- `run.log`
- config path and config hash
- environment metadata
- git commit hash
- dirty git state
- dataset and split manifest paths
- metrics/checkpoint paths

Dataset and split manifests are archived in:

`runpod_artifacts/archives/experiment_artifacts_20260601T120030Z.tar.gz`

### Archives

Latest canonical archive:

`runpod_artifacts/archives/experiment_artifacts_20260601T120030Z.tar.gz`

SHA-256:

`01dce774175e0670133fb84e8b11e1b5436efc793666d4bc9200be611637e6bf`

This archive should be treated as the canonical bundle for all results through adversarial training.

### Reproducibility Caveat: CuBLAS Determinism

During CUDA attack/training runs, PyTorch emitted a warning:

Deterministic algorithms were enabled, but some CuBLAS operations may be nondeterministic unless `CUBLAS_WORKSPACE_CONFIG` is set before the Python process starts.

To address this in future final reruns:

```bash
export CUBLAS_WORKSPACE_CONFIG=:4096:8
```

Then run training/evaluation commands in the same shell. This is recommended for strict bit-level reproducibility. The existing results are still scientifically useful, but this caveat should be documented in the final report.

## 8. Important Files and Artifacts

### Canonical Archive

`runpod_artifacts/archives/experiment_artifacts_20260601T120030Z.tar.gz`

This archive contains:

- official manifests
- duplicate-aware baseline results
- FGSM results
- FGSM validation artifacts
- PGD results
- adversarial training results
- configs
- reports

### Manifests

Archived paths:

- `manifests/dataset_manifest.json`
- `manifests/split_manifest_duplicate_aware.json`
- `manifests/runpod_environment_20260601T093345Z.txt`

### Official Baseline Results

Archived paths:

- `results/baseline_duplicate_aware/mobilenet_v3_small_20260601T100108Z/`
- `results/baseline_duplicate_aware/efficientnet_b0_20260601T100222Z/`

Important files in each:

- `best_model.pth`
- `metrics.csv`
- `history.csv`
- `confusion_matrix.png`
- `experiment_metadata.json`
- `run.log`

### Official FGSM Results

Archived path:

`results/robustness/fgsm/fgsm_20260601T102828Z/`

Important files:

- `fgsm_results.csv`
- `accuracy_vs_epsilon.png`
- `macro_f1_vs_epsilon.png`
- model-specific confusion matrices
- `sanity_check.json`
- `experiment_metadata.json`

### FGSM Validation Results

Archived path:

`results/robustness/fgsm_validation/fgsm_validation_20260601T104717Z/`

Important files:

- `perturbation_stats.csv`
- `example_analysis.csv`
- adversarial example visualizations
- `validation_metadata.json`

### Official PGD Results

Archived path:

`results/robustness/pgd/pgd_20260601T105733Z/`

Important files:

- `pgd_results.csv`
- `accuracy_by_pgd_setting.png`
- `macro_f1_by_pgd_setting.png`
- `asr_by_pgd_setting.png`
- model-specific confusion matrices
- `sanity_check.json`
- `experiment_metadata.json`

### Official Adversarial Training Results

Local synchronized path:

`results/defenses/adversarial_training/mobilenet_v3_small_pgd_adversarial_training_20260601T114339Z/`

Important files:

- `best_model.pth`
- `metrics.csv`
- `history.csv`
- `confusion_matrix.png`
- `experiment_metadata.json`
- `adversarial_training_report.md`
- `adversarial_training_comparison.csv`
- `per_class_f1_comparison.csv`
- `fgsm_accuracy_comparison.png`
- `fgsm_macro_f1_comparison.png`
- `pgd_accuracy_comparison.png`
- `pgd_macro_f1_comparison.png`
- `pgd_asr_comparison.png`

Defense FGSM path:

`results/defenses/adversarial_training/mobilenet_v3_small_pgd_adversarial_training_20260601T114339Z/fgsm_evaluation/fgsm_20260601T114531Z/`

Defense PGD path:

`results/defenses/adversarial_training/mobilenet_v3_small_pgd_adversarial_training_20260601T114339Z/pgd_evaluation/pgd_20260601T114554Z/`

### Non-Canonical Defense Pilot

Path:

`results/defenses/adversarial_training/mobilenet_v3_small_pgd_adversarial_training_20260601T113855Z/`

This was a conservative LR `1e-5` pilot. It improved FGSM but failed to improve PGD. Do not use it as the official defense result.

## 9. Current Project State

### Current Stage

The project has completed:

- Phase 3 Stage 1: real duplicate-aware baseline execution
- Phase 3 Stage 2: FGSM evaluation and validation
- Phase 3 Stage 3: PGD evaluation
- Phase 3 Stage 5: MobileNetV3 PGD adversarial training

Stage 4 robustness-efficiency analysis is mostly supported by generated tables and plots but may need a clean final consolidated report/table for publication.

Grad-CAM/explainability has not started.

### Has the Core Research Question Been Answered?

Yes, substantially.

Current answer:

Lightweight malware image classifiers can be clean-accurate and deployment-efficient, but they are not naturally robust under adversarial attack. PGD adversarial training can improve robustness without increasing inference cost or model size, but strong PGD attacks still cause major family-balanced performance degradation.

### Are Additional Experiments Necessary?

Not strictly necessary to answer the core question.

Additional work would improve report quality and confidence:

- Final consolidated robustness-efficiency table across MobileNetV3, EfficientNet-B0, and adversarially trained MobileNetV3.
- Optional strict-determinism rerun with `CUBLAS_WORKSPACE_CONFIG=:4096:8`.
- Optional Grad-CAM visual analysis.
- Optional black-box transfer attacks.

### Most Valuable Experiments If Time Permits

1. Strict-determinism rerun of official defense evaluation only.
2. Grad-CAM on clean vs adversarial examples for selected families.
3. Black-box transfer attacks from MobileNetV3 to EfficientNet-B0 and vice versa.
4. Additional adversarial training schedule search for PGD macro F1 improvement.

## 10. Recommended Next Steps

### High Priority

1. **Write the final research report.**
   - Use duplicate-aware baseline, FGSM, PGD, and adversarial training results only.
   - Explicitly discuss the duplicate leakage discovery and why the duplicate-aware split is official.
   - Emphasize PGD as the primary robustness benchmark.

2. **Create one final consolidated robustness-efficiency table.**
   - Rows:
     - MobileNetV3 baseline
     - EfficientNet-B0 baseline
     - MobileNetV3 PGD adversarial training
   - Columns:
     - clean accuracy
     - clean macro F1
     - FGSM `eps=0.03` accuracy/F1/ASR
     - PGD-10 accuracy/F1/ASR
     - PGD-20 accuracy/F1/ASR
     - parameters
     - model size
     - latency
     - throughput

3. **Document reproducibility caveats.**
   - Mention dirty git state in metadata.
   - Mention CuBLAS warning.
   - Mention exact Runpod environment.

4. **Use the latest archive as canonical.**
   - `runpod_artifacts/archives/experiment_artifacts_20260601T120030Z.tar.gz`

### Medium Priority

1. **Grad-CAM explainability phase.**
   - Generate Grad-CAM for:
     - clean-correct examples
     - FGSM successful attacks
     - PGD successful attacks
     - adversarially trained model examples
   - Focus on whether models attend to meaningful malware image structures or brittle artifacts.

2. **Strict-determinism rerun.**
   - Set:
     - `export CUBLAS_WORKSPACE_CONFIG=:4096:8`
   - Rerun only final official evaluation commands if time is limited.

3. **Improve adversarial training analysis.**
   - Analyze per-class PGD F1.
   - Identify which malware families benefit from defense.
   - Identify families still collapsing under PGD.

### Low Priority / Optional

1. Black-box transfer attacks.
2. ShuffleNetV2 as a third lightweight architecture.
3. MobileViT as a lightweight transformer comparison.
4. External dataset validation, such as BIG2015.

These are optional and should not be started until the current report is complete.

### Experiments That Should Not Be Pursued Yet

Avoid:

- Adding many new attack types.
- Adding many new defenses.
- Adding custom architectures.
- Switching datasets before the MalImg report is complete.
- Treating original non-duplicate-aware split results as official.

The project's strength is careful, reproducible experimentation, not architectural novelty.

## Practical Command Reference

### Setup Runpod

```bash
bash scripts/setup_runpod.sh
```

### Download Dataset

```bash
python scripts/download_dataset.py
```

### Verify Dataset

```bash
python preprocessing/check_dataset.py \
  --dataset-dir datasets/raw/malimg/malimg_paper_dataset_imgs \
  --manifest-path manifests/dataset_manifest.json
```

### Generate Duplicate-Aware Splits

```bash
python preprocessing/split_dataset.py \
  --dataset-dir datasets/raw/malimg/malimg_paper_dataset_imgs \
  --output-dir datasets/splits_duplicate_aware \
  --manifest-path manifests/split_manifest_duplicate_aware.json \
  --duplicate-aware \
  --dataset-manifest-path manifests/dataset_manifest.json
```

### Train Official Baselines

```bash
python training/train.py --config configs/mobilenet_duplicate_aware.yaml
python training/train.py --config configs/efficientnet_duplicate_aware.yaml
```

### Run Official FGSM

```bash
python attacks/evaluate_fgsm.py --config configs/fgsm.yaml
```

### Run Official PGD

```bash
python attacks/evaluate_pgd.py --config configs/pgd.yaml
```

### Run MobileNetV3 PGD Adversarial Training

```bash
python defenses/adversarial_training.py --config configs/adversarial_training_mobilenet.yaml
```

### Archive Results

```bash
bash scripts/archive_results.sh
```

## Final Note for the Next Codex Session

Do not restart from Phase 2. The repository contains the rebuilt training/evaluation/attack/defense infrastructure and the latest archive contains the canonical experimental evidence. The next valuable work is synthesis: produce final report-quality tables, figures, and interpretation from the official duplicate-aware results.
