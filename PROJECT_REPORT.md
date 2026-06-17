# MalGuard-X: Family-Balanced Adversarial Robustness for Malware Image Classification

**Report Type:** Public Research Report  
**Date:** 13 June 2026

## Abstract

MalGuard-X investigates whether malware image classifiers that achieve high clean accuracy remain reliable under adversarial attack, then develops a stronger defense based on family-balanced adversarial training. Under a duplicate-aware MalImg protocol, a standard MobileNetV3 classifier achieved 97.92% clean accuracy and 93.53% macro F1, but collapsed to 0.29% accuracy and 0.07% macro F1 under PGD-20. Vanilla PGD adversarial training improved average robustness, but PGD-20 macro F1 remained only 3.16%, indicating severe family-level collapse. MalGuard-X addresses this failure with Family-Balanced Malware Adversarial Training (FB-MalAT), combining Balanced Softmax Loss, balanced sampling, PGD-10 warm-up, PGD-20 continuation, and robust-min checkpoint selection. The verified finalist achieved 88.60% accuracy and 85.19% macro F1 under FGSM, 87.10% accuracy and 82.77% macro F1 under PGD-20, and 83.66% accuracy and 80.41% macro F1 under PGD-50. The result supports the conclusion that malware robustness must be evaluated and optimized at the family-balanced level, not only by clean accuracy or aggregate attacked accuracy.

## 1. Introduction

### 1.1 Background

Malware-family classification supports cybersecurity triage, incident response, and threat analysis. Malware image classification converts binaries into grayscale image representations and applies computer vision models to learn visual patterns associated with malware families.

This approach can produce strong clean-data accuracy, but cybersecurity machine learning has an active-adversary problem. Attackers may deliberately perturb inputs to fool a model. A malware detector that performs well only on clean samples may therefore be unreliable in adversarial settings.

### 1.2 Purpose

This project was carried out to answer three questions:

1. Do malware image classifiers with high clean accuracy remain reliable under adversarial attacks?
2. Can adversarial training improve robustness without hiding family-level failures?
3. Can a final solution optimize family-balanced robustness strongly enough to become a practical malware robustness tool rather than a simple results display?

### 1.3 Scope

The project uses the MalImg malware image dataset with 25 malware families. All official results use a duplicate-aware train/validation/test protocol. The attack scope is image-space FGSM and PGD at epsilon 0.03. The project evaluates MobileNetV3 Small, EfficientNet-B0, vanilla PGD adversarial training, and the final MalGuard-X FB-MalAT method.

The project does not claim to solve all malware evasion. It evaluates a specific image-space threat model on MalImg-style malware images.

### 1.4 Objectives

- Build clean malware-family classification baselines under a duplicate-aware protocol.
- Quantify adversarial vulnerability under FGSM and PGD.
- Evaluate vanilla PGD adversarial training.
- Diagnose weak macro-F1 and family-level robustness collapse.
- Develop a stronger family-balanced defense.
- Package the result as a demonstrable robustness-auditing solution.

## 2. Methodology

### 2.1 Dataset

The project uses MalImg, a malware image dataset containing 25 malware families. Malware binaries are represented as grayscale images. The model learns visual patterns corresponding to malware families.

The dataset is class-imbalanced. Therefore, accuracy alone is insufficient. Macro F1 is reported because it gives equal importance to each malware family.

### 2.2 Duplicate-Aware Protocol

The original split was checked for leakage. Although file paths did not overlap, SHA-256 image-content hashing found exact duplicate image content across splits. The official protocol corrects this by grouping identical image hashes before splitting.

Protocol:

1. Compute SHA-256 hashes from image content.
2. Group identical images by hash within each malware family.
3. Assign each duplicate group entirely to train, validation, or test.
4. Preserve approximate 70/15/15 split proportions.
5. Verify no content-hash overlap across splits.

Official split:

| Split | Samples |
|---|---:|
| Train | 6,539 |
| Validation | 1,405 |
| Test | 1,395 |

### 2.3 Models

| Model | Role |
|---|---|
| MobileNetV3 Small | Original lightweight baseline and vanilla PGD adversarial training target. |
| EfficientNet-B0 | Higher-capacity robustness track used for final MalGuard-X. |

MobileNetV3 established the clean-accuracy and lightweight robustness story. EfficientNet-B0 was used for the final high-performance robustness solution after the project shifted toward stronger effectiveness.

### 2.4 Attacks

The project evaluates white-box image-space attacks:

| Attack | Setting | Purpose |
|---|---|---|
| FGSM | eps=0.03 | One-step sensitivity test. |
| PGD-20 | eps=0.03, alpha=0.003 | Primary iterative robustness benchmark. |
| PGD-50 | eps=0.03, alpha=0.003 | Stronger final evaluation benchmark. |

Perturbations are bounded in raw `[0, 1]` pixel space. A normalization wrapper applies model preprocessing internally during attack generation.

### 2.5 Vanilla PGD Adversarial Training

The first defense used PGD adversarial training on MobileNetV3. This improved robustness but failed to produce acceptable PGD macro F1. The result showed that ordinary adversarial training can concentrate robustness in head families while leaving weaker families unprotected.

### 2.6 MalGuard-X: FB-MalAT

MalGuard-X uses Family-Balanced Malware Adversarial Training:

- **Balanced Softmax Loss:** adjusts logits using class counts so head families do not dominate the objective.
- **Balanced sampling:** increases exposure to underrepresented families during training.
- **PGD-10 warm-up:** builds initial adversarial robustness.
- **PGD-20 continuation:** strengthens the model under a harder attack.
- **Robust-min checkpoint selection:** selects checkpoints using the minimum validation macro F1 across PGD-20 and PGD-50.

The method targets robust macro F1 and weak-family collapse. This is the main distinction from ordinary PGD adversarial training.

### 2.7 Metrics

| Metric | Purpose |
|---|---|
| Accuracy | Overall correctness. |
| Macro F1 | Family-balanced correctness. |
| Worst-family F1 | Robustness of the weakest family. |
| Families below F1 thresholds | Number of families still unsafe under thresholds such as 0.50 and 0.80. |
| Attack Success Rate | Proportion of clean-correct samples flipped by attack, where available. |

### 2.8 Explainability

Grad-CAM was used as supporting evidence. It was used to compare clean, FGSM, and PGD attention maps for standard and adversarially trained detectors. Attention metrics included Top-20% heatmap IoU and center-of-mass shift. These findings support, but do not prove, the interpretation that attacks can disrupt model attention and adversarial training may stabilize it.

## 3. Results and Discussion

### 3.1 Work Completed

Completed project stages:

- duplicate-aware split and validation;
- clean MobileNetV3 and EfficientNet-B0 baselines;
- FGSM and PGD attack evaluation;
- vanilla PGD adversarial training;
- Grad-CAM explainability package;
- family-level robustness diagnosis;
- FB-MalAT training and finalist verification;
- static product demo for communicating the result.

### 3.2 Clean Accuracy Was Misleading

| Condition | Accuracy | Macro F1 |
|---|---:|---:|
| Clean | 97.92% | 93.53% |
| FGSM eps=0.03 | 18.06% | 3.22% |
| PGD-20 eps=0.03 | 0.29% | 0.07% |

The standard MobileNetV3 detector appeared strong under clean evaluation but almost completely failed under PGD-20. This demonstrates that clean accuracy is not a sufficient security metric.

### 3.3 Vanilla PGD Adversarial Training Was Not Enough

| Condition | Accuracy | Macro F1 |
|---|---:|---:|
| Clean | 97.35% | 91.90% |
| FGSM eps=0.03 | 82.87% | 50.96% |
| PGD-20 eps=0.03 | 20.00% | 3.16% |

Vanilla adversarial training improved FGSM robustness and some PGD accuracy, but macro F1 remained poor. This indicated family-level collapse: the model protected some families but failed many others.

### 3.4 Final MalGuard-X Result

Finalist artifact:

```text
checkpoint: results/fb_malat/finalists/efficientnet_pgd20_from_pgd10_epoch1_snapshot_20260612T1955Z/best_model.pth
evaluation: results/fb_malat/final_evaluations_pgd20_continuation/efficientnet_b0_20260612T200838Z/metrics.csv
checkpoint_sha256: 789445971574ac98544635e389c6192296f94aa00be4ea68d2cbffa8256ff909
```

| Condition | Accuracy | Macro F1 | Worst-Family F1 | Families F1 < 0.50 | Families F1 < 0.80 |
|---|---:|---:|---:|---:|---:|
| Clean | 90.39% | 89.86% | 0.00 | 2 | 3 |
| FGSM eps=0.03 | 88.60% | 85.19% | 0.00 | 3 | 5 |
| PGD-20 eps=0.03 | 87.10% | 82.77% | 0.00 | 4 | 6 |
| PGD-50 eps=0.03 | 83.66% | 80.41% | 0.00 | 4 | 7 |

This satisfies the upgraded aggregate target: above 80% accuracy and macro F1 under FGSM, PGD-20, and PGD-50.

### 3.5 Improvement Over Earlier Defense

| Metric | Vanilla PGD-AT MobileNetV3 | MalGuard-X | Improvement |
|---|---:|---:|---:|
| PGD-20 Accuracy | 20.00% | 87.10% | +67.10 percentage points |
| PGD-20 Macro F1 | 3.16% | 82.77% | +79.61 percentage points |
| PGD-50 Accuracy | Not official for vanilla defense | 83.66% | New stronger benchmark |
| PGD-50 Macro F1 | Not official for vanilla defense | 80.41% | New stronger benchmark |

The main scientific result is that family-balanced adversarial training transformed PGD-20 macro F1 from near-zero to strong aggregate robustness.

### 3.6 Innovation and Uniqueness

MalGuard-X is distinct because it changes the optimization target. Instead of asking only whether a model is accurate on average, it asks whether malware-family robustness remains balanced under attack.

Key innovative elements:

- It treats class imbalance as a cybersecurity robustness vulnerability.
- It optimizes adversarial macro F1 rather than only clean accuracy or attacked accuracy.
- It uses robust-min checkpoint selection across PGD-20 and PGD-50, reducing attack-specific overfitting.
- It presents the output as a robustness audit: aggregate results, family-level weaknesses, verified threat model, and claim boundary.

The final product is therefore not just a webpage. It is a reproducible pipeline and demonstration for assessing whether a malware classifier remains deployable under adversarial pressure.

### 3.7 Problems Encountered

Problems that shaped the project:

- exact duplicate image-content leakage risk in the original split;
- high clean accuracy hiding adversarial vulnerability;
- vanilla PGD adversarial training failing macro F1;
- class imbalance causing weak-family collapse;
- stronger PGD-50 evaluation making checkpoint selection harder;
- GPU compute requirements for adversarial training and evaluation.

### 3.8 Claim Boundary

Valid claim:

> MalGuard-X achieved above 80% test accuracy and above 80% macro F1 under FGSM, PGD-20, and PGD-50 on the official duplicate-aware MalImg image-space evaluation.

The project does not claim:

- every malware family is robust;
- worst-family robustness is solved;
- AutoAttack robustness has been proven;
- real executable malware evasion has been solved;
- the model is secure against all adaptive attacks.

## 4. Future Work

High-value next steps:

1. Run AutoAttack to strengthen robustness credibility.
2. Improve worst-family F1, because the final aggregate result still leaves at least one family at 0.0 F1.
3. Add abstention or warning behavior for weak families and low-confidence predictions.
4. Extend Grad-CAM analysis to the final MalGuard-X EfficientNet-B0 checkpoint.
5. Evaluate malware-preserving transformations that better reflect executable constraints.

## 5. Conclusion

The project progressed from a vulnerability study to a stronger cybersecurity ML solution. The first key finding was that clean malware image classification accuracy can be dangerously misleading: MobileNetV3 achieved 97.92% clean accuracy but collapsed to 0.29% under PGD-20. The first defense, vanilla PGD adversarial training, improved robustness but left PGD-20 macro F1 at only 3.16%.

MalGuard-X directly addressed this weakness by optimizing family-balanced adversarial robustness. The final verified EfficientNet-B0 FB-MalAT checkpoint achieved above 80% accuracy and macro F1 under FGSM, PGD-20, and PGD-50. This makes the project substantially more effective and technically distinct than a standard malware classifier or a simple research dashboard.

The honest assessment is that MalGuard-X is strong under the evaluated image-space threat model, but not complete as a general malware-security solution. Worst-family F1 remains unresolved, AutoAttack has not been included, and real executable malware evasion requires future evaluation. The project’s strongest contribution is therefore bounded but meaningful: robust malware ML should be evaluated and optimized at the family-balanced adversarial level.

## References

1. L. Nataraj, S. Karthikeyan, G. Jacob, and B. S. Manjunath, "Malware Images: Visualization and Automatic Classification," Proceedings of the 8th International Symposium on Visualization for Cyber Security, 2011.
2. I. J. Goodfellow, J. Shlens, and C. Szegedy, "Explaining and Harnessing Adversarial Examples," International Conference on Learning Representations, 2015. <https://arxiv.org/abs/1412.6572>
3. A. Madry, A. Makelov, L. Schmidt, D. Tsipras, and A. Vladu, "Towards Deep Learning Models Resistant to Adversarial Attacks," International Conference on Learning Representations, 2018. <https://arxiv.org/abs/1706.06083>
4. A. Howard et al., "Searching for MobileNetV3," IEEE/CVF International Conference on Computer Vision, 2019. <https://arxiv.org/abs/1905.02244>
5. M. Tan and Q. V. Le, "EfficientNet: Rethinking Model Scaling for Convolutional Neural Networks," International Conference on Machine Learning, 2019. <https://arxiv.org/abs/1905.11946>
6. J. Ren et al., "Balanced Meta-Softmax for Long-Tailed Visual Recognition," Neural Information Processing Systems, 2020. <https://arxiv.org/abs/2007.10740>
7. Y. Zhang et al., "Towards Adversarial Training on Long-Tailed Data," IEEE/CVF Conference on Computer Vision and Pattern Recognition, 2024.
8. R. R. Selvaraju et al., "Grad-CAM: Visual Explanations from Deep Networks via Gradient-Based Localization," IEEE International Conference on Computer Vision, 2017. <https://arxiv.org/abs/1610.02391>
9. F. Croce and M. Hein, "Reliable Evaluation of Adversarial Robustness with an Ensemble of Diverse Parameter-Free Attacks," International Conference on Machine Learning, 2020. <https://arxiv.org/abs/2003.01690>
10. L. Rice, E. Wong, and J. Z. Kolter, "Overfitting in Adversarially Robust Deep Learning," International Conference on Machine Learning, 2020. <https://arxiv.org/abs/2002.11569>
