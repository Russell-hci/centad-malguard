# Final Research Report

## Improving the Robustness of Lightweight Deep Learning Models Against Adversarial Attacks in Malware Classification

**Final system:** CenTaD-MalGuard
**Date:** 2026-06-01

## Abstract

Malware image classification uses computer vision models to classify malware families from image-like representations of binary files. Lightweight convolutional neural networks are attractive for this task because they can be accurate and efficient enough for constrained deployment settings. However, high clean accuracy does not guarantee cybersecurity robustness: adversarial perturbations can cause a model to make confident incorrect predictions. This project evaluates the robustness of lightweight malware image classifiers under FGSM and PGD attacks using a duplicate-aware MalImg protocol. MobileNetV3 Small achieved 97.92% clean accuracy and 93.53% macro F1, but its accuracy dropped to 18.06% under FGSM at eps=0.03 and to 0.29% under PGD-20. PGD adversarial training improved MobileNetV3 robustness substantially: FGSM accuracy increased from 18.06% to 82.87%, PGD-20 accuracy increased from 0.29% to 20.00%, clean accuracy remained high at 97.35%, and model size remained unchanged at 5.934 MB. Grad-CAM analysis provided supporting evidence that adversarial attacks can disrupt model attention and that adversarial training may improve attention stability on representative examples. The final result is CenTaD-MalGuard, a lightweight adversarially robust malware image classification demonstration system that packages the research into a judge-facing cybersecurity solution.

## Introduction

Machine learning is increasingly used in cybersecurity settings where models must operate against active adversaries. Malware classification is one such setting. A classifier that performs well on clean test data may still be unreliable if an attacker can deliberately modify inputs to force misclassification.

This project studies malware image classification, where malware binaries are represented as images and classified into malware families. The central research question is:

> Can lightweight malware image classifiers remain accurate and robust under adversarial attack conditions while still being efficient enough for deployment on resource-constrained devices?

The project focuses on lightweight architectures because deployment efficiency matters in practical security environments. MobileNetV3 Small and EfficientNet-B0 were selected as candidate models. FGSM was used as a fast one-step attack, while PGD was used as the primary iterative robustness benchmark. PGD adversarial training was then applied to MobileNetV3 to test whether the lightweight baseline could be hardened without changing its architecture or increasing model size.

The final phase converted the research into CenTaD-MalGuard, a demonstrable cybersecurity system. The demo shows a standard detector correctly classify a malware sample, an adversarial attack fool the detector, and the robust MalGuard detector recover the correct family.

## Related Work

Malware image classification is based on the observation that malware binaries can be converted into visual representations and classified using image-recognition models. This approach allows computer vision architectures to learn texture-like and structural patterns associated with malware families.

Lightweight neural networks such as MobileNet and EfficientNet are designed to reduce parameter count and computational cost while retaining strong classification performance. These models are relevant for malware classification because cybersecurity systems may need low-latency inference or deployment on constrained devices.

Adversarial machine learning shows that neural networks can be vulnerable to small, carefully chosen perturbations. FGSM uses a single gradient step to generate adversarial examples, while PGD applies repeated projected gradient steps and is generally considered a stronger first-order white-box attack. Adversarial training improves robustness by training on adversarial examples, but it can reduce clean accuracy or increase computational cost depending on implementation.

Explainability methods such as Grad-CAM visualize regions that contribute to model predictions. In this project, Grad-CAM is not treated as proof of semantic malware understanding. It is used as supporting evidence to examine whether attacks change model attention and whether adversarial training stabilizes attention patterns.

## Methodology

### Dataset

The project used the MalImg dataset, an established malware image dataset with 25 malware families and approximately 9.3k images. The dataset is class-imbalanced, which makes macro F1 important alongside accuracy.

### Models

Two lightweight architectures were evaluated:

| Model | Role |
|---|---|
| MobileNetV3 Small | Primary lightweight deployment candidate and final defense target. |
| EfficientNet-B0 | Lightweight comparison model with higher capacity and larger footprint. |

Both models used ImageNet-pretrained torchvision backbones with classifier heads adapted to the 25 MalImg classes.

### Attacks

Two white-box attacks were evaluated:

| Attack | Purpose |
|---|---|
| FGSM | Fast one-step sensitivity probe. |
| PGD | Stronger iterative benchmark and primary robustness test. |

Important implementation decision: attacks were defined in raw pixel space `[0,1]`, not normalized tensor space. The dataloaders return ImageNet-normalized tensors, so the attack pipeline denormalizes images and wraps the classifier so the attack sees raw pixels while the model still receives normalized inputs internally.

Attack Success Rate was computed only over samples that were correctly classified before attack. This avoids counting already-wrong clean predictions as attack successes.

### Defense

The official defense is MobileNetV3 PGD adversarial training:

- initialized from the official duplicate-aware MobileNetV3 clean baseline checkpoint
- PGD training attack: eps=0.03, alpha=0.003, steps=10
- random start enabled
- 50% clean and 50% adversarial samples in training batches
- fine-tuning learning rate: 1e-4
- 5 epochs
- architecture unchanged

## Duplicate-Aware Protocol

An early stratified split had no file-path overlap, but image-content SHA-256 analysis found exact duplicate images crossing train/validation/test. This was a methodological risk because duplicates can inflate generalization estimates.

The project corrected this by creating an official duplicate-aware split:

1. Compute image-content SHA-256 hashes.
2. Group images by content hash within each malware family.
3. Assign each duplicate group wholly to train, validation, or test.
4. Preserve approximate 70/15/15 ratios.
5. Validate no file-path overlap, no content-hash overlap, and no missing classes.

Official split:

| Split | Samples |
|---|---:|
| Train | 6,539 |
| Validation | 1,405 |
| Test | 1,395 |

All official baseline, attack, defense, and explainability conclusions use this duplicate-aware protocol.

## Baseline Results

The duplicate-aware clean baselines showed that lightweight models can perform well on clean malware image classification.

| Model | Accuracy | Macro F1 | Parameters | Model Size |
|---|---:|---:|---:|---:|
| MobileNetV3 Small | 0.979211 | 0.935261 | 1,543,481 | 5.934 MB |
| EfficientNet-B0 | 0.960573 | 0.879898 | 4,039,573 | 15.57 MB |

MobileNetV3 was selected as the primary model because it achieved higher accuracy and macro F1 while being much smaller than EfficientNet-B0. This made it the best candidate for a deployable lightweight solution.

## FGSM Results

FGSM evaluation measured one-step adversarial sensitivity across multiple epsilon values.

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

MobileNetV3 dropped from 97.92% clean accuracy to 18.06% accuracy at eps=0.03. EfficientNet-B0 sometimes retained higher attacked accuracy, but macro F1 remained very low, indicating poor family-balanced robustness.

FGSM validation confirmed that perturbations were bounded correctly in raw pixel space and that the degradation was not caused by a normalization or clipping error.

## PGD Results

PGD was the official primary robustness benchmark because it is a stronger iterative attack.

Primary PGD results:

| Model | Attack | Accuracy | Macro F1 | ASR |
|---|---|---:|---:|---:|
| MobileNetV3 | PGD-10 | 0.007168 | 0.003873 | 0.992679 |
| MobileNetV3 | PGD-20 | 0.002867 | 0.000706 | 0.997072 |
| EfficientNet-B0 | PGD-10 | 0.089606 | 0.008013 | 0.906716 |
| EfficientNet-B0 | PGD-20 | 0.150538 | 0.015908 | 0.843284 |

PGD nearly destroyed MobileNetV3 performance: PGD-20 accuracy fell to 0.29%. EfficientNet-B0 retained higher attacked accuracy, but macro F1 remained extremely low. This supports the conclusion that clean accuracy does not imply adversarial robustness.

## Adversarial Training Results

PGD adversarial training substantially improved robustness while preserving clean accuracy and efficiency.

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

The defense did not increase model size or parameter count because the architecture remained MobileNetV3 Small. Clean accuracy decreased by only 0.57 percentage points. The largest improvement was against FGSM, where accuracy increased by 64.80 percentage points. PGD-20 accuracy improved by 19.71 percentage points, but macro F1 remained low, indicating that robustness remains uneven across families.

## Grad-CAM Findings

The Grad-CAM phase was designed to answer three questions:

1. How do attacks affect model attention?
2. Does adversarial training stabilize attention?
3. Do robust models appear to focus on more consistent regions?

The curated evidence package selected 16 representative examples from the official duplicate-aware test split, including recovery cases, failure cases, strong-family examples, and weak-family examples.

For each selected sample, the pipeline generated:

- clean image
- FGSM adversarial image
- PGD adversarial image
- perturbation visualizations
- Grad-CAM overlays for the standard model and robust model
- attention-stability metrics

Summary attention-stability metrics:

| Model | Attack | Top-20% IoU Mean | Center-Shift Mean |
|---|---|---:|---:|
| Baseline | FGSM | 0.0905 | 0.1159 |
| Defense | FGSM | 0.3364 | 0.0822 |
| Baseline | PGD | 0.1355 | 0.0782 |
| Defense | PGD | 0.3607 | 0.0617 |

Higher Top-20% IoU indicates more overlap between clean and attacked attention regions. Lower center-of-mass shift indicates smaller movement in attention location. On the curated sample set, the robust model showed higher heatmap overlap and lower center shift under both FGSM and PGD.

These findings support the project narrative: adversarial attacks can disrupt classifier behavior and attention, while adversarial training improves robustness and may stabilize attention. However, Grad-CAM remains interpretive evidence and should not be overclaimed.

## CenTaD-MalGuard System

CenTaD-MalGuard packages the completed research into a demonstrable cybersecurity solution.

The demo workflow is:

```text
clean detection -> attack launched -> detector fooled -> MalGuard defense -> prediction recovered -> explanation and evidence
```

The default demonstration uses sample:

```text
05_allaple_a_pgd
```

In this example:

- the standard detector correctly classifies the clean malware image as `Allaple.A`
- the PGD attack changes the standard detector prediction to `Malex.gen!J`
- the MalGuard robust detector recovers the true family `Allaple.A`

The app is a static HTML/CSS/JavaScript interface served locally with Python's built-in HTTP server. It uses precomputed canonical assets only. It does not run model inference, generate attacks, or retrain models during the demo.

Run command:

```bash
python3 -m http.server 8765
```

Demo URL:

```text
http://localhost:8765/demo/centad-malguard/
```

## Innovation, Uniqueness, And Effectiveness

CenTaD-MalGuard is innovative because it treats malware image classification as a security system, not only as an image-classification benchmark. The project does not stop at clean test accuracy. It combines duplicate-aware evaluation, white-box adversarial attack testing, PGD adversarial training, Grad-CAM explainability, and a judge-facing demonstration into one reproducible solution package.

The project is unique in its integration of five elements:

1. **Duplicate-aware malware image evaluation:** exact image-content SHA-256 grouping prevents train/test leakage from duplicated malware images.
2. **Robustness-first testing:** FGSM, PGD-10, PGD-20, attack success rate, macro F1, latency, model size, and parameter count are evaluated together.
3. **Lightweight defense:** the final robust detector keeps the same MobileNetV3 Small architecture, parameter count, and 5.934 MB model size.
4. **Attention evidence:** Grad-CAM visualizations and lightweight attention-stability metrics show how attacks can affect model focus and how adversarial training may stabilize it.
5. **Demonstrable product:** CenTaD-MalGuard turns the experiment into a concrete cybersecurity workflow: classify, attack, defend, explain, quantify.

Within the evaluated scope, the solution is effective. PGD adversarial training improved FGSM accuracy from 18.06% to 82.87% and PGD-20 accuracy from 0.29% to 20.00%, while clean accuracy remained high at 97.35% and model size stayed unchanged. The defense does not solve adversarial malware classification completely, but it demonstrates a practical robustness improvement with a clear efficiency profile.

## Limitations

1. **Dataset scope:** MalImg is an image representation of malware binaries. Results may not generalize to raw-byte, dynamic-analysis, API-sequence, or behavioral malware classifiers.
2. **Class imbalance:** MalImg is imbalanced, so accuracy can hide poor minority-family robustness. Macro F1 is therefore essential.
3. **Attack scope:** The project evaluates white-box FGSM and PGD attacks. It does not evaluate black-box transfer attacks, adaptive attacks, or real malware-preserving binary transformations.
4. **Defense scope:** Only MobileNetV3 received adversarial training. EfficientNet-B0 was retained as a comparison baseline.
5. **Robustness remains incomplete:** PGD-20 accuracy improved, but PGD-20 macro F1 remained low after defense.
6. **Grad-CAM interpretability:** Grad-CAM provides useful visual evidence but does not prove semantic malware understanding.
7. **Reproducibility caveat:** Strict CUDA bit-level determinism may require setting `CUBLAS_WORKSPACE_CONFIG=:4096:8` before Python starts.

## Future Work

High-value future work includes:

1. Evaluate black-box transfer attacks to test robustness beyond white-box first-order attacks.
2. Study family-balanced adversarial training or loss weighting to improve macro F1 under PGD.
3. Test robustness on additional malware representations such as raw-byte or API-sequence models.
4. Evaluate adaptive attacks against the adversarially trained model.
5. Improve explainability analysis with larger sample sets and additional attribution methods.
6. Package model inference into a controlled local backend if the demo later needs live classification instead of precomputed assets.

## Conclusion

This project demonstrates that lightweight malware image classifiers can be highly accurate on clean data but extremely vulnerable to adversarial attacks. A duplicate-aware protocol showed MobileNetV3 Small reaching 97.92% clean accuracy, yet PGD-20 reduced its accuracy to 0.29%. PGD adversarial training improved FGSM accuracy to 82.87% and PGD-20 accuracy to 20.00% while preserving clean accuracy at 97.35% and keeping model size unchanged at 5.934 MB.

The central research question is therefore substantially answered: lightweight malware classifiers can be hardened against adversarial attacks without losing their efficiency advantage, but adversarial robustness is not fully solved. CenTaD-MalGuard communicates this result as a concrete cybersecurity demonstration: the standard detector is fooled, the robust detector recovers, and the evidence shows why robustness must be evaluated alongside clean accuracy.
