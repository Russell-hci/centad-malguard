# Executive Summary

## CenTaD-MalGuard

**A lightweight malware reliability system for adversarial robustness and attention stability**

## The Problem

Modern malware classifiers can achieve high accuracy on clean test data, but cybersecurity models face active adversaries. An attacker may intentionally modify an input to cause a machine-learning detector to make the wrong decision. This project investigates that problem in malware image classification, where malware binaries are represented as grayscale images and classified into malware families.

The key finding is simple:

> A malware classifier can be highly accurate and still be fragile under adversarial attack.

The official MobileNetV3 malware classifier reached **97.92% clean accuracy**, but under the strongest evaluated PGD-20 attack its accuracy dropped to **0.29%**.

## The Solution

CenTaD-MalGuard uses **PGD adversarial training** to harden a lightweight MobileNetV3 malware image classifier. The final product is not just a classifier; it is a reliability workflow that stress-tests the standard detector, activates the robust detector, and uses Grad-CAM to inspect whether attention remains more stable under attack.

The solution is intentionally practical:

- no new dataset
- no larger architecture
- no increase in parameter count
- no increase in model size
- same lightweight MobileNetV3 deployment footprint

## Key Results

| Metric | Standard MobileNetV3 | MalGuard Robust MobileNetV3 | Result |
|---|---:|---:|---|
| Clean Accuracy | 97.92% | 97.35% | nearly preserved |
| FGSM Accuracy, eps=0.03 | 18.06% | 82.87% | large improvement |
| PGD-20 Accuracy | 0.29% | 20.00% | large improvement |
| PGD Top-20% Attention IoU | 0.1355 | 0.3607 | higher overlap |
| Model Size | 5.934 MB | 5.934 MB | unchanged |
| Parameters | 1,543,481 | 1,543,481 | unchanged |

The strongest result is the robustness-efficiency tradeoff: adversarial training dramatically improved robustness while preserving nearly all clean accuracy and keeping the model lightweight.

## Innovation And Impact

CenTaD-MalGuard is designed as a cybersecurity solution, not only an experiment. Its novelty is the complete package: duplicate-aware malware image evaluation, adversarial attack simulation, robust lightweight defense, and an attention-stability lens that uses Grad-CAM to compare model focus before and after attack.

The most distinctive finding is that adversarial training appears to improve both prediction robustness and attention stability on representative malware images. The project is effective within its evaluated scope because the robust detector improves adversarial accuracy while preserving deployment constraints. It does not require a larger model, a new dataset, or a new architecture.

## Scientific Contribution

This project contributes four important pieces of evidence.

### 1. Duplicate-aware evaluation

The original train/validation/test split had no file-path overlap, but image-content hashing revealed exact duplicate images across splits. The project corrected this by creating a duplicate-aware protocol that keeps identical image-content hashes in the same split. All official results use this corrected protocol.

### 2. Clean accuracy is not enough

MobileNetV3 reached **97.92%** clean accuracy, showing strong baseline performance. However, the same model fell to **18.06%** accuracy under FGSM and **0.29%** under PGD-20. This shows that clean accuracy alone does not measure cybersecurity reliability.

### 3. PGD adversarial training improves robustness

The adversarially trained MobileNetV3 improved FGSM accuracy from **18.06% to 82.87%** and PGD-20 accuracy from **0.29% to 20.00%** while keeping model size unchanged.

### 4. Grad-CAM supports the explanation

Grad-CAM visualizations show that attacks can change what the model focuses on. On the curated explainability set, the robust model showed higher heatmap overlap and lower attention shift under both FGSM and PGD. This is the project's strongest behavioral insight: adversarial training may stabilize model attention as well as improve attacked accuracy. It remains supporting evidence, not proof of semantic malware understanding.

## CenTaD-MalGuard Demo

The final system is a local web demonstration designed for judging.

Demo flow:

```text
clean detection -> attack launched -> detector fooled -> MalGuard defense -> prediction recovered -> attention stability evidence
```

The default demonstration uses sample:

```text
05_allaple_a_pgd
```

In this example:

1. The standard detector correctly identifies the clean sample as `Allaple.A`.
2. A PGD attack fools the standard detector into predicting `Malex.gen!J`.
3. MalGuard's robust detector recovers the correct family: `Allaple.A`.

This makes the project understandable in under one minute: the attack breaks the standard detector, and MalGuard recovers.

## Limitations

The project does not claim to solve adversarial malware classification completely.

Important limitations:

- MalImg is an image-based malware dataset and may not generalize to all malware-detection settings.
- The dataset is class-imbalanced.
- Only white-box FGSM and PGD attacks were evaluated.
- Only MobileNetV3 received adversarial training.
- PGD-20 macro F1 remains low after defense, meaning family-balanced robustness is improved but not solved.
- Grad-CAM is supporting evidence, not definitive proof of how the model reasons.

## Final Takeaway

CenTaD-MalGuard demonstrates a practical cybersecurity lesson:

> A malware classifier must be evaluated not only by clean accuracy, but also by how it behaves under attack.

The project shows that lightweight malware classifiers are vulnerable to adversarial attacks, and that PGD adversarial training can substantially improve robustness without increasing model size. Its distinctive contribution is turning that defense into a reliability system that also checks attention stability, giving judges a clearer reason to remember the project as insight rather than only implementation.
