# CenTaD-MalGuard Poster

## Lightweight Malware Reliability Under Adversarial Attack

### Problem

Adversarial attacks can fool malware classifiers. A model can look accurate on clean malware images but fail when an attacker intentionally changes the input.

### Research Question

Can a lightweight malware image classifier remain accurate and robust under adversarial attack while staying efficient enough for practical deployment?

### Dataset And Protocol

- Dataset: MalImg malware image dataset
- Classes: 25 malware families
- Official protocol: duplicate-aware train/validation/test split
- Duplicate control: image-content SHA-256 grouping
- Official split: 6,539 train / 1,405 validation / 1,395 test

### Baseline

| Model | Clean Accuracy | Macro F1 | Size |
|---|---:|---:|---:|
| MobileNetV3 Small | 97.92% | 93.53% | 5.934 MB |
| EfficientNet-B0 | 96.06% | 87.99% | 15.57 MB |

MobileNetV3 was selected as the primary solution target because it was more accurate and much smaller.

### Attack Results

| Attack | Standard MobileNetV3 Accuracy | Macro F1 |
|---|---:|---:|
| Clean | 97.92% | 93.53% |
| FGSM eps=0.03 | 18.06% | 3.22% |
| PGD-10 eps=0.03 | 0.72% | 0.39% |
| PGD-20 eps=0.03 | 0.29% | 0.07% |

### MalGuard Solution

MalGuard is a reliability workflow: expose the standard detector's failure, recover with PGD-adversarially-trained MobileNetV3, then use Grad-CAM to check whether attention is more stable under attack.

| Metric | Standard | MalGuard | Result |
|---|---:|---:|---|
| Clean Accuracy | 97.92% | 97.35% | nearly preserved |
| FGSM Accuracy | 18.06% | 82.87% | large improvement |
| PGD-20 Accuracy | 0.29% | 20.00% | large improvement |
| Model Size | 5.934 MB | 5.934 MB | unchanged |

### Attention-Stability Insight

Grad-CAM shows that adversarial attacks can change what the model focuses on. On curated examples, adversarial training appears to make attention more stable. This is the project's distinctive behavioral finding.

| Model | Attack | Top-20% IoU | Center Shift |
|---|---|---:|---:|
| Standard | FGSM | 0.0905 | 0.1159 |
| MalGuard | FGSM | 0.3364 | 0.0822 |
| Standard | PGD | 0.1355 | 0.0782 |
| MalGuard | PGD | 0.3607 | 0.0617 |

### Demo Flow

```text
clean detection -> attack launched -> detector fooled -> MalGuard defense -> prediction recovered -> attention stability evidence
```

Default example:

```text
05_allaple_a_pgd
```

The standard detector is fooled by PGD, but MalGuard recovers the correct family: `Allaple.A`.

### Contribution

1. Duplicate-aware malware image classification protocol.
2. Evidence that lightweight clean classifiers are highly vulnerable to FGSM and PGD.
3. PGD adversarial training improves robustness without increasing model size.
4. Grad-CAM attention-stability evidence supports the attack/defense explanation.
5. CenTaD-MalGuard packages the research into a demonstrable malware reliability system.

### Limitation

Robustness is improved but not solved. PGD-20 macro F1 remains low, and future work should evaluate black-box and adaptive attacks.

### Takeaway

Clean accuracy is not enough for cybersecurity. CenTaD-MalGuard demonstrates that lightweight malware classifiers can be hardened against adversarial attacks while preserving deployment efficiency and producing supporting attention-stability evidence.
