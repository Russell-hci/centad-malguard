# CenTaD-MalGuard Final Slide Deck

## Slide 1: Title

**CenTaD-MalGuard**

Lightweight Malware Reliability Under Adversarial Attack

Key message:

```text
Adversarial attacks can fool malware classifiers. MalGuard improves robustness without increasing model size and checks whether model attention is more stable.
```

## Slide 2: Problem

Malware classifiers can be highly accurate on clean samples but fail under adversarial attack.

Why this matters:

- cybersecurity models face active adversaries
- clean accuracy does not measure attack resistance
- a confident wrong malware-family prediction can undermine trust

## Slide 3: Research Question

Can lightweight malware image classifiers remain accurate and robust under adversarial attack while still being efficient enough for practical deployment?

## Slide 4: Dataset And Duplicate-Aware Protocol

- Dataset: MalImg
- 25 malware families
- Official split: duplicate-aware SHA-256 image-content grouping
- Train: 6,539
- Validation: 1,405
- Test: 1,395

Why it matters:

```text
Duplicate leakage would inflate evaluation. The official protocol prevents exact duplicate image content from crossing splits.
```

## Slide 5: Clean Baseline

| Model | Clean Accuracy | Macro F1 | Model Size |
|---|---:|---:|---:|
| MobileNetV3 Small | 97.92% | 93.53% | 5.934 MB |
| EfficientNet-B0 | 96.06% | 87.99% | 15.57 MB |

MobileNetV3 became the solution target because it was smaller and more accurate.

## Slide 6: Attack Results

| Condition | MobileNetV3 Accuracy | Macro F1 |
|---|---:|---:|
| Clean | 97.92% | 93.53% |
| FGSM eps=0.03 | 18.06% | 3.22% |
| PGD-20 eps=0.03 | 0.29% | 0.07% |

Conclusion:

```text
The standard detector is accurate, but not robust.
```

## Slide 7: MalGuard Solution

MalGuard is a reliability workflow:

1. expose the standard detector's failure under attack
2. recover with PGD-adversarially-trained MobileNetV3
3. audit attention stability with Grad-CAM

Design goal:

```text
Improve robustness without increasing deployment cost.
```

## Slide 8: Robustness-Efficiency Result

| Metric | Standard | MalGuard |
|---|---:|---:|
| Clean Accuracy | 97.92% | 97.35% |
| FGSM Accuracy | 18.06% | 82.87% |
| PGD-20 Accuracy | 0.29% | 20.00% |
| Model Size | 5.934 MB | 5.934 MB |

## Slide 9: Demo Flow

Default sample:

```text
05_allaple_a_pgd
```

Story:

```text
clean detection -> attack launched -> detector fooled -> MalGuard defense -> prediction recovered
```

The standard detector predicts `Malex.gen!J` after attack. MalGuard recovers `Allaple.A`.

## Slide 10: Attention-Stability Insight

Grad-CAM shows where the model focuses. In this project, it is used as an attention-stability lens, not just a visualization.

Simple message:

```text
Attacks can change model attention. Adversarial training appears to make attention more stable.
```

| Attack | Standard Top-20 IoU | MalGuard Top-20 IoU |
|---|---:|---:|
| FGSM | 0.0905 | 0.3364 |
| PGD | 0.1355 | 0.3607 |

## Slide 11: Limitations

- MalImg is image-based and may not generalize to all malware detectors.
- Only white-box FGSM and PGD were evaluated.
- PGD-20 macro F1 remains low.
- Grad-CAM is supporting evidence, not proof of semantic understanding.

## Slide 12: Final Takeaway

```text
Clean accuracy is not enough for cybersecurity.
```

CenTaD-MalGuard demonstrates that PGD adversarial training can make a lightweight malware classifier substantially more robust while preserving clean accuracy and model size, with supporting evidence that robust training may stabilize attention under attack.
