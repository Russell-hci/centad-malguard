# 10-Minute Judge Script

## Goal

Use this script when a judge wants a deeper explanation of the full research process, including protocol design, experimental results, demo, Grad-CAM, limitations, and future work.

## 0:00-0:45 Opening

My project is **CenTaD-MalGuard**, a lightweight adversarially robust malware image classification system.

The project asks:

```text
Can lightweight malware image classifiers remain accurate and robust under adversarial attack while still being efficient enough for practical deployment?
```

The final answer is nuanced. Lightweight malware classifiers can be highly accurate, but they are extremely vulnerable to adversarial attacks. PGD adversarial training substantially improves robustness without increasing model size, but robustness is still not fully solved.

## 0:45-1:40 Background

This project uses malware image classification. Malware binaries are converted into grayscale image-like representations. A computer vision model then classifies the image into a malware family.

This approach is useful because convolutional networks can learn visual patterns in malware families. However, cybersecurity is different from ordinary image classification because attackers may deliberately manipulate inputs.

An adversarial attack makes a small, targeted change to the input so the model predicts the wrong class. In malware detection, that means a classifier may look accurate in normal testing but fail when an attacker tries to evade it.

## 1:40-2:40 Dataset And Duplicate-Aware Protocol

The dataset is MalImg, which contains 25 malware families and about 9.3k images.

One of the most important parts of the project was correcting the evaluation protocol. At first, the split had no file-path overlap. However, I checked image-content SHA-256 hashes and found exact duplicate image content across train, validation, and test splits.

That is a problem because if the same image content appears in both training and testing, the measured accuracy may be inflated.

I created a duplicate-aware split:

1. Hash image content.
2. Group exact duplicates by hash.
3. Keep each duplicate group entirely in train, validation, or test.
4. Preserve approximate 70/15/15 split proportions.
5. Verify no file overlap, no content-hash overlap, and no missing classes.

Official split:

| Split | Samples |
|---|---:|
| Train | 6,539 |
| Validation | 1,405 |
| Test | 1,395 |

All official results use this duplicate-aware protocol.

## 2:40-3:35 Clean Baselines

I evaluated two lightweight models:

- MobileNetV3 Small
- EfficientNet-B0

Official duplicate-aware clean baseline results:

| Model | Accuracy | Macro F1 | Parameters | Model Size |
|---|---:|---:|---:|---:|
| MobileNetV3 Small | 97.92% | 93.53% | 1,543,481 | 5.934 MB |
| EfficientNet-B0 | 96.06% | 87.99% | 4,039,573 | 15.57 MB |

MobileNetV3 was selected as the main solution target because it was more accurate, had higher macro F1, and was much smaller.

At this stage, MobileNetV3 looked like an excellent lightweight malware classifier.

## 3:35-4:35 Adversarial Attack Results

Next, I evaluated adversarial robustness.

I used FGSM as a fast one-step attack and PGD as the stronger iterative attack. The attacks were implemented in raw pixel space, so eps=0.03 means a raw pixel-space perturbation, not a normalized tensor-space perturbation.

MobileNetV3 results:

| Condition | Accuracy | Macro F1 | Attack Success Rate |
|---|---:|---:|---:|
| Clean | 97.92% | 93.53% | not applicable |
| FGSM eps=0.03 | 18.06% | 3.22% | 81.63% |
| PGD-10 eps=0.03 | 0.72% | 0.39% | 99.27% |
| PGD-20 eps=0.03 | 0.29% | 0.07% | 99.71% |

This is the central vulnerability: the model is highly accurate on clean data, but PGD almost completely breaks it.

## 4:35-5:25 Defense: PGD Adversarial Training

The defense was PGD adversarial training for MobileNetV3.

The model started from the official clean MobileNetV3 checkpoint. During training, batches mixed clean and PGD-adversarial examples. The architecture stayed the same.

This matters because I wanted to test whether robustness could improve without making the model larger.

Official defense results:

| Metric | Standard MobileNetV3 | MalGuard Robust MobileNetV3 |
|---|---:|---:|
| Clean Accuracy | 97.92% | 97.35% |
| FGSM Accuracy, eps=0.03 | 18.06% | 82.87% |
| PGD-10 Accuracy | 0.72% | 42.94% |
| PGD-20 Accuracy | 0.29% | 20.00% |
| Model Size | 5.934 MB | 5.934 MB |
| Parameters | 1,543,481 | 1,543,481 |

The result is a strong robustness-efficiency tradeoff. Robustness improved dramatically, clean accuracy remained high, and the model size did not increase.

## 5:25-6:55 Live Demo

Now I will demonstrate the result using CenTaD-MalGuard.

The default example is:

```text
05_allaple_a_pgd
```

This is the strongest recovery case.

### Step 1: Clean detection

The standard detector sees the clean malware image and correctly predicts:

```text
Allaple.A
```

### Step 2: Attack launched

I launch the PGD evasion attack. The perturbation visualization shows the change applied to the image.

### Step 3: Detector fooled

The standard detector now predicts:

```text
Malex.gen!J
```

This is a high-confidence wrong answer. It demonstrates why clean accuracy is not sufficient for cybersecurity.

### Step 4: MalGuard defense activated

Now I switch to the MalGuard robust detector, which is the PGD-adversarially-trained MobileNetV3.

### Step 5: Correct prediction recovered

MalGuard predicts:

```text
Allaple.A
```

So the attack fools the standard detector, but MalGuard recovers the correct family on this example.

## 6:55-7:55 Grad-CAM Explanation

Grad-CAM is used to visualize what regions the model focuses on.

The simple explanation is:

```text
Attacks can change what the model focuses on.
Adversarial training appears to make attention more stable.
```

On the curated explainability set:

| Model | Attack | Top-20% IoU Mean | Center-Shift Mean |
|---|---|---:|---:|
| Standard | FGSM | 0.0905 | 0.1159 |
| MalGuard | FGSM | 0.3364 | 0.0822 |
| Standard | PGD | 0.1355 | 0.0782 |
| MalGuard | PGD | 0.3607 | 0.0617 |

Higher overlap and lower shift suggest more stable attention. I treat this as supporting evidence, not proof that the model understands malware semantics.

## 7:55-8:50 Contribution

The project contributes:

1. A duplicate-aware malware image classification protocol.
2. Clean baseline evidence for MobileNetV3 and EfficientNet-B0.
3. FGSM and PGD robustness evaluation showing severe vulnerability.
4. PGD adversarial training showing large robustness gains without increasing model size.
5. Grad-CAM evidence showing how attacks affect attention.
6. A polished demo system that communicates the cybersecurity problem and solution clearly.

## 8:50-9:35 Limitations

The project has important limitations.

First, MalImg is an image representation of malware, so results may not generalize to all malware detection methods.

Second, the dataset is class-imbalanced, so macro F1 matters. PGD-20 macro F1 remains low after defense, meaning family-balanced robustness is improved but not solved.

Third, I evaluated white-box FGSM and PGD, not black-box transfer attacks or adaptive attacks.

Fourth, only MobileNetV3 was adversarially trained.

## 9:35-10:00 Closing

The final takeaway is:

```text
Clean accuracy is not enough for cybersecurity.
```

CenTaD-MalGuard shows that a lightweight malware classifier can be highly accurate but vulnerable, and that PGD adversarial training can substantially improve robustness while keeping the model lightweight.

The project does not claim to solve adversarial malware classification. It shows a practical, evidence-backed path toward more robust lightweight malware detection.
