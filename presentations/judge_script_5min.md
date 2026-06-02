# 5-Minute Judge Script

## Goal

Give judges a complete but concise explanation of the research question, method, demo, evidence, and limitations.

## 0:00-0:30 Opening

My project is **CenTaD-MalGuard**, a lightweight adversarially robust malware image classification system.

The core question is:

```text
Can a lightweight malware classifier remain accurate and robust under adversarial attack while staying efficient enough for practical use?
```

The short answer from my experiments is: yes, robustness can be improved substantially, but it is not fully solved.

## 0:30-1:10 Malware Image Classification

The dataset is MalImg. In malware image classification, malware binaries are represented as grayscale images. A computer vision model then predicts the malware family.

This is useful because image models can learn visual patterns in malware families. But cybersecurity is adversarial. A model that works on clean test images might fail when an attacker deliberately changes the input to cause a wrong prediction.

That is the problem CenTaD-MalGuard demonstrates.

## 1:10-1:55 Duplicate-Aware Protocol

Before evaluating robustness, I found a methodology issue. The original split had no file-path overlap, but when I hashed the image content, exact duplicate images appeared across train, validation, and test.

That matters because duplicates can make the model appear more generalizable than it really is.

I corrected this with a duplicate-aware protocol:

- compute image-content SHA-256 hashes
- group duplicate images together
- ensure a duplicate group appears in only one split
- preserve train/validation/test proportions as closely as possible

All official results use the duplicate-aware split:

- 6,539 training samples
- 1,405 validation samples
- 1,395 test samples

## 1:55-2:35 Baseline And Vulnerability

The best clean baseline was MobileNetV3 Small:

- 97.92% clean accuracy
- 93.53% macro F1
- 1.54 million parameters
- 5.934 MB model size

That made it a strong lightweight baseline.

But adversarial testing showed severe vulnerability:

- FGSM eps=0.03 reduced accuracy to 18.06%.
- PGD-10 reduced accuracy to 0.72%.
- PGD-20 reduced accuracy to 0.29%.

So the model was highly accurate on clean samples but almost completely broken under the strongest attack.

## 2:35-3:45 Live Demo

Now I will show the default demo case:

```text
05_allaple_a_pgd
```

This is the strongest recovery example.

First, the standard detector sees the clean malware image and correctly predicts:

```text
Allaple.A
```

Next, I launch the PGD attack. PGD is an iterative adversarial attack that changes the input to make the model fail.

After the attack, the standard detector is fooled and predicts:

```text
Malex.gen!J
```

This demonstrates the security problem: the detector gives a wrong malware-family prediction under attack.

Now I activate the MalGuard robust detector. It uses the same MobileNetV3 architecture, but it was adversarially trained with PGD examples.

For this example, MalGuard recovers the correct family:

```text
Allaple.A
```

That is the main demo story: clean detection works, attack breaks the standard detector, and MalGuard recovers.

## 3:45-4:35 Quantitative Evidence

The official adversarial-training result is:

| Metric | Standard MobileNetV3 | MalGuard Robust MobileNetV3 |
|---|---:|---:|
| Clean Accuracy | 97.92% | 97.35% |
| FGSM Accuracy | 18.06% | 82.87% |
| PGD-20 Accuracy | 0.29% | 20.00% |
| Model Size | 5.934 MB | 5.934 MB |

The important tradeoff is that robustness improved substantially while clean accuracy decreased by only about 0.57 percentage points and model size did not increase.

## 4:35-5:00 Grad-CAM And Closing

Grad-CAM provides a simple visual explanation. It highlights where the model focuses when making a prediction. The evidence suggests that attacks can change what the standard model focuses on, while adversarial training appears to make attention more stable on representative examples.

The limitation is that PGD-20 macro F1 remains low, so robustness is improved but not solved.

Final takeaway:

```text
Clean accuracy is not enough for cybersecurity. CenTaD-MalGuard shows that adversarial training can make a lightweight malware classifier more robust without increasing model size.
```
