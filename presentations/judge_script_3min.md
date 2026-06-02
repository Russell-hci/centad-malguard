# 3-Minute Judge Script

## Goal

Explain the project quickly and run the strongest live demo path.

## Opening: 20 Seconds

Hello, my project is **CenTaD-MalGuard**, a lightweight malware reliability system that tests whether a classifier still works after an adversarial attack.

The problem is that a malware classifier can look very accurate on normal test samples but fail when an attacker deliberately changes the input to fool the model. In cybersecurity, clean accuracy is not enough. A detector also needs robustness.

## Problem And Baseline: 35 Seconds

This project uses the MalImg malware image dataset. Malware binaries are represented as grayscale images, and the model classifies which malware family the sample belongs to.

I trained lightweight models using a duplicate-aware protocol. That matters because I found exact duplicate image content across the original train/test split. I corrected this by grouping identical image hashes so duplicates could not leak across splits.

The best clean baseline was MobileNetV3 Small:

- 97.92% clean accuracy
- 93.53% macro F1
- only 5.934 MB

So it looked accurate and lightweight.

## Attack: 35 Seconds

But when I tested adversarial attacks, the weakness became clear.

Under FGSM at eps=0.03, MobileNetV3 accuracy dropped from 97.92% to 18.06%.

Under PGD-20, the stronger attack, accuracy dropped to 0.29%.

That means the detector was almost completely broken under attack.

## Live Demo: 70 Seconds

Now I will show the default recovery case in the demo.

Use sample:

```text
05_allaple_a_pgd
```

Step 1: The standard detector sees the clean malware image and correctly predicts:

```text
Allaple.A
```

Step 2: I launch the PGD evasion attack.

Step 3: The standard detector is fooled and predicts:

```text
Malex.gen!J
```

This is the core security failure: the image still looks similar, but the model makes the wrong decision with high confidence.

Step 4: I activate MalGuard.

Step 5: The robust detector recovers the correct family:

```text
Allaple.A
```

## Solution And Evidence: 40 Seconds

MalGuard uses the same MobileNetV3 architecture, but adversarially trains it with PGD examples.

The result:

- FGSM accuracy improved from 18.06% to 82.87%.
- PGD-20 accuracy improved from 0.29% to 20.00%.
- Clean accuracy stayed high: 97.92% to 97.35%.
- Model size stayed unchanged at 5.934 MB.

The most distinctive part is the attention-stability finding. Grad-CAM shows that attacks can change what the model focuses on. On representative examples, adversarial training appears to make the model's attention more stable, so MalGuard is not only recovering the label; it is also giving behavioral evidence that the detector is more reliable.

## Closing: 20 Seconds

The contribution is not that adversarial robustness is solved. The contribution is showing, with a duplicate-aware protocol, that lightweight malware classifiers are highly vulnerable, PGD adversarial training can improve robustness without increasing model size, and the robust model may also stabilize attention under attack.

The main takeaway is:

```text
The attack breaks the standard detector; MalGuard recovers and presents attention-stability evidence.
```
