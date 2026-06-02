# Final Solution Review

Project: **CenTaD-MalGuard**
Review date: 2026-06-02
Purpose: final check of innovation, uniqueness, effectiveness, and submission readiness.

## Verdict

CenTaD-MalGuard is ready to present as a concrete cybersecurity solution rather than only a research dashboard. The project now communicates a clear problem, a specific defense, and quantitative proof:

```text
Problem: adversarial attacks can fool malware classifiers.
Solution: PGD-adversarially-trained MobileNetV3.
Evidence: large robustness gains with minimal efficiency cost.
```

## Innovation

The project is innovative because it evaluates malware image classification under adversarial conditions and packages the result as a practical demonstration system. The important distinction is that the project does not optimize only clean accuracy. It asks whether a lightweight classifier remains useful when actively attacked.

Key innovation points:

- duplicate-aware split construction using image-content SHA-256 grouping
- attack-aware evaluation with FGSM, PGD-10, PGD-20, ASR, macro F1, and efficiency metrics
- PGD adversarial training applied to a lightweight MobileNetV3 detector without increasing model size
- Grad-CAM evidence package connecting prediction failure to changes in model attention
- final static demo that shows classify, attack, defend, explain, and quantify in one judge-facing workflow

## Uniqueness

The unique value is the complete integration. Many projects show clean malware classification, and many adversarial ML projects report attack results. This project connects the full chain:

1. Correct the evaluation protocol.
2. Establish lightweight clean baselines.
3. Demonstrate adversarial vulnerability.
4. Train a robust lightweight model.
5. Explain behavior with Grad-CAM.
6. Present the result as a usable cybersecurity demonstration.

This gives judges a complete story instead of isolated experiments.

## Effectiveness

The solution is effective within the evaluated scope.

| Metric | Standard MobileNetV3 | MalGuard Robust MobileNetV3 | Result |
|---|---:|---:|---|
| Clean Accuracy | 97.92% | 97.35% | nearly preserved |
| FGSM Accuracy, eps=0.03 | 18.06% | 82.87% | large improvement |
| PGD-20 Accuracy | 0.29% | 20.00% | large improvement |
| Model Size | 5.934 MB | 5.934 MB | unchanged |
| Parameters | 1,543,481 | 1,543,481 | unchanged |

The defense is strongest against FGSM and improves PGD substantially, but PGD-20 macro F1 remains low. The project should therefore claim substantial robustness improvement, not complete adversarial security.

## Product Check

The demo is judge-ready because it:

- starts with the strongest recovery example, `05_allaple_a_pgd`
- shows the standard detector succeeding on the clean sample
- shows PGD fooling the standard detector
- shows MalGuard recovering the correct family
- explains Grad-CAM in plain language
- quantifies the official robustness-efficiency result

The demo should be rehearsed on the final judging laptop using both the 3-minute and 5-minute scripts.

## Remaining Non-Blocking Gaps

- Create a formal slide deck file only if the judging process specifically requires PowerPoint; Markdown and browser-printable HTML versions already exist.
- Decide whether the canonical experiment archive should be distributed by GitHub Release, Google Drive, or local backup.
- Run a final live rehearsal on the actual judging machine.

## Final Positioning

Recommended one-sentence pitch:

> CenTaD-MalGuard shows that malware classifiers can be highly accurate but fragile under attack, and that PGD adversarial training can make a lightweight detector substantially more robust without increasing model size.
