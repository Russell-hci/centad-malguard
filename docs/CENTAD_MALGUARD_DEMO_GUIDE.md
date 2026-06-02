# CenTaD-MalGuard Demo Guide

## Purpose

CenTaD-MalGuard is the judge-facing demonstration system for the completed malware robustness project. It packages the finalized research evidence into a local web application showing a simple cybersecurity story:

```text
standard detector works -> attack fools it -> MalGuard robust detector recovers
```

The demo shows:

- malware-family classification
- FGSM and PGD attack simulation with precomputed assets
- robust-model comparison using the adversarially trained MobileNetV3
- Grad-CAM explainability
- quantitative robustness-efficiency and attention-stability evidence

This demo does not retrain models, rerun baseline experiments, or generate new attacks. It reads the finalized asset package under:

```text
results/gradcam/cenTaD_malguard_gradcam/
```

## Implementation Choice

The demo is a static HTML/CSS/JavaScript application served from the repository root with Python's standard HTTP server.

This was chosen over Streamlit, Gradio, Flask, and a heavier Python backend because it maximizes:

- reliability: no additional web framework dependency
- simplicity: one local HTTP server command
- repeatability: all demo data comes from finalized CSV and image assets
- SSEF readiness: the demo can run offline once assets exist

## Prerequisites

Required files:

```text
demo/centad-malguard/index.html
demo/centad-malguard/styles.css
demo/centad-malguard/app.js
results/gradcam/cenTaD_malguard_gradcam/
reports/gradcam_analysis_report.md
```

No GPU is required. No model inference is performed by the app.

## Running The Demo

From the repository root:

```bash
python3 -m http.server 8765
```

Open:

```text
http://localhost:8765/demo/centad-malguard/
```

If `python3` is not available but the project virtual environment exists:

```bash
./venv/bin/python -m http.server 8765
```

## Demo Walkthrough

The first screen is designed to communicate the project in roughly 10 seconds:

- Problem: adversarial attacks can fool malware classifiers.
- Solution: CenTaD-MalGuard uses PGD adversarial training.
- Result: large robustness gains with minimal efficiency cost.

Use the primary button:

```text
Run 60-second attack demo
```

Then step through the guided stages:

1. Clean detection.
2. Attack launched.
3. Detector fooled.
4. MalGuard defense activated.
5. Correct prediction recovered.
6. Explanation and evidence.

The intended narrative is:

```text
clean prediction -> attack -> failure -> defense -> recovery -> attention stability evidence
```

## Recommended Judge Sequence

### 1. Strong Recovery Case

Sample:

```text
05_allaple_a_pgd
```

Use attack:

```text
PGD
```

Judge-facing explanation:

The standard detector correctly classifies the malware family on the clean image. PGD changes the standard detector prediction, but the MalGuard robust detector recovers the true family. This demonstrates the central solution: PGD adversarial training improves robustness while preserving a lightweight model.

### 2. Honest Failure Case

Sample:

```text
11_c2lop_p_pgd
```

Use attack:

```text
PGD
```

Judge-facing explanation:

This sample shows that the defense is not perfect. The standard detector fails under attack and the robust detector still fails. This supports the scientific limitation already observed in the official PGD-20 macro F1 result.

### 3. Grad-CAM Focus Case

Sample:

```text
01_dontovo_a_pgd
```

Use attack:

```text
PGD
```

Judge-facing explanation:

The Grad-CAM panel shows how attention shifts under attack and how the robust model can retain more stable decision regions. This is supporting evidence, not proof that the model semantically understands malware structure.

## Fallback Examples

If one example is visually unclear during judging, use:

```text
02_instantaccess_pgd
07_dialplatform_b_pgd
16_obfuscator_ad_pgd
```

Recommended use:

- `02_instantaccess_pgd`: recovery case
- `07_dialplatform_b_pgd`: recovery case with a weak-family tag
- `16_obfuscator_ad_pgd`: failure case

## Poster And Presentation Talking Points

Problem:

```text
Clean malware classifiers can be highly accurate but remain fragile under adversarial attacks.
```

Solution:

```text
Use PGD adversarial training to harden a lightweight MobileNetV3 malware classifier.
```

Evidence:

```text
FGSM eps=0.03 accuracy improves from 18.06% to 82.87%.
PGD-20 accuracy improves from 0.29% to 20.00%.
Clean accuracy remains high: 97.92% to 97.35%.
Model size remains unchanged: 5.934 MB.
```

Explainability:

```text
Grad-CAM panels show attack-related attention changes and provide supporting evidence that adversarial training may stabilize attention on representative examples.
```

Limitation:

```text
PGD-20 macro F1 remains low, so family-balanced adversarial robustness is improved but not solved.
```

## Troubleshooting

### Page loads but images are missing

Cause:

The HTTP server is probably not running from the repository root.

Fix:

Stop the server, `cd` to the repository root, and rerun:

```bash
python3 -m http.server 8765
```

### Browser blocks local file access

Cause:

Opening `index.html` directly as a file can block CSV loading.

Fix:

Use the HTTP server command instead of opening the file directly.

### Port 8765 is already in use

Use another port:

```bash
python3 -m http.server 8877
```

Then open:

```text
http://localhost:8877/demo/centad-malguard/
```

### App says data failed to load

Verify that these files exist:

```text
results/gradcam/cenTaD_malguard_gradcam/metadata/selected_samples.csv
results/gradcam/cenTaD_malguard_gradcam/metadata/predictions.csv
results/gradcam/cenTaD_malguard_gradcam/metadata/attention_stability_metrics.csv
results/gradcam/cenTaD_malguard_gradcam/metadata/adversarial_training_comparison.csv
```

### Do not run during demo

Do not run training, attack evaluation, or Grad-CAM generation during judging. The demo is designed to use precomputed assets.

## Next Packaging Step

Before final presentation:

1. Run the demo once from a clean browser session.
2. Confirm the default recovery case loads first.
3. Step through all six guided stages.
4. Confirm the defense limitation and attention focus examples load.
5. Keep screenshots of the hero, recovery stage, and evidence section as backup.
6. Prepare a 3 to 5 minute spoken sequence matching the guided app flow.
