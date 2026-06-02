# CenTaD-MalGuard Grad-CAM Analysis Report

Generated at: `2026-06-01T13:17:29.793744+00:00`

## Methodology

This phase generated the explainability evidence package for CenTaD-MalGuard using the finalized duplicate-aware MalImg protocol and the official MobileNetV3 checkpoints. No baseline experiment was rerun and no model was retrained. FGSM and PGD examples were generated only for the curated visualization set so the final demo, poster, and report can show concrete attack and defense behavior.

Target layer: `model.features[-1] (final MobileNetV3 convolutional feature block)`. This is the final convolutional feature block before MobileNetV3 pooling/classification, so it provides class-discriminative spatial evidence while retaining enough spatial resolution for visual explanation.

Grad-CAM target class: the model's predicted class for each image variant. This explains the decision the model actually made, including wrong attacked predictions.

Attack settings for visual assets:

- FGSM epsilon: `0.03` in raw pixel space.
- PGD epsilon: `0.03`, alpha: `0.003`, steps: `20`, random start: true.
- Adversarial examples were generated against the clean MobileNetV3 baseline, then evaluated with both clean and adversarially trained MobileNetV3 for side-by-side explanation.

## Sample Selection Rationale

Selected samples: `16`.

The selection pipeline scans the official duplicate-aware test split deterministically and prioritizes four evidence categories: A, baseline correct -> attack succeeds -> defense recovers; B, baseline correct -> attack succeeds -> defense still fails; C, strong-performing malware families; D, weak-performing malware families.

Category tag counts:

- `D_weak_family`: 15
- `A_defense_recovers`: 12
- `C_strong_family`: 11
- `B_defense_still_fails`: 3

Selected sample metadata is stored in `results/gradcam/cenTaD_malguard_gradcam/metadata/selected_samples.csv`.

## Visual Findings

The generated panels support the core project narrative: attacks can alter classifier behavior and associated attention maps, while adversarial training often improves robustness and may make attention more stable on selected examples. The evidence is intentionally mixed: both recovery cases and failure cases are included so the final presentation does not overstate the defense.

Success-case panel:

![Success case](/Users/mingxuan/Documents/malware-robustness-project/results/gradcam/cenTaD_malguard_gradcam/figures/success_case_comparison_panel.png)

Failure-case panel:

![Failure case](/Users/mingxuan/Documents/malware-robustness-project/results/gradcam/cenTaD_malguard_gradcam/figures/failure_case_comparison_panel.png)

Family-level comparison panel:

![Family comparison](/Users/mingxuan/Documents/malware-robustness-project/results/gradcam/cenTaD_malguard_gradcam/figures/family_level_comparison_panel.png)

## Quantitative Findings

Attention stability was measured with lightweight, interpretable metrics:

- Top-20% heatmap IoU: overlap between the most activated heatmap regions before and after attack. Higher is more stable.
- Center-of-mass shift: normalized movement of the heatmap activation center. Lower is more stable.

| Model | Attack | Mean Top-20% IoU | Median Top-20% IoU | Mean Center Shift | Median Center Shift |
|---|---:|---:|---:|---:|---:|
| baseline | fgsm | 0.0905 | 0.0429 | 0.1159 | 0.1319 |
| defense | fgsm | 0.3364 | 0.3684 | 0.0822 | 0.0771 |
| baseline | pgd | 0.1355 | 0.0883 | 0.0782 | 0.0725 |
| defense | pgd | 0.3607 | 0.3847 | 0.0617 | 0.0442 |

![Attention stability summary](/Users/mingxuan/Documents/malware-robustness-project/results/gradcam/cenTaD_malguard_gradcam/figures/attention_stability_summary.png)

These metrics should be interpreted as supporting evidence, not proof of semantic understanding. Grad-CAM is sensitive to target class and model internals, and malware image regions are not directly human-semantic in the same way natural-image objects are.

## Limitations

- The Grad-CAM set is curated for explanation and demonstration, not a replacement for the official full-test robustness metrics.
- The visual attacks are generated against the clean MobileNetV3 baseline for side-by-side comparison; official defense robustness numbers remain the primary quantitative evidence.
- Grad-CAM can show attention shifts but cannot prove that highlighted regions correspond to causally meaningful malware semantics.
- Some malware families remain weak under PGD, consistent with the low PGD-20 macro F1 after adversarial training.
- CPU-only local generation may differ in runtime from the original Runpod environment, but it does not change the finalized experimental conclusions.

## Implications for Adversarial Robustness

The explainability package reinforces the final CenTaD-MalGuard narrative: attacks disrupt classifier behavior and attention; PGD adversarial training improves robustness and may stabilize attention on representative examples, while strong PGD attacks still expose family-balanced weaknesses. The adversarially trained MobileNetV3 should therefore be presented as a substantially stronger lightweight solution, not as a complete solution to adversarial malware classification.

## Reproducibility Notes

- Output directory: `results/gradcam/cenTaD_malguard_gradcam`
- Baseline checkpoint SHA-256: `75edeefca5591db13f3689c479e0e4494b6a8b954c54158f2343e7cfa6cffe55`
- Defense checkpoint SHA-256: `a27bbdfcc81b3d6b921668b78bd93d073ecafe00e19e120fb4daccb1b86bccac`
- Test CSV SHA-256: `edb37847cfd82a71766df71b8f51da8602c2f2bd74a78b49fc63605754f0cec9`
- Seed: `42`
