# Repository Audit

Project: **CenTaD-MalGuard / Malware Robustness Project**
Audit date: 2026-06-01
Scope: repository structure, documentation, canonical artifacts, reports, demo assets, and submission readiness.

## Executive Assessment

The repository contains the complete experimental and product evidence needed for final judging:

- duplicate-aware dataset protocol
- official MobileNetV3 and EfficientNet-B0 baselines
- official FGSM robustness evaluation
- official PGD robustness evaluation
- official MobileNetV3 PGD adversarial-training result
- Grad-CAM explainability evidence package
- polished CenTaD-MalGuard static demo application
- demo guide and preview screenshots

The remaining repository risk is not scientific completeness. The main risk is packaging clarity: a GitHub visitor must be able to distinguish source code, official results, large ignored artifacts, final reports, and demo files without reading the handover first.

## Current Directory Structure

| Path | Current Purpose | Audit Notes |
|---|---|---|
| `attacks/` | FGSM and PGD attack implementations/evaluators. | Clear and relevant. |
| `configs/` | YAML configs for baselines, attacks, and adversarial training. | Good reproducibility value. Official configs should be named in README. |
| `datasets/` | Raw, processed, and split data directories. | Raw data is intentionally ignored. Duplicate-aware split CSVs exist locally. |
| `defenses/` | PGD adversarial training implementation. | Clear. |
| `demo/centad-malguard/` | Static judge-facing demo app. | Strong final product asset. Should be highlighted in README. |
| `docs/` | Demo guide and final packaging docs. | Needs repository audit and final usage guidance, now addressed by this file. |
| `evaluation/` | Metrics, latency, confusion matrix, benchmark utilities. | Clear. |
| `explainability/` | Explainability package namespace. | Directory exists but appears lightly populated or empty in the shallow audit; actual Grad-CAM pipeline is in `scripts/generate_gradcam_assets.py`. |
| `manifests/` | Dataset/split/environment manifests. | Important, but currently gitignored by `.gitignore`. Clarify archival strategy. |
| `models/` | MobileNetV3 and EfficientNet-B0 adapters. | Clear. |
| `notebooks/` | Notebook workspace. | Appears unused in current final workflow. |
| `preprocessing/` | Dataset verification, loading, transforms, splitting. | Important for duplicate-aware protocol. |
| `project_docs/` | Original proposal/planning/reference documents. | Useful history, but not the best first-read material. |
| `reports/` | Grad-CAM report, final reports, demo screenshots. | Good final deliverable location. |
| `results/` | Baseline, attack, defense, Grad-CAM outputs. | Scientifically central but gitignored. Local availability is good; GitHub packaging must explain artifact access. |
| `runpod_artifacts/` | Timestamped result archives and checksums. | Important canonical bundle, but gitignored and too large for normal GitHub. |
| `scripts/` | Dataset download, setup, archiving, Grad-CAM generation. | Clear. |
| `training/` | Baseline training pipeline. | Clear. |
| `utils/` | Config, experiment metadata, reproducibility utilities. | Clear. |
| `venv/` | Local virtual environment. | Correctly ignored; should not be committed. |

## Canonical Artifacts Verified Locally

### Baselines

Official duplicate-aware baseline directories exist:

- `results/baseline_duplicate_aware/mobilenet_v3_small_20260601T100108Z/`
- `results/baseline_duplicate_aware/efficientnet_b0_20260601T100222Z/`

Expected files are present:

- `best_model.pth`
- `metrics.csv`
- `history.csv`
- `confusion_matrix.png`
- `experiment_metadata.json`
- `run.log`

### FGSM

Official FGSM results exist:

- `results/robustness/fgsm/fgsm_20260601T102828Z/fgsm_results.csv`
- `accuracy_vs_epsilon.png`
- `macro_f1_vs_epsilon.png`
- `sanity_check.json`
- `experiment_metadata.json`

FGSM validation artifacts exist:

- `results/robustness/fgsm_validation/fgsm_validation_20260601T104717Z/perturbation_stats.csv`
- `example_analysis.csv`
- `validation_metadata.json`

### PGD

Official PGD results exist:

- `results/robustness/pgd/pgd_20260601T105733Z/pgd_results.csv`
- `accuracy_by_pgd_setting.png`
- `macro_f1_by_pgd_setting.png`
- `asr_by_pgd_setting.png`
- `sanity_check.json`
- `experiment_metadata.json`

### Adversarial Training

Official MobileNetV3 PGD adversarial-training result exists:

- `results/defenses/adversarial_training/mobilenet_v3_small_pgd_adversarial_training_20260601T114339Z/`

Important files exist:

- `best_model.pth`
- `metrics.csv`
- `history.csv`
- `confusion_matrix.png`
- `experiment_metadata.json`
- `adversarial_training_report.md`
- `adversarial_training_comparison.csv`
- FGSM/PGD comparison figures and CSVs

There is also an earlier adversarial-training directory:

- `mobilenet_v3_small_pgd_adversarial_training_20260601T113855Z/`

Recommendation: mark `20260601T114339Z` as official in README and final report; mention the earlier directory only as a secondary/non-canonical run if needed.

### Grad-CAM / Explainability

Grad-CAM evidence package exists:

- `results/gradcam/cenTaD_malguard_gradcam/`
- `reports/gradcam_analysis_report.md`

Verified high-value outputs:

- `figures/success_case_comparison_panel.png`
- `figures/failure_case_comparison_panel.png`
- `figures/family_level_comparison_panel.png`
- `figures/attention_stability_summary.png`
- `metadata/selected_samples.csv`
- `metadata/predictions.csv`
- `metadata/attention_stability_metrics.csv`
- `metadata/attention_stability_summary.csv`
- `metadata/adversarial_training_comparison.csv`
- sample comparison panels for 16 selected examples

### Demo

Polished static demo exists:

- `demo/centad-malguard/index.html`
- `demo/centad-malguard/styles.css`
- `demo/centad-malguard/app.js`
- `docs/CENTAD_MALGUARD_DEMO_GUIDE.md`

Preview screenshots exist:

- `reports/demo_previews/centad-malguard-final-desktop.png`
- `reports/demo_previews/centad-malguard-final-laptop.png`
- `reports/demo_previews/centad-malguard-final-mobile.png`
- `reports/demo_previews/centad-malguard-final-recovery-stage.png`

## Documentation Gaps Found

| Gap | Severity | Recommendation |
|---|---:|---|
| No top-level `README.md` before packaging pass. | High | Create a GitHub-facing README with project overview, key results, demo, architecture, and reproducibility notes. |
| No final research report before packaging pass. | High | Create `reports/final_research_report.md`. |
| No judge scripts before packaging pass. | High | Create `presentations/judge_script_3min.md`, `judge_script_5min.md`, and `judge_script_10min.md`. |
| Canonical artifacts are present locally but many are ignored by `.gitignore`. | Medium | README must explain that large checkpoints/results are local or archived separately. Include exact canonical paths and archive checksum. |
| `PROJECT_HANDOVER_FOR_NEW_CODEX.md` is very useful but not visitor-facing. | Medium | Keep as internal handover; make README and final reports the public first-read docs. |
| `project_docs/` contains historical planning/proposal files with overlapping narratives. | Low | Keep for provenance, but do not make it the primary reading path. |
| Multiple demo preview screenshots reflect old intermediate UI states. | Low | Keep final screenshots and optionally archive or ignore earlier previews to reduce confusion. |

## Confusing Structure / Stale Files

1. `results/defenses/adversarial_training/` contains at least two timestamped MobileNetV3 adversarial-training runs. The official run is `20260601T114339Z`; the earlier `20260601T113855Z` should be treated as secondary.
2. `reports/demo_previews/` contains older screenshots from before the final polish pass. This is useful history, but final documentation should reference only the `centad-malguard-final-*` screenshots.
3. `explainability/` exists, while the actual Grad-CAM generator is `scripts/generate_gradcam_assets.py`. This is not harmful, but future readers may expect explainability code there.
4. `notebooks/` appears unused. It can remain, but README should not direct users there.
5. `PROJECT_HANDOVER_FOR_NEW_CODEX.md` says Grad-CAM had not yet been implemented at the time of handover. This is now stale relative to the completed project. The final report and README supersede it.

## Duplicate / Large Artifact Handling

The `.gitignore` intentionally excludes:

- `results/`
- `manifests/`
- `runpod_artifacts/`
- `datasets/raw/`
- model checkpoint files such as `*.pth`
- archives such as `*.tar.gz`

This is appropriate for GitHub repository hygiene, but it means a public GitHub repository may not include the full canonical experiment bundle unless artifacts are uploaded separately. Recommended packaging strategy:

1. Keep code, configs, reports, demo app, and final screenshots in Git.
2. Keep raw dataset and checkpoints out of Git.
3. Publish canonical experiment archive separately if required by judges/mentors.
4. Include archive path and checksum in README:

```text
runpod_artifacts/archives/experiment_artifacts_20260601T120030Z.tar.gz
SHA-256: 01dce774175e0670133fb84e8b11e1b5436efc793666d4bc9200be611637e6bf
```

## Reproducibility Information Present

The repository includes strong reproducibility foundations:

- pinned non-PyTorch dependencies in `requirements.txt`
- Runpod setup script
- dataset download script
- dataset and split manifests
- experiment metadata JSON files
- config-driven training/evaluation
- run logs
- canonical archive checksums
- explicit duplicate-aware protocol

Important reproducibility caveat:

- Strict CUDA determinism may require `CUBLAS_WORKSPACE_CONFIG=:4096:8` to be set before Python starts. This should be documented in the final report and README.

## Recommendations Before Final Submission

### Required

1. Use `README.md` as the top-level visitor entry point.
2. Use `reports/final_research_report.md` as the full scientific report.
3. Use `reports/executive_summary.md` for judges and mentors.
4. Use `presentations/` scripts for live judging.
5. Reference only final demo screenshots in README and presentation scripts.

### Strongly Recommended

1. Add an artifact-access note explaining which directories are gitignored and why.
2. Keep the final demo launch command in README:

```bash
python3 -m http.server 8765
```

3. Include the exact demo URL:

```text
http://localhost:8765/demo/centad-malguard/
```

4. Keep the official result table consistent across README, executive summary, and final report.

### Optional Cleanup

1. Move older demo preview screenshots into an archive folder or leave them unreferenced.
2. Add a short `docs/artifact_manifest.md` later if external artifact submission becomes necessary.
3. Consider moving Grad-CAM code under `explainability/` in a future cleanup, but this is not needed for final judging.

## Final Audit Verdict

The repository is scientifically complete and locally artifact-complete. Its main remaining need was final packaging: README, final report, executive summary, and presentation scripts. Once those documents are added, the repository is ready for final review, with the caveat that large results/checkpoints are intentionally excluded from normal Git tracking and should be provided separately if the judging process requires raw artifacts.
