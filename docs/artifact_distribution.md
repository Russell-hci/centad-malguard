# Artifact Distribution Plan

## Purpose

This repository is designed to be GitHub-friendly. Source code, configs, reports, demo files, screenshots, and presentation materials should be committed. Large or sensitive artifacts should be distributed separately.

## Do Commit To GitHub

- Source code:
  - `attacks/`
  - `configs/`
  - `defenses/`
  - `evaluation/`
  - `models/`
  - `preprocessing/`
  - `scripts/`
  - `training/`
  - `utils/`
- Demo application:
  - `demo/centad-malguard/`
- Final reports:
  - `reports/final_research_report.md`
  - `reports/executive_summary.md`
  - `reports/gradcam_analysis_report.md`
- Final demo screenshots:
  - `reports/demo_previews/centad-malguard-final-desktop.png`
  - `reports/demo_previews/centad-malguard-final-laptop.png`
  - `reports/demo_previews/centad-malguard-final-mobile.png`
  - `reports/demo_previews/centad-malguard-final-recovery-stage.png`
- Presentation package:
  - `presentations/final_slide_deck.md`
  - `presentations/final_slide_deck.html`
  - `presentations/ssef_poster.md`
  - `presentations/ssef_poster.html`
  - judge scripts

## Do Not Commit To GitHub

The following should remain outside normal Git tracking:

- raw MalImg dataset files
- model checkpoints such as `.pth`
- full `results/` directories with checkpoints and large generated assets
- `runpod_artifacts/` archives
- local virtual environments
- Kaggle credentials or other secrets

The existing `.gitignore` already excludes these categories.

## Canonical Archive

The local canonical experiment archive is:

```text
runpod_artifacts/archives/experiment_artifacts_20260601T120030Z.tar.gz
```

SHA-256 checksum:

```text
01dce774175e0670133fb84e8b11e1b5436efc793666d4bc9200be611637e6bf
```

This archive should be used if a mentor, judge, or evaluator needs the full result bundle.

## Recommended Cloud Distribution

Use one of these approaches:

1. **GitHub Release**
   - Create a release named `final-ssef-artifacts`.
   - Upload the canonical archive and checksum file as release assets.
   - Keep the main repository lightweight.

2. **Google Drive / OneDrive**
   - Upload the canonical archive and checksum.
   - Add the share link to a private submission note.
   - Use this if GitHub release upload limits or network conditions are inconvenient.

3. **Local Backup**
   - Keep a copy of the archive on the presentation laptop.
   - Keep another copy on external storage.
   - Use this as the final backup for judging day.

## Public README Language

Recommended wording:

```text
Large experiment artifacts, checkpoints, and raw datasets are excluded from GitHub.
The canonical local archive is experiment_artifacts_20260601T120030Z.tar.gz.
It can be provided separately for verification.
```

## Final Recommendation

For SSEF/CenTaD, use GitHub for the polished code/report/demo package and a separate archive link for heavyweight artifacts. This keeps the public repository clean while preserving full reproducibility for evaluators who request raw artifacts.
