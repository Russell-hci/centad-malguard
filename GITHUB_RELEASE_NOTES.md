# GitHub Release Notes: BinaryShield Public Final

BinaryShield is a PE-aware malware robustness audit framework for static malware detectors. It evaluates append-overlay and section-slack PE transformations, validates transformed files structurally, compares detector families, and exports sanitized robustness evidence.

## Included

- BinaryShield source code and command-line tools.
- Synthetic/fixture-based tests.
- Source-grounded audits and acceptance-gate documentation.
- Final paper, judge summary, verified metrics summary, robustness card, ClamAV blocker report, and slack RCA.
- Sanitized Dike and PEMML evidence summaries.
- Safe figures used by the final paper.

## Excluded

No raw malware, benign PE datasets, transformed binaries, archives, model checkpoints, ClamAV databases, virtual environments, private run folders, or unsafe local paths are included.

## Key Results

- MalGuard image-space MobileNetV3 collapsed from clean macro F1 `0.935261` to PGD-20 macro F1 `0.000706`.
- FB-MalAT reached aggregate 80/80 image-space robustness under FGSM, PGD-20, and PGD-50, while worst-family F1 remained `0.000000`.
- Dike accepted `byte_histogram_logistic` with append robust-min macro F1 `0.977220`, slack robust-min macro F1 `0.980882`, stability `1.000000`, ASR `0.000000`, and acceptance `PASS`.
- PEMML 5k+5k external subset achieved clean macro F1 `0.906000`, append robust macro F1 `0.894983`, slack robust macro F1 `0.889822`, append stability `0.993980`, slack stability `0.996986`.
- Paired statistical analysis found no significant append/slack degradation for the best detector under this protocol.
- ClamAV integration is implemented but metrics are not claimed because official signatures were unavailable.

## Claim Boundaries

BinaryShield is an audit framework, not an antivirus replacement. It does not prove malware behavior preservation, full PEMML validation, commercial antivirus superiority, or universal adversarial robustness.
