# Security And Ethics

BinaryShield is intended for defensive evaluation and malware-robustness research.

## Repository Safety

This public repository does not include malware samples, transformed binaries, malware archives, ClamAV databases, model checkpoints, or private dataset paths. Reports contain sanitized aggregate metrics and anonymized identifiers only.

## Malware Handling Rules

- Do not execute malware on a normal workstation.
- Use isolated, purpose-built malware-analysis environments for any dynamic analysis.
- Keep raw PE datasets outside this repository.
- Remove execute permissions from samples when practical.
- Do not commit raw PE files, transformed binaries, archives, checkpoints, or local run outputs.
- Do not upload malware to third-party scanners unless you understand their sharing and redistribution policies.

## ClamAV Integration

The ClamAV baseline integration is scan-only and non-destructive. It must not be run with `--remove`, `--move`, `--copy`, quarantine options, or any workflow that modifies original samples. In this release, ClamAV metrics are not claimed because official signatures were unavailable during the final attempt.

## Research Claim Boundaries

BinaryShield performs static structural validation. It does not prove malware behavior preservation, universal malware robustness, commercial antivirus superiority, or sandbox-level semantic equivalence.
