# BinaryShield Autonomous Execution Summary

Generated: `2026-06-26T10:43:27Z`

## Scope

This continuation used the CPU-only RunPod endpoint `213.173.105.96:40493` with persistent storage mounted at `/workspace`. Per user direction, validation stopped after the 5k+5k PEMML subset. No 10k+10k and no full PEMML validation were run.

## Completed Work

- Verified the existing extracted PEMML dataset on `/workspace`.
- Confirmed PEMML metadata: `201549` source CSV rows, `id` sample identifiers, and `list` label values mapped into `malware`/`benign`.
- Confirmed existing 1k+1k and 5k+5k manifests.
- Completed the 1k+1k smoke validation.
- Completed the 5k+5k balanced 10,000-sample external subset validation.
- Generated sanitized evidence tables for both stages.
- Stopped after 5k+5k as requested.

## Main Result

BinaryShield was externally evaluated on a reproducible balanced PEMML subset of 10,000 raw PE files: 5,000 malware and 5,000 benign samples.

The candidate detector was `byte_histogram_logistic`.

## 5k+5k Metrics

- Clean macro F1: `0.906000`.
- Append robust macro F1: `0.894983`.
- Slack robust macro F1: `0.889822`.
- Append prediction stability: `0.993980`.
- Slack prediction stability: `0.996986`.
- Append attack success rate: `0.004474`.
- Slack attack success rate: `0.001691`.
- Candidate acceptance status: `FAIL`.
- Runtime: `6h 22m 40s`.
- Run storage: `12G`.

Failed 5k gate:

- `Slack executable sections unchanged`: observed `0.9984951091045899`, target `>= 1.00`

## Generated Safe Reports

- `reports/binaryshield_pemml_validation_results.md`.
- `reports/binaryshield_runpod_external_validation_results.md`.
- `reports/binaryshield_autonomous_execution_summary.md`.
- `reports/binaryshield/pemml_1k_1k_sanitized_metrics/`.
- `reports/binaryshield/pemml_5k_5k_sanitized_metrics/`.
- `reports/binaryshield/pemml_1k_1k_manifest_summary.json`.
- `reports/binaryshield/pemml_5k_5k_manifest_summary.json`.

## Storage And Safety

- PEMML dataset storage: `118G` under `/path/to/pemml`.
- 1k+1k run storage: `2.5G` under `/path/to/runs/pemml_1k_1k`.
- 5k+5k run storage: `12G` under `/path/to/runs/pemml_5k_5k`.
- `/workspace` free space after run: about `510T` reported by RunPod network volume.
- Raw PE files, transformed binaries, run artifacts, detector artifacts, and archives were not copied into the repository.

## Limitations

- The result is a balanced 10,000-sample external subset validation, not full PEMML validation.
- The 1k+1k result is a smoke test only.
- No 10k+10k or full PEMML run was performed.
- The 5k+5k candidate acceptance status is `FAIL` because of the strict slack executable-section unchanged gate.
- No dynamic malware execution or Level 3 behavioral validation was performed.

## Next Authorized Command

Only if the user later explicitly authorizes a larger run, start from the already built manifest and run the next stage manually. Under the current instruction, the correct next action is review and commit/sync of safe reports only.
