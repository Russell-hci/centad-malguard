# BinaryShield ClamAV Baseline Status

## Goal

ClamAV was selected as a reproducible traditional signature-based baseline so BinaryShield can compare learned detectors and a non-project detector under a shared, scan-only robustness protocol.

## Safety Controls

- No VirusTotal or commercial antivirus services were used.
- No malware samples were uploaded anywhere.
- ClamAV is invoked only through `clamscan --no-summary`.
- Destructive options such as `--remove`, `--move`, and `--copy` are not used.
- Raw PEMML samples and transformed files remain outside the Git repository.

## Latest FreshClam Check

- Timestamp: `2026-06-26T15:04:46Z`
- `clamscan --version`: `ClamAV 0.103.12`
- `freshclam --version`: `ClamAV 0.103.12`
- Official signature database status: blocked. `/var/lib/clamav` previously contained only `freshclam.dat`; no usable `main`, `daily`, or `bytecode` database was available.
- FreshClam result: official CDN 403/429 cooldown/rate-limit remains active.
- Next retry time reported by FreshClam: `2026-06-27 14:17:16`.

```text
Fri Jun 26 15:04:15 2026 -> ClamAV update process started at Fri Jun 26 15:04:15 2026
Fri Jun 26 15:04:15 2026 -> ^Your ClamAV installation is OUTDATED!
Fri Jun 26 15:04:15 2026 -> ^Local version: 0.103.12 Recommended version: 1.0.9
Fri Jun 26 15:04:15 2026 -> DON'T PANIC! Read https://docs.clamav.net/manual/Installing.html
Fri Jun 26 15:04:15 2026 -> ^FreshClam previously received error code 429 or 403 from the ClamAV Content Delivery Network (CDN).
Fri Jun 26 15:04:15 2026 -> This means that you have been rate limited or blocked by the CDN.
Fri Jun 26 15:04:15 2026 ->  1. Verify that you're running a supported ClamAV version.
Fri Jun 26 15:04:15 2026 ->     See https://docs.clamav.net/faq/faq-eol.html for details.
Fri Jun 26 15:04:15 2026 ->  2. Run FreshClam no more than once an hour to check for updates.
Fri Jun 26 15:04:15 2026 ->     FreshClam should check DNS first to see if an update is needed.
Fri Jun 26 15:04:15 2026 ->  3. If you have more than 10 hosts on your network attempting to download,
Fri Jun 26 15:04:15 2026 ->     it is recommended that you set up a private mirror on your network using
Fri Jun 26 15:04:15 2026 ->     cvdupdate (https://pypi.org/project/cvdupdate/) to save bandwidth on the
Fri Jun 26 15:04:15 2026 ->     CDN and your own network.
Fri Jun 26 15:04:15 2026 ->  4. Please do not open a ticket asking for an exemption from the rate limit,
Fri Jun 26 15:04:15 2026 ->     it will not be granted.
Fri Jun 26 15:04:15 2026 -> ^You are still on cool-down until after: 2026-06-27 14:17:16
```

## Outcome

The ClamAV baseline script exists as `scripts/binaryshield_clamav_baseline.py`, but PEMML 5k+5k ClamAV metrics were not generated because no official signature database is available. Running ClamAV without signatures would produce misleading coverage and detection metrics, so the baseline remains objectively blocked rather than fabricated.

## Exact Command Template After Signatures Are Available

```bash
cd /path/to/binaryshield-repo
source /tmp/binaryshield_venv/bin/activate
freshclam
python3 scripts/binaryshield_clamav_baseline.py \
  --manifest /path/to/manifests/pemml_5k_5k_manifest.csv \
  --dataset-root /path/to/pemml \
  --output-dir reports/binaryshield/clamav_pemml_5k_5k_sanitized_metrics \
  --split test \
  --append-predictions /path/to/runs/pemml_5k_5k/results/byte_histogram_logistic_append_eval/predictions_byte_histogram_logistic_append_overlay.csv \
  --slack-predictions /path/to/runs/pemml_5k_5k/results/byte_histogram_logistic_slack_eval/predictions_byte_histogram_logistic_section_slack.csv \
  --require-db
```

## Interpretation Boundary

This baseline is intended to show that BinaryShield can audit ML detectors and a traditional signature scanner under a shared static transformation protocol. It is not a claim that BinaryShield beats commercial antivirus.
