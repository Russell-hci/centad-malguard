# BinaryShield Slack Failure Root-Cause Analysis

Validation records inspected: `1329`
Executable-section preservation passes: `1327`
Executable-section preservation failures: `2`

## Classification Counts

- `out_of_file_slack_append_within_declared_executable_raw_extent`: `2`

## Root Cause

The two PEMML 5k+5k slack failures are classified as out-of-file slack mutations on malformed or truncated PE layouts. The mutation records target slack in later non-executable sections, but those raw offsets are beyond the original file length. Python bytearray slice assignment beyond EOF appends data at the file end. In these cases the original PE also declares an executable/code section raw extent past EOF, so appending bytes changes the byte range compared by the executable-section preservation validator.

This is a real transformer edge case, not a basis for lowering the acceptance gate. The appropriate remediation is to skip slack regions whose raw byte ranges are not fully present in the source file, preserving validation coverage accounting instead of silently accepting ambiguous mutations.

## Claim Boundary

This RCA is static structural evidence only. It does not prove malware functionality preservation and does not change the original PEMML 5k+5k acceptance status unless the affected validation is rerun under the patched transformer.

Failure cases CSV: `reports/binaryshield/pemml_5k_5k_sanitized_metrics/slack_failure_cases.csv`
