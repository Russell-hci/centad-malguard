# BinaryShield Transformation And Validation Audit

This audit is derived from `binaryshield/mutation_regions.py`, `binaryshield/transformations.py`, `binaryshield/validation.py`, and the evaluation code.

## Append Regions

`find_mutation_regions()` always proposes an `append_overlay` region at `file_size`.

The append region is Level 2 only when the file size is greater than or equal to the maximum declared section raw end. In that case, appending bytes does not modify declared section raw data. If the file ends inside declared section raw data, append is marked Level 1 and `append_overlay(..., require_level2=True)` rejects it.

`append_overlay()` appends deterministic pseudo-random bytes of `payload_size` using `random.Random(seed)`. It does not alter existing bytes.

## Slack Regions

Slack starts at:

```text
section.raw_pointer + min(max(section.virtual_size, 0), section.raw_size)
```

Slack ends at:

```text
section.raw_pointer + section.raw_size
```

`find_mutation_regions()` emits `section_slack` regions for sections with positive slack. Slack in non-executable sections is Level 2. Slack in executable/code sections is Level 1 and is excluded by default.

`mutate_slack_space()` chooses the largest suitable slack region, writes deterministic pseudo-random bytes into up to `max_bytes`, and rejects files with no suitable non-executable slack region unless executable slack is explicitly allowed.

## Protected Areas

The code protects executable sections during Level 2 validation. It checks executable-section metadata and bytes:

- section name
- raw pointer
- raw size
- virtual address
- virtual size
- characteristics
- raw section bytes

Entry point equality is checked by comparing `address_of_entry_point` before and after transformation.

Section count is checked by comparing `number_of_sections`.

The code does not separately parse or compare imports, exports, resources, relocations, or certificate tables. These areas are protected only indirectly when they reside inside unchanged executable sections or outside the modified append/slack ranges. This should be stated as a limitation.

## Validation Levels

Source: `binaryshield/validation.py`

Level 0 means validation failed or required structural properties were not met.

Level 1 requires:

- original file parses as PE
- transformed file parses as PE
- SHA-256 hash changed
- entry point unchanged
- section count unchanged

Level 2 requires Level 1 plus:

- executable sections unchanged
- the expected transformation level is at least 2

Level 3 requires Level 2 plus:

- `sandbox_execution_status == "passed"`

No source path currently performs sandbox execution. Level 3 exists as a validation field and future extension point, not as current evidence.

## Evaluation Allowance

`allowed_for_evaluation` is true when the observed validation level is at least `min(result.validation_level_expected, 2)`.

Append and non-executable slack transformations are therefore accepted for current BinaryShield evaluation when they meet structural Level 2 checks.

## Claim Boundary

BinaryShield can claim that append-overlay and non-executable slack transformations preserve the checked PE structure and executable sections. It cannot claim universal behavior preservation, import/export/resource preservation, or semantic malware equivalence without additional approved analysis.
