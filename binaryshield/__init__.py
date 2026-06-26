"""BinaryShield: PE-aware malware robustness auditing utilities."""

from binaryshield.byte_loader import ByteLoadResult, load_bytes
from binaryshield.mutation_regions import MutationRegion, find_mutation_regions
from binaryshield.pe_features import PEFeatureRecord, PEParseError, PESection, parse_pe
from binaryshield.robustness_card import RobustnessCard, write_robustness_card
from binaryshield.transformations import TransformationResult, append_overlay, mutate_slack_space
from binaryshield.validation import ValidationRecord, validate_transformation

__all__ = [
    "ByteLoadResult",
    "MutationRegion",
    "PEFeatureRecord",
    "PEParseError",
    "PESection",
    "RobustnessCard",
    "TransformationResult",
    "ValidationRecord",
    "append_overlay",
    "find_mutation_regions",
    "load_bytes",
    "mutate_slack_space",
    "parse_pe",
    "validate_transformation",
    "write_robustness_card",
]
