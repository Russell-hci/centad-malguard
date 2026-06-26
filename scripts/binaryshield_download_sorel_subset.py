from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from binaryshield.pe_features import PEParseError, parse_pe  # noqa: E402
from binaryshield.safety import is_relative_to  # noqa: E402
from binaryshield.sorel import SOREL_BINARY_PREFIX, maybe_decompress_sorel_binary  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Download a bounded SOREL-20M disarmed malware subset into external storage.")
    parser.add_argument("--workspace", type=Path, required=True, help="External SOREL subset workspace.")
    parser.add_argument("--max-samples", type=int, default=100)
    parser.add_argument("--max-object-mb", type=float, default=2.0)
    parser.add_argument("--list-limit", type=int, default=2000)
    parser.add_argument("--prefix", default="09-DEC-2020/binaries/")
    parser.add_argument("--bucket", default="sorel-20m")
    parser.add_argument("--keep-compressed", action="store_true")
    parser.add_argument("--output-summary", type=Path, default=None)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    workspace = args.workspace.resolve()
    if is_relative_to(workspace, PROJECT_ROOT):
        raise ValueError(f"workspace must be outside the repository: {workspace}")
    compressed_dir = workspace / "compressed_binaries"
    binary_dir = workspace / "binaries"
    logs_dir = workspace / "logs"
    for path in [compressed_dir, binary_dir, logs_dir]:
        path.mkdir(parents=True, exist_ok=True)

    try:
        import boto3
        from botocore import UNSIGNED
        from botocore.config import Config
    except ImportError as exc:
        raise ImportError("boto3 is required; install it in Colab with `pip install boto3`") from exc

    s3 = boto3.client("s3", config=Config(signature_version=UNSIGNED, retries={"max_attempts": 3}))
    selected = _select_objects(
        s3,
        bucket=args.bucket,
        prefix=args.prefix,
        max_samples=args.max_samples,
        max_object_bytes=int(args.max_object_mb * 1024 * 1024),
        list_limit=args.list_limit,
    )
    rows: list[dict[str, object]] = []
    for obj in selected:
        key = str(obj["Key"])
        sha_name = Path(key).name
        compressed_path = compressed_dir / sha_name
        raw_path = binary_dir / sha_name
        data = s3.get_object(Bucket=args.bucket, Key=key)["Body"].read()
        decompressed, was_compressed = maybe_decompress_sorel_binary(data)
        if args.keep_compressed:
            compressed_path.write_bytes(data)
        raw_path.write_bytes(decompressed)
        parse_success = False
        parse_error = ""
        try:
            parse_pe(raw_path)
            parse_success = True
        except (PEParseError, OSError, ValueError) as exc:
            parse_error = str(exc)
        rows.append(
            {
                "s3_key": key,
                "sha256_name": sha_name,
                "compressed_size": len(data),
                "decompressed_size": len(decompressed),
                "was_zlib_compressed": was_compressed,
                "raw_path": str(raw_path),
                "parse_success": parse_success,
                "parse_error": parse_error,
            }
        )

    summary = {
        "workspace": str(workspace),
        "source": SOREL_BINARY_PREFIX,
        "selected_objects": len(selected),
        "downloaded_files": len(rows),
        "parse_success_count": sum(bool(row["parse_success"]) for row in rows),
        "parse_success_rate": (sum(bool(row["parse_success"]) for row in rows) / max(len(rows), 1)),
        "max_samples": args.max_samples,
        "max_object_mb": args.max_object_mb,
        "claim_boundary": (
            "This script downloads a bounded SOREL disarmed-malware subset into external storage. "
            "It does not copy samples into Git and does not validate behavior preservation."
        ),
    }
    summary_path = args.output_summary or logs_dir / "sorel_subset_download_summary.json"
    rows_path = logs_dir / "sorel_subset_download_rows.csv"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    with rows_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()) if rows else ["s3_key"])
        writer.writeheader()
        writer.writerows(rows)
    print(json.dumps(summary, indent=2))


def _select_objects(
    s3: object,
    *,
    bucket: str,
    prefix: str,
    max_samples: int,
    max_object_bytes: int,
    list_limit: int,
) -> list[dict[str, object]]:
    selected: list[dict[str, object]] = []
    token: str | None = None
    inspected = 0
    while len(selected) < max_samples and inspected < list_limit:
        kwargs = {"Bucket": bucket, "Prefix": prefix, "MaxKeys": min(1000, list_limit - inspected)}
        if token:
            kwargs["ContinuationToken"] = token
        response = s3.list_objects_v2(**kwargs)
        for obj in response.get("Contents", []):
            inspected += 1
            size = int(obj.get("Size", 0))
            if 4096 <= size <= max_object_bytes and not str(obj.get("Key", "")).endswith("/"):
                selected.append(obj)
                if len(selected) >= max_samples:
                    break
            if inspected >= list_limit:
                break
        token = response.get("NextContinuationToken")
        if not token:
            break
    return selected


if __name__ == "__main__":
    main()
