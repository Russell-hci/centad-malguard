#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, precision_recall_fscore_support

INFECTED_MARKERS = (" FOUND",)
OK_MARKERS = (" OK",)
ERROR_MARKERS = (" ERROR", " Can't open file or directory")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a safe scan-only ClamAV baseline over a BinaryShield manifest.")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--dataset-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--split", default="test")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--clamscan", default="clamscan")
    parser.add_argument("--append-predictions", type=Path, default=None, help="Optional BinaryShield predictions CSV containing sample_id and transformed_path for append files.")
    parser.add_argument("--slack-predictions", type=Path, default=None, help="Optional BinaryShield predictions CSV containing sample_id and transformed_path for slack files.")
    parser.add_argument("--require-db", action="store_true", help="Fail if no official ClamAV signature database is installed.")
    return parser.parse_args()


def has_signature_database(db_dir: Path = Path("/var/lib/clamav")) -> bool:
    return any((db_dir / name).exists() for name in ("main.cvd", "daily.cvd", "bytecode.cvd", "main.cld", "daily.cld", "bytecode.cld"))


def parse_clamscan_output(output: str) -> str:
    for line in output.splitlines():
        if any(marker in line for marker in INFECTED_MARKERS):
            return "malware"
    for line in output.splitlines():
        if any(marker in line for marker in ERROR_MARKERS):
            return "error"
    for line in output.splitlines():
        if any(marker in line for marker in OK_MARKERS):
            return "benign"
    return "error"


def resolve_path(dataset_root: Path, value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else dataset_root / path


def run_scan(clamscan: str, path: Path, timeout: float) -> tuple[str, int, str]:
    if not path.exists():
        return "error", 127, "missing file"
    try:
        result = subprocess.run(
            [clamscan, "--no-summary", str(path)],
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return "timeout", 124, "timeout"
    output = (result.stdout or "") + (result.stderr or "")
    return parse_clamscan_output(output), int(result.returncode), output.strip()[:500]


def metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    scanned = [row for row in rows if row["prediction"] in {"malware", "benign"}]
    labels = [row["label"] for row in scanned]
    preds = [row["prediction"] for row in scanned]
    if not scanned:
        return {
            "total": len(rows),
            "scanned": 0,
            "coverage": 0.0,
            "errors_or_timeouts": len(rows),
            "accuracy": None,
            "macro_f1": None,
            "malware_recall": None,
            "benign_false_positive_rate": None,
            "benign_true_negative_rate": None,
        }
    precision, recall, f1, support = precision_recall_fscore_support(
        labels,
        preds,
        labels=["benign", "malware"],
        zero_division=0,
    )
    benign_support = int(support[0])
    malware_support = int(support[1])
    benign_false_positives = sum(1 for label, pred in zip(labels, preds) if label == "benign" and pred == "malware")
    benign_true_negatives = sum(1 for label, pred in zip(labels, preds) if label == "benign" and pred == "benign")
    return {
        "total": len(rows),
        "scanned": len(scanned),
        "coverage": len(scanned) / len(rows) if rows else 0.0,
        "errors_or_timeouts": len(rows) - len(scanned),
        "accuracy": accuracy_score(labels, preds),
        "macro_f1": f1_score(labels, preds, average="macro", zero_division=0),
        "malware_recall": float(recall[1]) if malware_support else None,
        "benign_false_positive_rate": benign_false_positives / benign_support if benign_support else None,
        "benign_true_negative_rate": benign_true_negatives / benign_support if benign_support else None,
        "benign_precision": float(precision[0]),
        "malware_precision": float(precision[1]),
        "benign_f1": float(f1[0]),
        "malware_f1": float(f1[1]),
    }


def prediction_path_map(path: Path | None) -> dict[str, str]:
    if path is None:
        return {}
    frame = pd.read_csv(path)
    if "sample_id" not in frame.columns or "transformed_path" not in frame.columns:
        raise ValueError(f"{path} must contain sample_id and transformed_path columns")
    return {str(row.sample_id): str(row.transformed_path) for row in frame.itertuples(index=False)}


def scan_named_set(name: str, manifest: pd.DataFrame, path_map: dict[str, str], dataset_root: Path, clamscan: str, timeout: float) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in manifest.itertuples(index=False):
        sample_id = str(item.sample_id)
        if name == "clean":
            scan_path = resolve_path(dataset_root, str(item.path))
        else:
            transformed = path_map.get(sample_id)
            if not transformed:
                rows.append({"sample_id": sample_id, "label": item.label, "set": name, "prediction": "error", "returncode": 127, "error": "missing transformed path"})
                continue
            scan_path = Path(transformed)
        prediction, returncode, message = run_scan(clamscan, scan_path, timeout)
        rows.append({"sample_id": sample_id, "label": item.label, "set": name, "prediction": prediction, "returncode": returncode, "error": message if prediction in {"error", "timeout"} else ""})
    return rows


def stability_and_attack(clean_rows: list[dict[str, Any]], transformed_rows: list[dict[str, Any]]) -> dict[str, Any]:
    clean = {row["sample_id"]: row for row in clean_rows if row["prediction"] in {"malware", "benign"}}
    transformed = {row["sample_id"]: row for row in transformed_rows if row["prediction"] in {"malware", "benign"}}
    paired_ids = sorted(set(clean) & set(transformed))
    if not paired_ids:
        return {"paired_scanned": 0, "prediction_stability": None, "attack_success_rate": None, "attack_successes": 0}
    stable = sum(clean[sid]["prediction"] == transformed[sid]["prediction"] for sid in paired_ids)
    attack_denominator = 0
    attack_successes = 0
    for sid in paired_ids:
        label = clean[sid]["label"]
        if label == "malware" and clean[sid]["prediction"] == "malware":
            attack_denominator += 1
            if transformed[sid]["prediction"] == "benign":
                attack_successes += 1
    return {
        "paired_scanned": len(paired_ids),
        "prediction_stability": stable / len(paired_ids),
        "attack_success_rate": attack_successes / attack_denominator if attack_denominator else None,
        "attack_successes": attack_successes,
    }


def write_outputs(output_dir: Path, rows_by_set: dict[str, list[dict[str, Any]]]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    all_rows = [row for rows in rows_by_set.values() for row in rows]
    with (output_dir / "clamav_predictions.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["sample_id", "label", "set", "prediction", "returncode", "error"], extrasaction="ignore")
        writer.writeheader()
        writer.writerows(all_rows)
    summary = {name: metrics(rows) for name, rows in rows_by_set.items()}
    if "clean" in rows_by_set:
        for transformed_name in ("append", "slack"):
            if transformed_name in rows_by_set:
                summary[f"clean_to_{transformed_name}"] = stability_and_attack(rows_by_set["clean"], rows_by_set[transformed_name])
    (output_dir / "clamav_metrics.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")


def main() -> None:
    args = parse_args()
    clamscan = shutil.which(args.clamscan) or args.clamscan
    if not Path(clamscan).exists() and shutil.which(clamscan) is None:
        raise SystemExit(f"clamscan executable not found: {args.clamscan}")
    db_available = has_signature_database()
    if args.require_db and not db_available:
        raise SystemExit("No ClamAV signature database found under /var/lib/clamav; refusing to scan with --require-db")

    manifest = pd.read_csv(args.manifest)
    if args.split and "split" in manifest.columns:
        manifest = manifest[manifest["split"].astype(str) == args.split]
    if args.limit is not None:
        manifest = manifest.head(args.limit)
    rows_by_set = {
        "clean": scan_named_set("clean", manifest, {}, args.dataset_root, clamscan, args.timeout),
    }
    append_map = prediction_path_map(args.append_predictions)
    slack_map = prediction_path_map(args.slack_predictions)
    if append_map:
        rows_by_set["append"] = scan_named_set("append", manifest, append_map, args.dataset_root, clamscan, args.timeout)
    if slack_map:
        rows_by_set["slack"] = scan_named_set("slack", manifest, slack_map, args.dataset_root, clamscan, args.timeout)
    write_outputs(args.output_dir, rows_by_set)
    print(json.dumps({"output_dir": str(args.output_dir), "db_available": db_available, "sets": sorted(rows_by_set)}, indent=2))


if __name__ == "__main__":
    main()
