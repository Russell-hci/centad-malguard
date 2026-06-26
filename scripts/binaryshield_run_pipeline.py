from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from binaryshield.datasets import iter_split, load_manifest  # noqa: E402
from binaryshield.safety import assert_safe_transformation_output  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a BinaryShield manifest-to-report pipeline.")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--root-dir", type=Path, default=None)
    parser.add_argument("--output-dir", type=Path, default=Path("results/binaryshield/pipeline"))
    parser.add_argument("--report-dir", type=Path, default=Path("reports/binaryshield/pipeline"))
    parser.add_argument("--target", choices=["label", "family"], default="label")
    parser.add_argument(
        "--model-type",
        choices=[
            "centroid",
            "sklearn_random_forest",
            "byte_histogram_centroid",
            "byte_histogram_calibrated",
            "byte_histogram_logistic",
            "hybrid_centroid",
        ],
        default=None,
        help="Legacy single model selector. Use --model-types for multi-detector runs.",
    )
    parser.add_argument(
        "--model-types",
        nargs="+",
        choices=[
            "centroid",
            "sklearn_random_forest",
            "byte_histogram_centroid",
            "byte_histogram_calibrated",
            "byte_histogram_logistic",
            "hybrid_centroid",
        ],
        default=None,
        help="Detector families to train/evaluate in one pipeline run.",
    )
    parser.add_argument("--candidate-model-type", default=None, help="Model type to treat as the BinaryShield candidate.")
    parser.add_argument("--strongest-n", type=int, default=5)
    parser.add_argument("--skip-strongest-n", action="store_true", help="Skip strongest-of-N evaluation for faster real-data passes.")
    parser.add_argument("--skip-slack", action="store_true")
    parser.add_argument("--max-bytes", type=int, default=None, help="Optional byte cap for byte-based centroid models.")
    parser.add_argument(
        "--allow-repo-output",
        action="store_true",
        help="Allow transformed outputs under the repository. Use only for controlled non-malware fixtures.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    model_types = args.model_types or ([args.model_type] if args.model_type else ["centroid"])
    samples = list(iter_split(load_manifest(args.manifest, args.root_dir), "test"))
    assert_safe_transformation_output(
        samples=samples,
        output_dir=args.output_dir,
        project_root=PROJECT_ROOT,
        allow_repo_output=args.allow_repo_output,
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    args.report_dir.mkdir(parents=True, exist_ok=True)

    validation_dir = args.report_dir / "manifest_validation"
    transfer_dir = args.output_dir / "transfer_eval"
    summary_dir = args.report_dir / "multi_detector"
    acceptance_dir = args.report_dir / "acceptance"

    run(
        [
            "scripts/binaryshield_validate_manifest.py",
            "--manifest",
            args.manifest,
            "--output-dir",
            validation_dir,
            *root_args(args.root_dir),
        ]
    )
    model_paths: list[Path] = []
    per_model_dirs: dict[str, dict[str, str | None]] = {}
    for model_type in model_types:
        baseline_dir = args.output_dir / f"{model_type}_baseline"
        append_dir = args.output_dir / f"{model_type}_append_eval"
        slack_dir = args.output_dir / f"{model_type}_slack_eval"
        strongest_dir = args.output_dir / f"{model_type}_strongest_n"
        run(
            [
                "scripts/binaryshield_train_pe_baseline.py",
                "--manifest",
                args.manifest,
                "--output-dir",
                baseline_dir,
                "--target",
                args.target,
                "--model-type",
                model_type,
                *(["--max-bytes", args.max_bytes] if args.max_bytes is not None else []),
                *root_args(args.root_dir),
            ]
        )
        model_path = _model_path_for(model_type, baseline_dir)
        model_paths.append(model_path)
        run_eval(args.manifest, args.root_dir, args.target, model_path, "append_overlay", append_dir, allow_repo_output=args.allow_repo_output)
        append_validation_summary_dir = append_dir / "validation_summary"
        run_validation_summary(
            args.manifest,
            args.root_dir,
            append_dir / "validation" / "append_overlay",
            append_validation_summary_dir,
            expected_existing_records=True,
        )
        append_card_summary_dir = append_dir / "card_summary"
        run_card_summary(
            args.manifest,
            args.root_dir,
            append_dir / "cards" / "append_overlay",
            append_card_summary_dir,
            expected_existing_records=True,
        )
        slack_metrics: Path | None = None
        slack_validation_summary_dir: Path | None = None
        slack_card_summary_dir: Path | None = None
        if not args.skip_slack:
            run_eval(
                args.manifest,
                args.root_dir,
                args.target,
                model_path,
                "section_slack",
                slack_dir,
                allow_failure=True,
                allow_repo_output=args.allow_repo_output,
            )
            slack_metrics = _first_metrics(slack_dir, "section_slack")
            if (slack_dir / "validation" / "section_slack").exists():
                slack_validation_summary_dir = slack_dir / "validation_summary"
                run_validation_summary(
                    args.manifest,
                    args.root_dir,
                    slack_dir / "validation" / "section_slack",
                    slack_validation_summary_dir,
                    expected_existing_records=True,
                )
            if (slack_dir / "cards" / "section_slack").exists():
                slack_card_summary_dir = slack_dir / "card_summary"
                run_card_summary(
                    args.manifest,
                    args.root_dir,
                    slack_dir / "cards" / "section_slack",
                    slack_card_summary_dir,
                    expected_existing_records=True,
                )
        if not args.skip_strongest_n:
            run(
                [
                    "scripts/binaryshield_eval_strongest_n.py",
                    "--manifest",
                    args.manifest,
                    "--model",
                    model_path,
                    "--target",
                    args.target,
                    "--transformation",
                    "append_overlay",
                    "--n",
                    str(args.strongest_n),
                    "--output-dir",
                    strongest_dir,
                    *(["--allow-repo-output"] if args.allow_repo_output else []),
                    *root_args(args.root_dir),
                ]
            )
        per_model_dirs[model_type] = {
            "baseline_dir": str(baseline_dir),
            "model_path": str(model_path),
            "append_dir": str(append_dir),
            "append_metrics": str(_first_metrics(append_dir, "append_overlay") or ""),
            "append_validation_summary": str(append_validation_summary_dir / "transformation_validation_summary.json"),
            "append_card_summary": str(append_card_summary_dir / "robustness_card_summary.json"),
            "slack_dir": str(slack_dir) if not args.skip_slack else None,
            "slack_metrics": str(slack_metrics) if slack_metrics else None,
            "slack_validation_summary": str(slack_validation_summary_dir / "transformation_validation_summary.json") if slack_validation_summary_dir else None,
            "slack_card_summary": str(slack_card_summary_dir / "robustness_card_summary.json") if slack_card_summary_dir else None,
            "strongest_dir": str(strongest_dir) if not args.skip_strongest_n else None,
        }

    run(
        [
            "scripts/binaryshield_eval_transfer.py",
            "--manifest",
            args.manifest,
            "--models",
            *model_paths,
            "--target",
            args.target,
            "--transformations",
            "append_overlay",
            *(["section_slack"] if not args.skip_slack else []),
            "--output-dir",
            transfer_dir,
            *(["--allow-repo-output"] if args.allow_repo_output else []),
            *root_args(args.root_dir),
        ]
    )
    candidate_model_type = args.candidate_model_type or model_types[-1]
    candidate_append = _first_metrics(args.output_dir / f"{candidate_model_type}_append_eval", "append_overlay")
    if candidate_append is None:
        raise FileNotFoundError(f"missing append metrics for candidate model type: {candidate_model_type}")
    candidate_append_validation = (
        args.output_dir
        / f"{candidate_model_type}_append_eval"
        / "validation_summary"
        / "transformation_validation_summary.json"
    )
    candidate_slack_validation = (
        args.output_dir
        / f"{candidate_model_type}_slack_eval"
        / "validation_summary"
        / "transformation_validation_summary.json"
    )
    candidate_append_cards = (
        args.output_dir
        / f"{candidate_model_type}_append_eval"
        / "card_summary"
        / "robustness_card_summary.json"
    )
    candidate_slack_cards = (
        args.output_dir
        / f"{candidate_model_type}_slack_eval"
        / "card_summary"
        / "robustness_card_summary.json"
    )
    run(
        [
            "scripts/binaryshield_multi_detector_report.py",
            "--transfer-matrix",
            transfer_dir / "transfer_matrix.json",
            "--candidate-detector",
            _detector_name_for_model_type(candidate_model_type),
            "--output-dir",
            summary_dir,
        ]
    )
    run(
        [
            "scripts/binaryshield_acceptance_report.py",
            "--validation-summary",
            validation_dir / "validation_summary.json",
            "--append-metrics",
            candidate_append,
            "--append-validation-summary",
            candidate_append_validation,
            "--append-card-summary",
            candidate_append_cards,
            "--transfer-matrix",
            transfer_dir / "transfer_matrix.json",
            "--multi-detector-summary",
            summary_dir / "multi_detector_summary.json",
            "--output-dir",
            acceptance_dir,
            *(
                ["--slack-metrics", candidate_slack]
                if (candidate_slack := _first_metrics(args.output_dir / f"{candidate_model_type}_slack_eval", "section_slack")) is not None
                else []
            ),
            *(["--slack-validation-summary", candidate_slack_validation] if candidate_slack_validation.exists() else []),
            *(["--slack-card-summary", candidate_slack_cards] if candidate_slack_cards.exists() else []),
        ]
    )
    summary = {
        "validation_dir": str(validation_dir),
        "model_types": model_types,
        "candidate_model_type": candidate_model_type,
        "per_model": per_model_dirs,
        "transfer_dir": str(transfer_dir),
        "multi_detector_summary_dir": str(summary_dir),
        "acceptance_dir": str(acceptance_dir),
        "claim_boundary": "Pipeline artifacts are valid only for the supplied manifest and transformation settings.",
    }
    (args.report_dir / "pipeline_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


def root_args(root_dir: Path | None) -> list[object]:
    return ["--root-dir", root_dir] if root_dir is not None else []


def run_eval(
    manifest: Path,
    root_dir: Path | None,
    target: str,
    model_path: Path,
    transformation: str,
    output_dir: Path,
    allow_failure: bool = False,
    allow_repo_output: bool = False,
) -> None:
    command = [
        "scripts/binaryshield_eval_pe_baseline.py",
        "--manifest",
        manifest,
        "--model",
        model_path,
        "--target",
        target,
        "--transformation",
        transformation,
        "--output-dir",
        output_dir,
        *(["--allow-repo-output"] if allow_repo_output else []),
        *root_args(root_dir),
    ]
    run(command, allow_failure=allow_failure)


def run_validation_summary(
    manifest: Path,
    root_dir: Path | None,
    validation_dir: Path,
    output_dir: Path,
    *,
    expected_existing_records: bool = False,
) -> None:
    run(
        [
            "scripts/binaryshield_summarize_transform_validations.py",
            "--validation-dir",
            validation_dir,
            "--output-dir",
            output_dir,
            "--manifest",
            manifest,
            *(["--expected-existing-records"] if expected_existing_records else []),
            *root_args(root_dir),
        ]
    )


def run_card_summary(
    manifest: Path,
    root_dir: Path | None,
    cards_dir: Path,
    output_dir: Path,
    *,
    expected_existing_records: bool = False,
) -> None:
    run(
        [
            "scripts/binaryshield_summarize_robustness_cards.py",
            "--cards-dir",
            cards_dir,
            "--output-dir",
            output_dir,
            "--manifest",
            manifest,
            *(["--expected-existing-records"] if expected_existing_records else []),
            *root_args(root_dir),
        ]
    )


def run(command: list[object], allow_failure: bool = False) -> None:
    rendered = [str(item) for item in command]
    print("RUN", " ".join(rendered))
    result = subprocess.run([sys.executable, *rendered], cwd=PROJECT_ROOT)
    if result.returncode and not allow_failure:
        raise SystemExit(result.returncode)


def _first_existing(paths: list[Path]) -> Path:
    for path in paths:
        if path.exists():
            return path
    raise FileNotFoundError(f"none of these files exist: {[str(path) for path in paths]}")


def _model_path_for(model_type: str, output_dir: Path) -> Path:
    if model_type == "sklearn_random_forest":
        return output_dir / "pe_feature_detector.joblib"
    if model_type == "byte_histogram_centroid":
        return output_dir / "byte_histogram_detector.json"
    if model_type == "byte_histogram_calibrated":
        return output_dir / "byte_histogram_calibrated_detector.json"
    if model_type == "byte_histogram_logistic":
        return output_dir / "byte_histogram_logistic_detector.json"
    if model_type == "hybrid_centroid":
        return output_dir / "hybrid_centroid_detector.json"
    return output_dir / "pe_feature_detector.json"


def _first_metrics(output_dir: Path, transformation: str) -> Path | None:
    matches = sorted(output_dir.glob(f"metrics_*_{transformation}.json"))
    return matches[0] if matches else None


def _detector_name_for_model_type(model_type: str) -> str:
    if model_type == "byte_histogram_centroid":
        return "byte_histogram_centroid"
    if model_type == "byte_histogram_calibrated":
        return "byte_histogram_calibrated"
    if model_type == "byte_histogram_logistic":
        return "byte_histogram_logistic"
    if model_type == "hybrid_centroid":
        return "hybrid_centroid"
    if model_type == "sklearn_random_forest":
        return "pe_feature_sklearn"
    return "pe_feature_centroid"


if __name__ == "__main__":
    main()
