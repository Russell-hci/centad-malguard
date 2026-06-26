from __future__ import annotations

from pathlib import Path

from binaryshield.datasets import BinarySample


def is_relative_to(path: str | Path, parent: str | Path) -> bool:
    try:
        Path(path).resolve().relative_to(Path(parent).resolve())
        return True
    except ValueError:
        return False


def samples_include_external_paths(samples: list[BinarySample], project_root: str | Path) -> bool:
    root = Path(project_root).resolve()
    return any(not is_relative_to(sample.path, root) for sample in samples)


def assert_safe_transformation_output(
    *,
    samples: list[BinarySample],
    output_dir: str | Path,
    project_root: str | Path,
    allow_repo_output: bool = False,
) -> None:
    """Prevent accidental transformed-malware writes into the Git repository.

    Synthetic fixtures inside the repository may still write under repo-local
    results directories. When evaluated samples are external to the repository,
    transformed outputs must also stay external unless the caller explicitly
    overrides the guard for a controlled non-malware run.
    """

    if allow_repo_output:
        return
    if not samples_include_external_paths(samples, project_root):
        return
    if is_relative_to(output_dir, project_root):
        raise ValueError(
            "refusing to write transformed artifacts inside the repository for external PE samples. "
            "Use an external --output-dir, or pass --allow-repo-output only for controlled non-malware fixtures."
        )
