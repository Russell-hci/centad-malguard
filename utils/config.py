from pathlib import Path

import yaml


def load_yaml_config(config_path: str | Path | None) -> dict:
    if config_path is None:
        return {}

    resolved_path = Path(config_path)
    with resolved_path.open("r", encoding="utf-8") as handle:
        config = yaml.safe_load(handle) or {}

    if not isinstance(config, dict):
        raise ValueError(f"Config file must contain a mapping at the top level: {resolved_path}")

    return config
