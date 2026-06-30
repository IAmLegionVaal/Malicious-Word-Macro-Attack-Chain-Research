from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError as exc:
    raise SystemExit("PyYAML is required: python -m pip install PyYAML") from exc

ROOT = Path(__file__).resolve().parents[1]
SIGMA_DIR = ROOT / "detections" / "sigma"
REQUIRED_KEYS = {"title", "id", "status", "description", "logsource", "detection", "level"}


def validate_sigma(path: Path) -> list[str]:
    errors: list[str] = []

    try:
        data: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return [f"{path}: YAML parse failure: {exc}"]

    if not isinstance(data, dict):
        return [f"{path}: top-level YAML document must be a mapping"]

    missing = sorted(REQUIRED_KEYS - set(data))
    if missing:
        errors.append(f"{path}: missing required keys: {', '.join(missing)}")

    detection = data.get("detection")
    if not isinstance(detection, dict) or "condition" not in detection:
        errors.append(f"{path}: detection.condition is required")

    return errors


def main() -> int:
    errors: list[str] = []
    sigma_files = sorted(SIGMA_DIR.glob("*.yml"))

    if not sigma_files:
        errors.append("No Sigma rules found.")

    for path in sigma_files:
        errors.extend(validate_sigma(path))

    if errors:
        print("Validation failed:")
        for error in errors:
            print(f" - {error}")
        return 1

    print(f"Validated {len(sigma_files)} Sigma rule(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
