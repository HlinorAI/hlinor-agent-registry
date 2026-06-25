from pathlib import Path
import yaml

REQUIRED_AGENT_FIELDS = [
    "id",
    "name",
    "department",
    "description",
    "skills",
    "validators",
    "policies",
    "allowed_actions",
    "blocked_actions",
]

def load_yaml(path: str | Path) -> dict:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        raise ValueError("YAML root must be an object")

    return data

def validate_agent(path: str | Path) -> list[str]:
    data = load_yaml(path)
    errors: list[str] = []

    for field in REQUIRED_AGENT_FIELDS:
        if field not in data:
            errors.append(f"Missing required field: {field}")

    for list_field in ["skills", "validators", "policies", "allowed_actions", "blocked_actions"]:
        if list_field in data and not isinstance(data[list_field], list):
            errors.append(f"Field must be a list: {list_field}")

    return errors
