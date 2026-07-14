import argparse
import sys
import yaml
from hlinor_registry.validator import (
    validate_execution_context,
    load_yaml,
    validate_agent,
    validate_department,
    validate_policy,
    validate_production_action_boundary_example,
    validate_runtime_example,
    validate_skill,
    validate_validator,
    validate_lifecycle_map,
    validate_lifecycle_receipt,
    validate_lifecycle_schema,
)


VALIDATION_COMMANDS = {
    "validate-agent": ("Agent", validate_agent),
    "validate-department": ("Department", validate_department),
    "validate-policy": ("Policy", validate_policy),
    "validate-skill": ("Skill", validate_skill),
    "validate-validator": ("Validator", validate_validator),
    "validate-runtime-example": ("Runtime example", validate_runtime_example),
    "validate-production-action-boundary-example": (
        "Production action boundary example",
        validate_production_action_boundary_example,
    ),
    "validate-lifecycle-map": ("Lifecycle map", validate_lifecycle_map),
    "validate-lifecycle-receipt": ("Lifecycle receipt", validate_lifecycle_receipt),
    "validate-lifecycle-schema": ("Lifecycle schema", validate_lifecycle_schema),
}


def _compact_error(error: Exception) -> str:
    return " ".join(str(error).split())


def _run_validation(label: str, validator, path: str) -> int:
    try:
        errors = validator(path)
    except FileNotFoundError as error:
        errors = [_compact_error(error)]
    except (ValueError, yaml.YAMLError) as error:
        errors = [_compact_error(error)]

    if errors:
        print(f"Invalid {label}:")
        for error in errors:
            print(f"- {error}")
        return 1

    print(f"{label} is valid.")
    return 0


def _inspect(path: str) -> int:
    try:
        data = load_yaml(path)
    except FileNotFoundError as error:
        print(f"Error: {_compact_error(error)}")
        return 1
    except ValueError as error:
        print(f"Error: {_compact_error(error)}")
        return 1
    except yaml.YAMLError as error:
        print(f"Error: Invalid YAML: {_compact_error(error)}")
        return 1

    keys = ", ".join(sorted(data))
    print(f"Path: {path}")
    print(f"id: {data.get('id', '<missing>')}")
    print(f"name: {data.get('name', '<missing>')}")
    print(f"keys: {keys}")
    return 0

def main() -> int:
    parser = argparse.ArgumentParser(
        prog="hlinor-registry",
        description="Validate Hlinor Agent Registry YAML files.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser("validate", help="Validate an agent YAML file")
    validate_parser.add_argument("path", help="Path to YAML file")

    for command in VALIDATION_COMMANDS:
        command_parser = subparsers.add_parser(command, help=f"Run {command}")
        command_parser.add_argument("path", help="Path to YAML file")

    inspect_parser = subparsers.add_parser("inspect", help="Inspect a YAML registry file")
    inspect_parser.add_argument("path", help="Path to YAML file")

    execution_context_parser = subparsers.add_parser(
        "validate-execution-context",
        help="Validate an execution context YAML file",
    )
    execution_context_parser.add_argument("path", help="Path to YAML file")

    args = parser.parse_args()

    if args.command == "validate":
        errors = validate_agent(args.path)

        if errors:
            print("Invalid registry file:")
            for error in errors:
                print(f"- {error}")
            return 1

        print("Registry file is valid.")
        return 0

    if args.command in VALIDATION_COMMANDS:
        label, validator = VALIDATION_COMMANDS[args.command]
        return _run_validation(label, validator, args.path)

    if args.command == "inspect":
        return _inspect(args.path)

    if args.command == "validate-execution-context":
        try:
            errors = validate_execution_context(args.path)
        except (FileNotFoundError, ValueError) as exc:
            print(f"Invalid execution context: {exc}")
            return 1

        if errors:
            print("Invalid execution context:")
            for error in errors:
                print(f"- {error}")
            return 1

        print("Execution context is valid.")
        return 0

    return 1

if __name__ == "__main__":
    sys.exit(main())
