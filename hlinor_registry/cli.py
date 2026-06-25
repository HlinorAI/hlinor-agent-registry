import argparse
import sys
from hlinor_registry.validator import validate_agent

def main() -> int:
    parser = argparse.ArgumentParser(
        prog="hlinor-registry",
        description="Validate Hlinor Agent Registry YAML files.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser("validate", help="Validate an agent YAML file")
    validate_parser.add_argument("path", help="Path to YAML file")

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

    return 1

if __name__ == "__main__":
    sys.exit(main())
