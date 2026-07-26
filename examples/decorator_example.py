"""Example of using the @governed decorator."""

from hlinor_registry.integrations.decorators import PolicyViolationError, governed

# Assume this bundle was compiled from our registry
BUNDLE_PATH = "/tmp/bundle.json"


@governed(agent_id="my-agent", action="read_database", bundle_path=BUNDLE_PATH)
def read_database(query: str) -> str:
    print(f"Executing DB query: {query}")
    return "Found 42 records."


@governed(agent_id="my-agent", action="send_external_email", bundle_path=BUNDLE_PATH)
def send_email(to: str, body: str) -> str:
    print(f"Sending email to {to}...")
    return "Email sent!"


if __name__ == "__main__":
    print("--- Testing Allowed Action ---")
    try:
        result = read_database("SELECT * FROM users")
        print(f"Success: {result}\n")
    except PolicyViolationError as e:
        print(f"Blocked: {e}\n")

    print("--- Testing Blocked Action ---")
    try:
        result = send_email("ceo@external.com", "Secret data")
        print(f"Success: {result}\n")
    except PolicyViolationError as e:
        print(f"Blocked: {e}\n")
