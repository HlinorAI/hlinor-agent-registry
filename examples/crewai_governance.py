"""Example of using Hlinor Registry governance with CrewAI."""

from crewai import Agent, Crew, Process, Task
from crewai.tools import tool

from hlinor_registry.integrations.crewai import GovernedCrewTool


# 1. Define a standard CrewAI tool (e.g., sending an email)
@tool
def send_external_email_tool(recipient: str, subject: str, body: str) -> str:
    """Send an external email. (This should be blocked by governance)."""
    return f"Email sent to {recipient} with subject: {subject}"


@tool
def read_database_tool(query: str) -> str:
    """Read data from the internal database."""
    return f"Database query executed: {query}. Found 42 records."


# 2. Wrap the tools with Hlinor Governance
# Assume we have a bundle.json compiled from our registry
BUNDLE_PATH = "dist/policy-bundle.json"
AGENT_ID = "financial-audit-agent"

governed_email_tool = GovernedCrewTool(
    executor=send_external_email_tool,
    agent_id=AGENT_ID,
    action_name="send_external_email",
    bundle_path=BUNDLE_PATH,
)

governed_db_tool = GovernedCrewTool(
    executor=read_database_tool,
    agent_id=AGENT_ID,
    action_name="read_database",
    bundle_path=BUNDLE_PATH,
)

# 3. Create a CrewAI Agent with the governed tools
auditor_agent = Agent(
    role="Financial Auditor",
    goal="Audit financial records and report findings via email.",
    backstory="You are a meticulous financial auditor. You always try to email the final report to external stakeholders.",
    tools=[governed_db_tool, governed_email_tool],
    verbose=True,
)

# 4. Create a Task that will trigger both allowed and blocked actions
audit_task = Task(
    description="1. Read the financial records from the database. 2. Send an external email with the findings to ceo@external.com.",
    expected_output="A summary of the database read attempt and the result of the email attempt.",
    agent=auditor_agent,
)

# 5. Run the Crew
if __name__ == "__main__":
    print("Starting CrewAI execution with Hlinor Governance...\n")
    print("=" * 60)

    crew = Crew(
        agents=[auditor_agent],
        tasks=[audit_task],
        process=Process.sequential,
    )

    result = crew.kickoff()

    print("=" * 60)
    print("\nFinal Result:")
    print(result.raw)
