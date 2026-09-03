"""Synthetic source inventory used by the governance coverage check."""


def governed(*args: object, **kwargs: object):
    """Synthetic decorator marker; this file is inspected, not executed."""
    return lambda function: function


def bind_tool(*args: object, **kwargs: object):
    """Synthetic binding marker; this file is inspected, not executed."""
    return


reviewed_contract = {}
observed_contract = {}


@governed(
    agent_id="synthetic-agent",
    action="send_report",
    bundle_path="dist/policy-bundle.json",
)
def governed_send_report(destination: str, body: str) -> None:
    """A sensitive path protected by the shared decorator boundary."""


def bound_delete_record(record_id: str) -> None:
    """A sensitive path retained only through an exact BoundTool target."""


BOUND_DELETE_RECORD = bind_tool(
    reviewed_contract,
    observed_contract,
    tool_id="records.delete",
    target=bound_delete_record,
)
