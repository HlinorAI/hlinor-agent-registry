#!/usr/bin/env python3
"""Generate examples/notebooks/first-look.ipynb.

The notebook is generated rather than hand-edited because a .ipynb is JSON
with the source split into lines, and editing that by hand is how a demo ends
up claiming an output it no longer produces. The code cells here are the same
text that tests/test_first_look_notebook.py extracts and executes, so a claim
in the notebook that stops being true fails CI.

Run: python3 examples/notebooks/build_first_look.py
"""

from __future__ import annotations

import json
from pathlib import Path

NOTEBOOK = Path(__file__).resolve().parent / "first-look.ipynb"

AGENT_YAML = """\
id: support-agent
type: agent
name: Support Agent
department: support
description: Reads tickets and their attachments. Never replies, never refunds.

skills: []
validators: []
policies: []

allowed_actions:
  - read_ticket
  - read_attachment:queue/support/*
  - send_customer_reply:ticket/*

blocked_actions:
  - refund_payment

enforcement_mode: strict
"""

TOOLS_YAML = """\
schema_version: "1.0"
type: tool_contract
id: support-tools
name: Support Tools
description: The tools this agent actually has.
version: "1.1.0"

metadata:
  owner: Support Platform Team
  source: manual
  repository: https://github.com/example/support-agent
  revision: demo-v1

tools:
  - id: ticket.read
    action: read_ticket
    description: Read one ticket.
    input_schema:
      type: object
      properties:
        ticket_id: {type: string}
      required: [ticket_id]
      additionalProperties: false
    resource_patterns: ["ticket/*"]
    effects: [database_read]
    annotations: {read_only: true, destructive: false, idempotent: true}

  - id: attachment.read
    action: read_attachment
    description: Read one attachment from a queue.
    input_schema:
      type: object
      properties:
        path: {type: string}
      required: [path]
      additionalProperties: false
    resource_patterns: ["queue/*"]
    effects: [filesystem_read]
    annotations: {read_only: true, destructive: false, idempotent: true}

  - id: ticket.delete
    action: delete_ticket
    description: Added last sprint. Nobody updated the registry.
    input_schema:
      type: object
      properties:
        ticket_id: {type: string}
      required: [ticket_id]
      additionalProperties: false
    resource_patterns: ["ticket/*"]
    effects: [database_write]
    annotations: {read_only: false, destructive: true, idempotent: false}
"""

MANIFEST_YAML = """\
schema_version: "1.0"
policies:
  - path: "agent.yaml"
metadata:
  environment: development
  bundle_revision: 1
  policy_revision: "demo"
"""


def markdown(text: str) -> dict:
    return {"cell_type": "markdown", "metadata": {}, "source": text.splitlines(True)}


def code(text: str) -> dict:
    """Emit a code cell in the exact form `ruff format` produces.

    pre-commit runs ruff-format over .ipynb files, so a cell written in any
    other shape would be rewritten on commit and the generated notebook would
    stop matching this builder. Two rules cover it: no trailing newline on the
    last line, and double quotes for the triple-quoted literals below.
    """
    return {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": text.rstrip("\n").splitlines(True),
    }


CELLS = [
    markdown(
        """\
# An allowed action that denies the call it was written for

This takes about a minute and needs nothing installed on your machine.

A support agent is allowed to read tickets. Its permission list says so:

```yaml
allowed_actions:
  - read_ticket
```

Its tool reads ticket `ticket/5`. Two lines that a reviewer reads as the same
thing. They are not, and the runtime refuses the call.

The point of the demo is not that the rule is surprising once you know it. It
is that nothing in an ordinary test suite tells you, because the tool works,
the YAML is valid, and the permission is right there in the file.
"""
    ),
    code(
        """\
%pip install --quiet hlinor-registry
"""
    ),
    markdown(
        """\
## The two files

`agent.yaml` is the boundary a reviewer signs off. `tools.yaml` is a Tool
Contract: a framework-neutral description of what the agent's tools can
actually reach.
"""
    ),
    code(
        "from pathlib import Path\n\n"
        f'Path("agent.yaml").write_text("""{AGENT_YAML}""")\n'
        f'Path("tools.yaml").write_text("""{TOOLS_YAML}""")\n'
        f'Path("registry.yaml").write_text("""{MANIFEST_YAML}""")\n'
        'print("written")\n'
    ),
    markdown(
        """\
## Compile the boundary

Compilation reads exactly the files the manifest names, so what runs is always
something someone listed on purpose.
"""
    ),
    code(
        """\
!hlinor-registry compile --manifest registry.yaml --output bundle.json
"""
    ),
    markdown(
        """\
## Ask it the question a reviewer would ask

May this agent read a ticket?
"""
    ),
    code(
        """\
!hlinor-registry check --bundle bundle.json --agent support-agent --action read_ticket
"""
    ),
    markdown(
        """\
`ALLOWED`. Looks settled.

Now ask the question the running system asks. The tool does not read "a
ticket"; it reads ticket `ticket/5`.
"""
    ),
    code(
        """\
!hlinor-registry check --bundle bundle.json --agent support-agent --action read_ticket --resource ticket/5
"""
    ),
    markdown(
        """\
`DENIED`, with `ACTION_NOT_ALLOWLISTED`.

`read_ticket` with no wildcard is an exact match. It permits the action named
with no resource attached, and nothing else. To cover the call the tool makes,
the entry has to say `read_ticket:ticket/*`.

This fails in the safe direction -- the agent is refused, not over-permitted.
But it fails at runtime, in production, on a permission everyone already read
and approved.
"""
    ),
    markdown(
        """\
## What would have said so first

`contract check` compares the boundary against the tools the agent really has.
It needs no running agent and no traffic.
"""
    ),
    code(
        """\
!hlinor-registry contract check --agent agent.yaml --tools tools.yaml
"""
    ),
    markdown(
        """\
Four findings, each a different kind of divergence:

- `UNSCOPED_ALLOW_PERMISSION` on `read_ticket` -- the defect from the first
  half of this notebook, stated before it runs, with the line to write
  instead. This is the common one: the permission and the call it was meant
  to cover differ by a suffix nobody notices in review.
- `UNDECLARED_TOOL_SCOPE` on `ticket.delete` -- a destructive tool was added
  last sprint and the registry was never told. Today the runtime refuses it by
  default. It stays refused only until somebody widens a permission to fix an
  unrelated denial.
- `STALE_ALLOW_PERMISSION` on `send_customer_reply:ticket/*` and
  `STALE_BLOCK_PERMISSION` on `refund_payment` -- rules kept for tools that no
  longer exist. Harmless until a tool takes one of those names again.

The command exits non-zero, so it fails a pull request rather than printing
into a log nobody reads.
"""
    ),
    markdown(
        """\
## What this does not do

Worth stating plainly, because the opposite is usually assumed.

The Tool Contract carries a JSON Schema for each tool's inputs. It would be
reasonable to read that as the runtime validating arguments. **It does not.**
Those schemas are an authoring and review artifact. The policy checker sees an
action and a resource, never the arguments a tool was called with, so a tool
that receives a well-formed argument pointing somewhere it should not go is
not stopped by this layer.

The contract is a reviewed description of a boundary. It is not the boundary
itself, and treating it as one is the mistake this project exists to make
visible rather than to commit.

See `SECURITY.md` in the repository for the full trust model.
"""
    ),
    markdown(
        """\
## Try it against your own agent

If you already have an agent with tools, the fastest useful thing is to write
its Tool Contract and run one command against the boundary you already have:

```bash
pip install hlinor-registry
hlinor-registry contract check --agent your-agent.yaml --tools your-tools.yaml
```

The interesting result is not a clean run. It is a finding you did not expect,
or a finding that turns out to be wrong -- the second is more useful than the
first, because a check that cries wolf is worse than no check.

Either way I would like to hear what happened:

- **What the check said about your agent**, including "nothing, and that
  surprised me":
  [Discussions](https://github.com/HlinorAI/hlinor-agent-registry/discussions)
- **A wrong finding, a crash, or a missing feature**:
  [Issues](https://github.com/HlinorAI/hlinor-agent-registry/issues)

Apache-2.0. No telemetry, no account, nothing phones home -- which also means
the only way I learn whether this is useful is if you say so.
"""
    ),
]


def main() -> int:
    notebook = {
        "cells": CELLS,
        "metadata": {
            "kernelspec": {
                "display_name": "Python 3",
                "language": "python",
                "name": "python3",
            },
            "language_info": {"name": "python"},
        },
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    NOTEBOOK.write_text(json.dumps(notebook, indent=1) + "\n", encoding="utf-8")
    print(f"wrote {NOTEBOOK} ({len(CELLS)} cells)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
