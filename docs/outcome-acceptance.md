# Outcome and Acceptance Gate

The public runtime includes a small, framework-neutral gate for deciding
whether a task outcome is supported by evidence. It answers one question:

> Can this task honestly be called successful?

## Public OSS scope

`OutcomeAcceptanceGate` is local and stateless. It validates an explicit set of
acceptance criteria against `EvidenceRecord` values supplied by the adapter.
Each criterion must require at least one evidence reference. A reference is
accepted only when the adapter marks its record as verified.

The gate does not grant permissions, authenticate the host, persist tasks,
collect telemetry, or verify an external side effect. Those responsibilities
belong to the existing policy/runtime boundary or to the private control plane.

## Terminal outcomes

| Execution state | Outcome | Meaning |
| --- | --- | --- |
| `completed` + every criterion evidenced | `SUCCESS` | The result is fully accepted. |
| `completed` + missing/unverified evidence | `BLOCKED` | Completion was observed, but acceptance is not proven. |
| `failed`, `timed_out`, `interrupted` | `FAILED` | Execution did not complete reliably. |
| `blocked` | `BLOCKED` | A control prevented continuation. |
| `awaiting_approval` | `AWAITING_APPROVAL` | A required approval is still missing. |
| `partial` | `PARTIAL` | Some work happened, but it is not a successful result. |

No caller-provided `completed` flag can turn missing evidence into `SUCCESS`.
The returned `TaskOutcome.as_receipt_fields()` produces portable fields that
can be embedded in the existing lifecycle receipt.

## Example

```python
from hlinor_registry import (
    AcceptanceCriterion,
    EvidenceRecord,
    OutcomeAcceptanceGate,
)

gate = OutcomeAcceptanceGate(
    task_id="task-001",
    criteria=(
        AcceptanceCriterion(
            criterion_id="checks_passed",
            required_evidence=("checks.json",),
        ),
    ),
)

outcome = gate.evaluate(
    {"checks.json": EvidenceRecord("check-result", "checks.json", True)},
    execution_state="completed",
)
assert outcome.successful
```

## Private/commercial scope

The private control plane may persist task state, collect and retain receipts,
correlate outcomes across deployments, apply organization policies, expose
review UI, and connect the result to workload attestation, SIEM, quotas, or
incident workflows. None of those services are implemented here.
