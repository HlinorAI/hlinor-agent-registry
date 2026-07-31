# Deterministic policy tests

Policy tests turn governance expectations into executable, reviewable cases.
They answer a narrow question: given this compiled bundle, request, and fixed
time, does the checker return the decision the policy author intended?

## Run the example

Compile the repository policy bundle, then run the synthetic refund suite:

```bash
hlinor-registry compile \
  --manifest registry.yaml \
  --output dist/policy-bundle.json

hlinor-registry test-policies \
  --bundle dist/policy-bundle.json \
  --tests examples/policy-tests/refund-policy-tests.yaml
```

A successful run exits `0`. An expectation mismatch exits `1`. An unreadable
bundle, invalid test document, unsupported schema version, or broken trust
configuration exits `2`. This separation lets CI distinguish a policy
regression from a test setup that never reached a decision.

Use `--format json` for a stable report:

```bash
hlinor-registry test-policies \
  --bundle dist/policy-bundle.json \
  --tests examples/policy-tests/refund-policy-tests.yaml \
  --format json
```

## File format

```yaml
schema_version: "1.0"
fixed_time: "2026-07-27T12:00:00Z"
cases:
  - id: fresh-approval-is-allowed
    request:
      agent_id: refund-agent
      action: refund_payment
      resource: ticket/1234
      signals:
        approval:
          approver_role: support-lead
          granted_for: refund_payment:ticket/1234
          granted_at: "2026-07-27T11:55:00Z"
    expect:
      result: allowed
      reason_code: EXPLICITLY_ALLOWED
      matched_policy_ids:
        - refund-requires-approval
```

The root object accepts exactly three fields:

- `schema_version` identifies the test contract. Version 1.x is supported.
- `fixed_time` is a timezone-aware ISO-8601 instant used by every policy
  freshness check in the suite.
- `cases` is a non-empty list with unique IDs.

Each case contains a request and the three stable decision fields that matter
to governance: `result`, `reason_code`, and `matched_policy_ids`. Volatile
fields such as decision IDs and wall-clock audit timestamps are deliberately
excluded from comparisons and JSON reports. The report includes the tested
bundle digest and policy revision so a stored CI result identifies the exact
policy artifact it covered.

Request fields map to `ActionRequest`. The test runner generates a stable
request ID from the case ID and sets `requested_at` to `fixed_time`.

## Clock safety

`PolicyChecker` still uses the system UTC clock by default. The test command
injects the suite's fixed clock only into that command's checker instance.
Bundle signature validity continues to be checked using the normal trust
verification clock; policy tests cannot make an expired signature valid.

The format is strict. Unknown fields, duplicate case IDs, naive timestamps,
unknown reason codes, duplicate policy IDs, and result/reason contradictions
are invalid input rather than partially executed tests.
