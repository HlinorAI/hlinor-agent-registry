# Process Contracts

A Process Contract is a portable description of the end-to-end process a
project is expected to improve. It records the entry condition, explicit
stages, required evidence, outputs, handoffs, terminal outcomes, baseline
metrics, and shortcuts that must remain forbidden.

It is intentionally business-neutral. The public registry validates the shape
of the contract and provides a synthetic fixture; it does not store live
owners, run a queue, grant approvals, send external messages, or turn a
recommendation into an outcome.

## Minimal command

```bash
PYTHONPATH=. hlinor-registry validate-process-contract \
  examples/process-contract.yaml
```

The example shows the smallest useful map: intake, review, and decision. A
consumer can add domain-specific stages in its own private repository while
keeping evidence, ownership, handoffs, and terminal outcomes explicit.
