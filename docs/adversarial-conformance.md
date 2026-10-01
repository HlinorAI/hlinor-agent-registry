# Adversarial conformance suite

The public repository includes a focused negative-test profile in
`tests/test_adversarial_conformance.py`. It uses synthetic keys, scopes,
delegations, receipts, and tools to check that attacker-controlled input does
not silently become governance authority.

Run it locally:

```bash
python -m pytest tests/test_adversarial_conformance.py -q
```

## Coverage matrix

| Attack or failure mode | Public boundary exercised | Required result |
| --- | --- | --- |
| Spoofed sender | Signed scoped message verification | Untrusted sender is rejected. |
| Poisoned message | Signed body and policy-signal projection | Body tampering fails; body text is not authority. |
| Filename/tool-output authority | `BoundTool.invoke()` scope and receipt path | Missing typed scope blocks dispatch; output remains data. |
| Receipt tampering | Hash-chained receipt verification | Changed fields fail hash verification. |
| Delegation fan-out abuse | `reserve_delegation_child()` and chain verification | Child distribution stops at the configured limit. |
| Runaway retries | Durable `SQLiteCircuitBreaker` plus `BoundTool` | A real failure opens the circuit; the next retry does not call the tool. |
| Partial execution after interruption | Runtime receipt plus `OutcomeAcceptanceGate` | Attempted/partial work is not `SUCCESS`. |

The suite is deliberately conformance-level, not a claim of whole-program
security. It does not inspect model reasoning, provide network message
delivery, attest an external workload identity, or operate an independent
audit collector. Those are deployment or private control-plane boundaries.

The policy layer also documents that ordinary `ActionRequest.signals` are
caller assertions. A deployment that needs hostile-adapter resistance must use
the independently verifiable signed approval/delegation paths and its own
trusted runtime boundary; this suite does not turn asserted signals into proof.
