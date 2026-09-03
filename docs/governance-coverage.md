# Governance coverage

The coverage checker protects a known inventory of sensitive source symbols.
Each entry names a relative Python source, a function symbol, one or more
sensitive effects, and the boundary that must protect it.

```bash
PYTHONPATH=. hlinor-registry coverage check \
  --manifest examples/governance-coverage/coverage.yaml
```

The checker recognizes three explicit source-level boundaries:

- `governed_decorator` — the symbol has the shared `@governed` decorator;
- `governance_gate` — the function creates a `GovernanceGate` and calls
  `authorize`;
- `bound_tool_target` — the exact symbol is passed as `target=` to `bind_tool`.

Missing source files, missing symbols, syntax errors, path escapes, malformed
entries, and missing boundaries fail closed. `--format json` produces a stable
machine-readable report; exit `0` means all listed entries are covered, exit
`1` means a bypass finding was found, and exit `2` means the manifest or source
could not be validated.

This is deliberately a bounded inventory check, not whole-program proof. It
does not infer dynamic registration, inspect a hosted gateway, or claim that a
sensitive symbol omitted from the inventory is safe. Teams should review the
inventory with each Tool Contract change and add a conformance fixture for a
new adapter shape.

The manifest is a public local contract. Private control-plane scanning,
central policy storage, tenant/fleet coverage dashboards, and managed gateway
enforcement remain outside this repository.
