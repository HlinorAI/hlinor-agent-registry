# Shared runtime limits

`SQLiteRuntimeBudget` is an experimental admission guard for one governed
dispatch boundary. It stores state in a shared SQLite file so workers and
restarts observe the same controls:

- a kill switch checked atomically before a lease is created;
- a per-scope maximum number of active concurrency leases;
- a per-scope event limit over a bounded time window;
- expiring leases so a crashed worker cannot hold a slot forever.

`BoundTool.invoke()` accepts `runtime_budget`, `budget_scope`, and explicit
`max_concurrency`/`rate_limit` settings. Admission happens before the
pre-dispatch receipt and exact callable. The lease is released in a `finally`
path after success, tool failure, or receipt failure. Kill-switch, rate, and
concurrency errors fail closed and never dispatch the target.

```python
from hlinor_registry import SQLiteRuntimeBudget

runtime_budget = SQLiteRuntimeBudget("/protected/state/runtime-limits.sqlite3")
runtime_budget.activate_kill_switch("incident-2026-08-27")
runtime_budget.deactivate_kill_switch()
```

The store is a coordination primitive, not an authenticated control plane.
Protect its file and the kill-switch controller with deployment access control.
This slice does not account for monetary cost, enforce a global network-wide
quota, or prove that every agent path uses the guard.
