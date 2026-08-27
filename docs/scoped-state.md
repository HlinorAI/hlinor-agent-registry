# Scoped workspace state and messages

`SQLiteScopedWorkspaceStore` is the first durable runtime boundary for the
project-isolation model. Every read, write, and message query requires an
explicit `ExecutionScope(project_id, workspace_id)`.

```python
from hlinor_registry import ExecutionScope, SQLiteScopedWorkspaceStore

scope = ExecutionScope("project-1", "workspace-1")
with SQLiteScopedWorkspaceStore("state.sqlite3") as store:
    store.put(scope, "evidence/latest", {"status": "reviewed"})
    record = store.get(scope, "evidence/latest")
```

Records use a composite `(project_id, workspace_id, key)` primary key. The API
has no project-global listing operation, so the caller cannot discover or read
another project's records by changing a filename or package label. Values are
finite JSON, keys and identities have bounded lengths, and updates expose a
monotonic revision.

Messages are also stored under the composite project/workspace scope and must
be read for an explicit recipient. Message bodies are ordinary JSON data; text
such as `GO`, `STOP`, or `VETO` does not grant authority and is not interpreted
by this store. `sender_agent_id` is recorded metadata, not cryptographic
authentication. Signed delegation transport or an external identity provider
is still required when sender authenticity matters.

This is a scoped persistence primitive, not a complete workspace protocol. It
does not yet implement AutoGen execution wrapping, handoff authorization,
message signatures, retention/garbage collection, or external attestation.
