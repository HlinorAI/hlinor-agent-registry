# Capability Verification

Declared capabilities are not sufficient.

A capability is considered available only when:

- the required tool or provider is observable;
- required permissions are present;
- the current execution context supports the operation;
- verification is current for the task and workspace;
- the requested scope matches the verified scope.

Verification must fail closed when evidence is missing or stale.
