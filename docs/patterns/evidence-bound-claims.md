# Evidence-Bound Claims

> **Scope.** This is an authoring contract, not a runtime control. The schema is
> validated when you compile a bundle; `PolicyChecker` does not evaluate it.
> Enforcement is your adapter's, your preflight step's, or a reviewer's job. See
> [What is enforced at runtime](../../README.md#what-is-enforced-at-runtime).

An agent may state only what is supported by evidence available to the current task.

Required properties:

- the claim references evidence;
- evidence belongs to the same object;
- evidence is fresh enough for the claim;
- the validator can inspect the same evidence seen by the generator;
- synthetic output is never presented as observation;
- insufficient evidence blocks the claim.

A failed evidence binding must stop downstream materialization.
