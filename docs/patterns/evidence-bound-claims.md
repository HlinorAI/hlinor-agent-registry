# Evidence-Bound Claims

An agent may state only what is supported by evidence available to the current task.

Required properties:

- the claim references evidence;
- evidence belongs to the same object;
- evidence is fresh enough for the claim;
- the validator can inspect the same evidence seen by the generator;
- synthetic output is never presented as observation;
- insufficient evidence blocks the claim.

A failed evidence binding must stop downstream materialization.
