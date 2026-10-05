# Sanitized evidence notes

Reviewed 2026-10-04. Public synthetic policy cases reproduce library decisions; integration acceptance remains a separate historical observation.

Private Mail Hub source revision: `fbabd069358ba79bf1eb9e2cad59e76f83e980e4`.
Private implementation/raw reports are not copied into this repository. Digests
identify the reviewed artifacts for an authorized operator; they do not make
private evidence publicly reproducible or independently attest its content.
Historical records are not a new live check.

| Reviewed source (private unless noted) | SHA-256 | Evidence / limit |
| --- | --- | --- |
| `mailhub/governance.py` | `3b1df4d7236d6ae6cee714dd4b2ab72247a0d66f5e3a34a7f81fa7fbf4a52231` | In-process ActionRequest/PolicyChecker/GovernanceGate, required signed production bundle, body-free decision provenance. |
| `governance/agent.yaml` | `f5bf2a0e1a3a4d7510e33f6a7d32e69bc1a7644202cf4a363b8fffba05acf283` | Internal work action allowlist is mailbox-scoped; production identifiers omitted. |
| `governance/send-approval.yaml` | `5aca0953833471909e91d42f7e055493877c682ee5df2e1f94d91172fb00d618` | Owner-role, request-bound, maximum-age approval policy. |
| `tests/test_stage4.py` | `63c9cf97d1f683d74367625631a7891578bbbe3135307ede555195e8f4879464` | Draft revision/scoping, owner-only approval, input injection, signed policy tamper and audit-failure tests; mock transport is not production send. |
| `evidence/stage4-production/acceptance-finish.json` | `f2c5e42b530997450cc4262f91eaddc2de49a00d812ded17e74759b195ee7c6f` | Saved internal-action/restart acceptance; external writes disabled. |
| `evidence/stage5-production/production-smoke.json` | `960b073c22bc92b4d4f28ad57d50d4b2d377437b7cdcc7c9e01ce199007f0bdf` | Saved server MCP reads, capability-denied send, no outbound. |
