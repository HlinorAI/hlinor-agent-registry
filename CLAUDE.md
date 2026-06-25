

<!-- BEGIN k16_email_gate_before_acceptance_invariant_20260625 -->

## K16 Email Gate Before Acceptance Invariant

Severity: HARD_INVARIANT

This is a hard invariant, not a recommendation.

K16 accepted candidate requires verified recipient email.

Required order:

1. Live discovery
2. Basic business fit
3. Extract contact data
4. Verify recipient email
5. If no verified email -> `no_email_skipped`
6. If verified recipient email exists -> accepted candidate
7. Visual/website proof
8. Build preview
9. Validate To/Subject/body
10. Dry-run report or draft/send stage

Runtime rule:

- No verified recipient email -> `no_email_skipped` and stop.
- No candidate without verified recipient email may be counted as accepted candidate.
- No candidate without verified recipient email may enter materialization.
- No candidate without verified recipient email may enter Visual/website proof.
- No candidate without verified recipient email may enter preview.
- No candidate without verified recipient email may enter owner-review packet.
- No candidate without verified recipient email may enter draft, send-ready, or send stage.
- Missing, unknown, stale, skipped, failed, or ambiguous email verification is treated as not verified.

<!-- END k16_email_gate_before_acceptance_invariant_20260625 -->

