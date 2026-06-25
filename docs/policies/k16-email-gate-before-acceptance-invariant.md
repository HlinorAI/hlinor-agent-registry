# K16 Email Gate Before Acceptance Invariant

Status: ACTIVE
Severity: HARD_INVARIANT
Applies to: Hlinor/K16 discovery, candidate acceptance, materialization, visual proof, preview, owner-review packet, draft build, send-ready state.

## Authoritative order

1. Live discovery
2. Basic business fit
3. Extract contact data
4. Verify recipient email
5. If no verified email -> skip with status `no_email_skipped`
6. If verified email exists -> accepted candidate
7. Visual/website proof
8. Build preview
9. Validate To/Subject/body
10. Dry-run report or draft/send stage

## Hard rule

Email verification is mandatory BEFORE:

- accepted candidate status
- materialization
- Visual/website proof
- preview build
- owner-review packet
- draft generation
- send-ready artifact
- send stage

A candidate without a verified recipient email MUST stop immediately after contact verification with:

`status = no_email_skipped`

Such a candidate MUST NOT be counted as accepted, MUST NOT be materialized, MUST NOT enter visual/preview work, and MUST NOT consume downstream model/browser/rendering effort.

## Fail-closed behavior

If email verification is missing, unknown, ambiguous, stale, failed, skipped, or not explicitly true:

`verified_email != true`

then the pipeline MUST treat the candidate as:

`no_email_skipped`

No fallback may promote the candidate downstream.

## Required accepted-candidate definition

`accepted candidate` means:

- live discovered
- basic business fit passed
- contact data extracted
- verified recipient email exists

Without verified recipient email, there is no accepted candidate.
