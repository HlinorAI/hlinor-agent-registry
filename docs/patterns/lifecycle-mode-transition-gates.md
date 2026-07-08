# Lifecycle Mode Transition Gates

Transition gates define when a task may move from one lifecycle mode to another. They are evidence requirements, not automatic runtime triggers.

## Prototyper to Builder

Allowed only when:

- Hypothesis is clear
- Expected value is clear
- Owner constraints are known
- Success criteria are defined
- Kill criteria are defined
- Implementation scope is bounded

Required evidence:

- Idea brief
- Experiment card
- Risk notes
- Kill criteria
- Suggested next mode

## Builder to Sweeper

Allowed only when:

- Implementation works
- Tests or smoke checks exist
- Changed files are known
- Rollback notes exist
- Side effects are documented

Required evidence:

- Implementation summary
- Changed files list
- Test or smoke-check result
- Rollback notes
- Execution receipt

## Sweeper to Grower

Allowed only when:

- System is stable
- Behavior is preserved
- Baseline exists
- Improvement area is measurable

Required evidence:

- Cleanup summary
- Removed complexity list
- Regression check result
- Risk assessment
- Remaining clutter list

## Grower to Maintainer

Allowed only when:

- Product or workflow is mature enough
- Repeat usage or repeat operation exists
- Risks are operational rather than exploratory
- Reliability, cost, security, or scalability now matter

Required evidence:

- Growth hypothesis
- Baseline metric
- Result review
- Keep, revert, iterate, or kill decision
- Operational risks found during growth

## Maintainer to Builder

Allowed only through a change request with:

- Specific issue
- Impact
- Minimal fix
- Risk level
- Validation plan
- Rollback or recovery path

Required evidence:

- Health report or incident note
- Risk classification
- Proposed change request
- Validation plan

## Disallowed Silent Transitions

The following transitions require explicit classification or approval:

- Prototyper directly modifying production behavior
- Builder expanding scope into new strategy
- Sweeper changing business logic
- Grower running experiments without metrics
- Maintainer blocking changes without a concrete risk

