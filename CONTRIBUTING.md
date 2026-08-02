# Contributing

Thank you for your interest in Hlinor Agent Registry.

## How to contribute

1. Open an issue before proposing a major change.
2. Discuss the proposed change with maintainers.
3. Submit a pull request.
4. Keep changes focused and documented.

## Project scope

This repository focuses on:

- agent registry specifications
- schemas
- documentation
- examples
- governance and audit models

It does not include private runtime logic, production pipelines, or commercial implementations.

## Pull requests

Pull requests should include:

- a clear description
- related issue reference
- documentation updates when needed

## Required status checks

The checks that must pass before `main` accepts a merge are listed in
`.github/required-checks.txt`. Every pull request runs
`scripts/check_required_checks.py`, which fails if that file and the jobs in
`.github/workflows/test.yml` disagree.

The file is not the enforcement. The branch ruleset is, and `GITHUB_TOKEN` can
neither read nor write repository rules, so applying the file is a maintainer
step. This gap is the reason the check exists: a job was once added to the
workflow, ran green on every pull request for weeks, and could not block a
merge because the ruleset had never been told about it.

After changing the list, a maintainer applies it. The update endpoint replaces
the rules array, so the current ruleset is fetched, edited, and sent back whole
rather than patched field by field:

```bash
REPO=HlinorAI/hlinor-agent-registry
gh api "repos/$REPO/rulesets" --jq '.[] | "\(.id)  \(.name)  \(.enforcement)"'
ID=<the id printed above>
gh api "repos/$REPO/rulesets/$ID" > /tmp/ruleset.json
grep -v '^#' .github/required-checks.txt | grep -v '^$' |
  jq -R . | jq -s '[.[] | {context: .}]' > /tmp/contexts.json
jq --slurpfile ctx /tmp/contexts.json '
  .rules |= map(
    if .type == "required_status_checks"
    then .parameters.required_status_checks = $ctx[0]
    else . end)
  | {name, target, enforcement, conditions, rules, bypass_actors}
' /tmp/ruleset.json > /tmp/ruleset-new.json
gh api -X PUT "repos/$REPO/rulesets/$ID" --input /tmp/ruleset-new.json > /dev/null
```

Then read back what GitHub stored, rather than trusting that the write did what
it said:

```bash
gh api "repos/HlinorAI/hlinor-agent-registry/rulesets/$ID" \
  --jq '.rules[] | select(.type=="required_status_checks")
        | .parameters.required_status_checks[].context' | sort > /tmp/live.txt
grep -v '^#' .github/required-checks.txt | grep -v '^$' | sort > /tmp/want.txt
diff /tmp/live.txt /tmp/want.txt && echo "ruleset matches the file"
```

Confirm `enforcement` is `active` and that no bypass actor was introduced; a
rule that is present but not enforced is the same defect in a different place.

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
