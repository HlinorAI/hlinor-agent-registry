"""Typed policies: obligations a permitted action must still discharge.

Layer 1 answers "may this agent touch this resource at all". A policy answers
the question that comes after: *given that it may, what must be true of this
particular request before it proceeds.*

A policy is a separate file compiled into the bundle, and an agent opts into it
by naming its id in ``policies:``. It carries a ``trigger`` -- the same pattern
syntax the action lists use -- and a handler ``kind`` that decides what the
request must supply:

    type: policy
    id: external-send-requires-approval
    kind: requires_approval
    trigger:
      - send:email:external:*
    requires:
      approver_role: security-lead
      max_age_seconds: 900

Policies only ever restrict. They run after the allow list has already
permitted the action, and no handler can turn a denial into an allowance. That
keeps the reasoning one-directional: reading the action lists tells you the
widest thing an agent can do, and policies can only narrow it.

## What a policy can and cannot establish

Handlers read *signals*: material the caller places in ``ActionRequest.signals``
to show an obligation was discharged. An approval, a set of evidence claims, a
failure count.

**A signal is asserted by the caller. The checker enforces the rule, not the
truth of the signal.** ``PolicyChecker`` runs in the same process as the code
it is governing; it has no independent view of whether an approval was really
granted or whether a failure really occurred. What it can do -- and what makes
this worth having -- is refuse to let an action proceed unless the caller
states, in a recorded and digested form, that the obligation was met. That
turns "the adapter is supposed to check this" into "the request is denied
unless the check is claimed", and puts the claim in the audit record where a
reviewer can compare it against the approval system's own logs.

Within that limit the checker verifies real things the caller can get wrong by
accident, which is the common case:

- an approval is bound to the request it was granted for, so an approval for
  one action cannot be replayed for another;
- an approval or an evidence claim is fresh, computed against the policy's own
  window rather than trusted from a self-reported "fresh" flag;
- an evidence claim is about the same resource the request names, computed by
  comparison rather than taken from a ``same_object_verified`` boolean.

A caller that deliberately fabricates signals defeats all of it. Guarding
against that requires the approval to be independently verifiable -- a signed
token checked against a trust store, the way bundles already are -- which is
not implemented. Until it is, treat these as gates against mistakes and
omissions, not against a hostile adapter.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from ._matching import find_match, matches, pattern_errors, request_key
from .enums import ReasonCode

__all__ = [
    "POLICY_KINDS",
    "PolicyOutcome",
    "PolicyRule",
    "load_policy_rules",
    "policy_definition_errors",
]

#: Signal names each handler reads from ``ActionRequest.signals``. Kept here so
#: the error messages, the docs and the handlers cannot drift apart.
SIGNAL_NAMES = {
    "requires_approval": "approval",
    "requires_evidence": "evidence",
    "failure_threshold": "failure_counts",
}


@dataclass(frozen=True)
class PolicyOutcome:
    """Why a policy let a request through, or did not."""

    policy_id: str
    satisfied: bool
    reason_code: ReasonCode | None = None
    detail: str = ""


def _parse_timestamp(value: Any) -> datetime | None:
    """Parse an ISO 8601 instant, or return None if it is not one.

    ``datetime.fromisoformat`` did not accept a trailing ``Z`` until Python
    3.11, and this package supports 3.10. Normalising here keeps a policy from
    deciding differently on different interpreters -- the same class of
    platform-dependence that ``fnmatchcase`` avoids in the matcher.

    A naive timestamp is rejected rather than assumed to be UTC. Guessing an
    offset would silently shift a freshness window by hours.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed


#: How far ahead of the checker's clock a signal timestamp may sit before it is
#: treated as wrong rather than merely early. Machines disagree by seconds; a
#: signal dated further ahead than this is a broken clock or a fabricated
#: value, and either way it must not extend a freshness window.
ALLOWED_CLOCK_SKEW_SECONDS = 30.0


def _freshness_error(
    timestamp: datetime,
    *,
    max_age_seconds: float,
    now: datetime | None = None,
    allowed_clock_skew_seconds: float = ALLOWED_CLOCK_SKEW_SECONDS,
) -> str | None:
    """Check both ends of the accepted window, or return why it failed.

    A window with only an upper bound is not a window. Age is ``now -
    timestamp``, so a timestamp in the future produces a *negative* age, and a
    check that only asks ``age > max_age`` accepts a signal dated a year from
    now as though it were seconds old. That is the whole freshness control
    inverted by a minus sign, and it is why this helper exists rather than the
    comparison living inline in each handler where it can drift.

    Negative age is reported, not clamped to zero. Clamping would let a
    malformed or fabricated timestamp pass as merely fresh, and the audit
    record would say nothing about it.
    """
    reference = now or datetime.now(timezone.utc)
    age = (reference - timestamp).total_seconds()

    if age < -allowed_clock_skew_seconds:
        return (
            f"timestamp is {-age:.0f}s in the future, beyond the "
            f"{allowed_clock_skew_seconds:.0f}s clock-skew allowance"
        )
    if age > max_age_seconds:
        return f"timestamp is {age:.0f}s old, limit is {max_age_seconds}s"
    return None


def _as_mapping(value: Any) -> Mapping[str, Any] | None:
    return value if isinstance(value, Mapping) else None


def _require_bool(spec: Mapping[str, Any], field: str) -> bool:
    """Read a security-sensitive switch that must be an actual boolean.

    ``spec.get(field, True)`` under Python truthiness lets ``0``, ``""`` or
    ``null`` turn a binding check off. These two switches decide whether an
    approval is tied to its request and whether evidence must concern the
    resource being acted on, so a governance file must not be able to disable
    them by writing something that merely looks false.

    Authoring validation rejects these values too. This is the second line:
    a compiled bundle can be produced by another implementation or edited by
    hand, and a runtime that trusts the artifact it is verifying is not a
    runtime that verifies anything.
    """
    value = spec.get(field, True)
    if not isinstance(value, bool):
        raise TypeError(
            f"compiled policy {field} must be a boolean, got {type(value).__name__}"
        )
    return value


@dataclass(frozen=True)
class PolicyRule:
    """One compiled policy: when it applies, and what it then demands."""

    policy_id: str
    kind: str
    trigger: tuple[str, ...]
    spec: Mapping[str, Any]

    def applies_to(self, key: str) -> bool:
        """True when the request key matches any trigger pattern.

        Uses the same matcher as the action lists, so ``*`` crosses ``:`` here
        too. A trigger is therefore at least as broad as it looks, which is the
        safe direction for something that only adds obligations.
        """
        return find_match(self.trigger, key) is not None

    def check(
        self,
        request: Any,
        *,
        now: datetime | None = None,
    ) -> PolicyOutcome:
        """Decide whether this request discharges the obligation."""
        handler = _HANDLERS[self.kind]
        signal_name = SIGNAL_NAMES[self.kind]
        signals = getattr(request, "signals", None) or {}
        signal = signals.get(signal_name) if isinstance(signals, Mapping) else None

        if signal is None:
            return PolicyOutcome(
                self.policy_id,
                False,
                ReasonCode.POLICY_SIGNAL_MISSING,
                f"policy '{self.policy_id}' requires signals['{signal_name}']",
            )
        return handler(self, request, signal, now)


def _check_approval(
    rule: PolicyRule,
    request: Any,
    signal: Any,
    now: datetime | None,
) -> PolicyOutcome:
    """Require an approval that is bound to this request and still fresh."""
    approval = _as_mapping(signal)
    if approval is None:
        return PolicyOutcome(
            rule.policy_id,
            False,
            ReasonCode.POLICY_SIGNAL_MISSING,
            f"policy '{rule.policy_id}': signals['approval'] must be an object",
        )

    def refuse(detail: str) -> PolicyOutcome:
        return PolicyOutcome(
            rule.policy_id,
            False,
            ReasonCode.APPROVAL_REQUIRED,
            f"policy '{rule.policy_id}': {detail}",
        )

    required_role = rule.spec.get("approver_role")
    if required_role is not None and approval.get("approver_role") != required_role:
        return refuse(
            f"approval must come from role '{required_role}', "
            f"got {approval.get('approver_role')!r}"
        )

    # Bind the approval to the request it was granted for. Without this an
    # approval legitimately obtained for a harmless action can be attached to
    # any other action the same agent is permitted to attempt.
    if _require_bool(rule.spec, "bind_to_request"):
        granted_for = approval.get("granted_for")
        if not isinstance(granted_for, str) or not granted_for.strip():
            return refuse("approval must name the request it was granted for")
        key = request_key(request.action, getattr(request, "resource", None))
        if not matches(granted_for, key):
            return refuse(f"approval was granted for {granted_for!r}, not {key!r}")

    max_age = rule.spec.get("max_age_seconds")
    if max_age is not None:
        granted_at = _parse_timestamp(approval.get("granted_at"))
        if granted_at is None:
            return refuse("approval must carry granted_at as a timezone-aware instant")
        problem = _freshness_error(granted_at, max_age_seconds=float(max_age), now=now)
        if problem is not None:
            return refuse(f"approval {problem}")

    return PolicyOutcome(rule.policy_id, True)


def _check_evidence(
    rule: PolicyRule,
    request: Any,
    signal: Any,
    now: datetime | None,
) -> PolicyOutcome:
    """Require evidence claims of the named types, fresh and about this resource."""
    if not isinstance(signal, Sequence) or isinstance(signal, (str, bytes)):
        return PolicyOutcome(
            rule.policy_id,
            False,
            ReasonCode.POLICY_SIGNAL_MISSING,
            f"policy '{rule.policy_id}': signals['evidence'] must be a list",
        )

    def refuse(detail: str) -> PolicyOutcome:
        return PolicyOutcome(
            rule.policy_id,
            False,
            ReasonCode.EVIDENCE_REQUIRED,
            f"policy '{rule.policy_id}': {detail}",
        )

    claims = [claim for claim in signal if isinstance(claim, Mapping)]
    max_age = rule.spec.get("max_age_seconds")
    # The schema in registry/schema/evidence-claim-binding.yaml carries a
    # same_object_verified boolean. A claim asserting its own correctness is
    # worth nothing, so the comparison is computed here instead.
    same_resource = _require_bool(rule.spec, "same_resource")
    resource = getattr(request, "resource", None)

    # Missing data must deny, not disable the binding. Skipping the comparison
    # when the request names no resource meant an action with no resource
    # accepted evidence about anything at all -- the check switched itself off
    # in exactly the case where nothing else constrained the claim.
    if same_resource and (not isinstance(resource, str) or not resource.strip()):
        return refuse(
            "request must name a resource for evidence bound with same_resource"
        )

    for required_type in rule.spec.get("evidence_types") or []:
        candidates = [claim for claim in claims if claim.get("type") == required_type]
        if not candidates:
            return refuse(f"no evidence claim of type {required_type!r}")

        if same_resource:
            candidates = [
                claim for claim in candidates if claim.get("resource") == resource
            ]
            if not candidates:
                return refuse(
                    f"evidence of type {required_type!r} does not name resource "
                    f"{resource!r}"
                )

        if max_age is not None:
            fresh = []
            for claim in candidates:
                observed_at = _parse_timestamp(claim.get("observed_at"))
                if observed_at is None:
                    continue
                if (
                    _freshness_error(
                        observed_at, max_age_seconds=float(max_age), now=now
                    )
                    is None
                ):
                    fresh.append(claim)
            if not fresh:
                return refuse(
                    f"no evidence of type {required_type!r} carries a "
                    f"timezone-aware observed_at inside the {max_age}s window"
                )

    return PolicyOutcome(rule.policy_id, True)


def _check_failure_threshold(
    rule: PolicyRule,
    request: Any,
    signal: Any,
    now: datetime | None,
) -> PolicyOutcome:
    """Stop a series once the caller reports enough consecutive failures.

    The count comes from the caller because ``PolicyChecker`` has no memory
    between requests. Holding a counter in the checker was considered and
    rejected: it would reset on restart and would not be shared between
    workers, so it would report protection that a second process does not have.
    What the bundle contributes is the threshold itself -- a reviewed, signed
    number rather than a constant somewhere in the application.
    """
    counts = _as_mapping(signal)
    if counts is None:
        return PolicyOutcome(
            rule.policy_id,
            False,
            ReasonCode.POLICY_SIGNAL_MISSING,
            f"policy '{rule.policy_id}': signals['failure_counts'] must be an object",
        )

    counter = rule.spec["counter"]
    limit = rule.spec["max_consecutive_failures"]
    observed = counts.get(counter)

    if not isinstance(observed, int) or isinstance(observed, bool) or observed < 0:
        # Fail closed. An unreported counter is indistinguishable from a
        # counter nobody is keeping, and a breaker that assumes zero whenever
        # it is not told otherwise is a breaker that never opens.
        return PolicyOutcome(
            rule.policy_id,
            False,
            ReasonCode.POLICY_SIGNAL_MISSING,
            f"policy '{rule.policy_id}': signals['failure_counts'][{counter!r}] "
            f"must be reported as a non-negative integer",
        )

    if observed >= limit:
        return PolicyOutcome(
            rule.policy_id,
            False,
            ReasonCode.FAILURE_THRESHOLD_REACHED,
            f"policy '{rule.policy_id}': {counter} reported {observed} "
            f"consecutive failures, limit is {limit}",
        )

    return PolicyOutcome(rule.policy_id, True)


_HANDLERS = {
    "requires_approval": _check_approval,
    "requires_evidence": _check_evidence,
    "failure_threshold": _check_failure_threshold,
}

#: The complete set of handler kinds. A policy naming anything else is refused
#: at compile time rather than ignored at runtime, because a policy that is
#: silently skipped is worse than one that was never written.
POLICY_KINDS = frozenset(_HANDLERS)

#: Switches that decide whether a binding check runs at all. They must be real
#: booleans in both the authored file and the compiled bundle.
_BOOLEAN_SPEC_FIELDS: dict[str, tuple[str, ...]] = {
    "requires_approval": ("bind_to_request",),
    "requires_evidence": ("same_resource",),
}

_REQUIRED_SPEC_FIELDS: dict[str, tuple[str, ...]] = {
    "requires_approval": (),
    "requires_evidence": ("evidence_types",),
    "failure_threshold": ("counter", "max_consecutive_failures"),
}

_SPEC_SECTION = {
    "requires_approval": "requires",
    "requires_evidence": "requires",
    "failure_threshold": "threshold",
}


def policy_definition_errors(data: Mapping[str, Any]) -> list[str]:
    """Validate the enforceable part of a policy file.

    Everything here is refused at compile time. A policy whose handler name is
    misspelled, or whose trigger is a pattern the matcher does not support,
    would otherwise compile into a bundle and then apply to nothing -- looking,
    to anyone reading the registry, exactly like a control that is in force.
    """
    errors: list[str] = []

    kind = data.get("kind")
    if kind is None:
        return errors  # Prose-only policy; still valid declarative context.

    if not isinstance(kind, str) or kind not in POLICY_KINDS:
        supported = ", ".join(sorted(POLICY_KINDS))
        errors.append(
            f"policy: Unsupported kind {kind!r}. Supported kinds: {supported}"
        )
        return errors

    trigger = data.get("trigger")
    if not isinstance(trigger, list) or not trigger:
        errors.append("policy: Field must be a non-empty list: trigger")
    else:
        for index, pattern in enumerate(trigger):
            if not isinstance(pattern, str) or not pattern.strip():
                errors.append(
                    f"policy: Invalid trigger[{index}]: expected a non-empty string"
                )
                continue
            for problem in pattern_errors(pattern):
                errors.append(f"policy: Invalid trigger[{index}]: {problem}")

    section = _SPEC_SECTION[kind]
    spec = data.get(section)
    if spec is not None and not isinstance(spec, Mapping):
        errors.append(f"policy: Field must be an object when set: {section}")
        spec = None

    spec = spec or {}
    for required_field in _REQUIRED_SPEC_FIELDS[kind]:
        if required_field not in spec:
            errors.append(f"policy: Kind {kind!r} requires {section}.{required_field}")

    errors.extend(_spec_field_errors(kind, section, spec))
    return errors


def _spec_field_errors(kind: str, section: str, spec: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []

    max_age = spec.get("max_age_seconds")
    if max_age is not None and (
        not isinstance(max_age, (int, float))
        or isinstance(max_age, bool)
        or max_age <= 0
    ):
        errors.append(f"policy: {section}.max_age_seconds must be a positive number")

    if kind == "requires_evidence":
        evidence_types = spec.get("evidence_types")
        if evidence_types is not None and (
            not isinstance(evidence_types, list)
            or not evidence_types
            or not all(
                isinstance(item, str) and item.strip() for item in evidence_types
            )
        ):
            errors.append(
                f"policy: {section}.evidence_types must be a non-empty list of strings"
            )

    # Truthiness is not a governance contract. A file that writes `0` or
    # "false" here is either a mistake or an attempt to disable a binding
    # check while looking like it configured one; both are refused by name.
    for boolean_field in _BOOLEAN_SPEC_FIELDS.get(kind, ()):
        if boolean_field in spec and not isinstance(spec[boolean_field], bool):
            errors.append(
                f"policy: {section}.{boolean_field} must be a boolean "
                f"(true or false), not {type(spec[boolean_field]).__name__}"
            )

    if kind == "failure_threshold":
        counter = spec.get("counter")
        if counter is not None and (
            not isinstance(counter, str) or not counter.strip()
        ):
            errors.append(f"policy: {section}.counter must be a non-empty string")
        limit = spec.get("max_consecutive_failures")
        if limit is not None and (
            not isinstance(limit, int) or isinstance(limit, bool) or limit < 1
        ):
            errors.append(
                f"policy: {section}.max_consecutive_failures must be an integer >= 1"
            )

    return errors


def load_policy_rules(policies: Any) -> dict[str, PolicyRule]:
    """Build the enforceable rules from the bundle's compiled policy entries.

    Entries without a ``kind`` are declarative prose and produce no rule. They
    stay in the bundle so a reviewer still sees them; they simply do not decide
    anything.
    """
    rules: dict[str, PolicyRule] = {}
    if not isinstance(policies, Mapping):
        return rules

    for policy_id, entry in policies.items():
        bundle_entry = _as_mapping(entry)
        if bundle_entry is None:
            continue
        config = _as_mapping(bundle_entry.get("config"))
        if config is None:
            continue
        kind = config.get("kind")
        if kind not in POLICY_KINDS:
            continue
        trigger = config.get("trigger")
        if not isinstance(trigger, list):
            continue
        spec = _as_mapping(config.get(_SPEC_SECTION[kind])) or {}
        # Refuse the bundle rather than the request. A compiled artifact can
        # come from another implementation or be edited by hand, so authoring
        # validation is not the last word; raising here means a checker never
        # comes into existence holding a policy whose binding switch is a
        # string. Failing at load is also the only place this can fail loudly
        # without turning a denial into an exception mid-decision.
        for boolean_field in _BOOLEAN_SPEC_FIELDS.get(kind, ()):
            if boolean_field in spec and not isinstance(spec[boolean_field], bool):
                raise TypeError(
                    f"Policy '{policy_id}': {boolean_field} must be a boolean, "
                    f"got {type(spec[boolean_field]).__name__}"
                )
        rules[policy_id] = PolicyRule(
            policy_id=policy_id,
            kind=kind,
            trigger=tuple(item for item in trigger if isinstance(item, str)),
            spec=spec,
        )
    return rules
