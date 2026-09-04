"""Portable correlation context hooks for governed agent operations.

The module intentionally has no OpenTelemetry SDK dependency.  It carries
validated correlation identifiers across adapters and receipts; it does not
export spans, collect telemetry, authorize work, or identify a workload.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ._limits import MAX_SOURCE_BYTES, read_text_capped

CORRELATION_SCHEMA_VERSION = "1.0"
CORRELATION_FIXTURE_TYPE = "observability_correlation"
_HEX_ID = re.compile(r"^[0-9a-f]+$")
_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_TRACE_ID_LENGTH = 32
_SPAN_ID_LENGTH = 16
_FIXTURE_FIELDS = {
    "schema_version",
    "type",
    "id",
    "trace_id",
    "span_id",
    "run_id",
    "parent_id",
    "attributes",
}


class CorrelationValidationError(ValueError):
    """Raised when correlation metadata is missing, malformed, or collides."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


def _validate_hex_id(value: object, field: str, length: int) -> str:
    if (
        not isinstance(value, str)
        or len(value) != length
        or _HEX_ID.fullmatch(value) is None
        or int(value, 16) == 0
    ):
        raise CorrelationValidationError(
            "CORRELATION_ID_INVALID",
            f"{field} must be a non-zero lowercase {length}-character hex ID",
        )
    return value


def _validate_run_id(value: object) -> str:
    if not isinstance(value, str) or _RUN_ID.fullmatch(value) is None:
        raise CorrelationValidationError(
            "CORRELATION_RUN_ID_INVALID",
            "run_id must be 1-128 ASCII characters without outer whitespace",
        )
    return value


@dataclass(frozen=True, slots=True)
class CorrelationContext:
    """Validated identifiers for one trace and one governed run.

    ``parent_id`` is an opaque caller correlation identifier.  It is useful
    for joining a child operation to its caller, but it is never an approval,
    delegation, identity, or policy signal.
    """

    trace_id: str
    span_id: str
    run_id: str
    parent_id: str | None = None

    def __post_init__(self) -> None:
        _validate_hex_id(self.trace_id, "trace_id", _TRACE_ID_LENGTH)
        _validate_hex_id(self.span_id, "span_id", _SPAN_ID_LENGTH)
        _validate_run_id(self.run_id)
        if self.parent_id is not None:
            _validate_run_id(self.parent_id)

    def as_attributes(self) -> dict[str, str]:
        """Return stable namespaced attributes for logs or span adapters."""
        attributes = {
            "hlinor.correlation.trace_id": self.trace_id,
            "hlinor.correlation.span_id": self.span_id,
            "hlinor.correlation.run_id": self.run_id,
        }
        if self.parent_id is not None:
            attributes["hlinor.correlation.parent_id"] = self.parent_id
        return attributes

    def as_receipt_fields(self) -> dict[str, str]:
        """Return correlation fields safe to merge into one execution receipt."""
        fields = {
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "run_id": self.run_id,
        }
        if self.parent_id is not None:
            fields["parent_id"] = self.parent_id
        return fields


def validate_correlation_context(value: object) -> CorrelationContext:
    """Require a context object instead of accepting caller-shaped mappings."""
    if not isinstance(value, CorrelationContext):
        raise CorrelationValidationError(
            "CORRELATION_CONTEXT_INVALID",
            "correlation must be a CorrelationContext instance",
        )
    return value


def attach_correlation_fields(
    fields: Mapping[str, Any], context: CorrelationContext
) -> dict[str, Any]:
    """Copy fields and add correlation IDs without allowing overwrite."""
    correlation = validate_correlation_context(context)
    result = dict(fields)
    for name, value in correlation.as_receipt_fields().items():
        if name in result and result[name] != value:
            raise CorrelationValidationError(
                "CORRELATION_FIELD_COLLISION",
                f"{name} already contains a different correlation value",
            )
        result[name] = value
    return result


def validate_correlation_fixture(data: Mapping[str, Any]) -> CorrelationContext:
    """Validate a portable YAML/JSON fixture and return its context."""
    if not isinstance(data, Mapping):
        raise CorrelationValidationError(
            "CORRELATION_FIXTURE_INVALID", "fixture must be an object"
        )
    unknown = set(data).difference(_FIXTURE_FIELDS)
    if unknown:
        raise CorrelationValidationError(
            "CORRELATION_FIXTURE_UNKNOWN_FIELD",
            f"fixture has unknown fields: {sorted(unknown)}",
        )
    required = {"schema_version", "type", "id", "trace_id", "span_id", "run_id"}
    missing = required.difference(data)
    if missing:
        raise CorrelationValidationError(
            "CORRELATION_FIXTURE_REQUIRED_FIELD_MISSING",
            f"fixture is missing fields: {sorted(missing)}",
        )
    if data["schema_version"] != CORRELATION_SCHEMA_VERSION:
        raise CorrelationValidationError(
            "CORRELATION_FIXTURE_VERSION_UNSUPPORTED",
            f"expected {CORRELATION_SCHEMA_VERSION}",
        )
    if data["type"] != CORRELATION_FIXTURE_TYPE:
        raise CorrelationValidationError(
            "CORRELATION_FIXTURE_TYPE_INVALID",
            "fixture.type is not supported",
        )
    _validate_run_id(data["id"])
    context = CorrelationContext(
        trace_id=data["trace_id"],
        span_id=data["span_id"],
        run_id=data["run_id"],
        parent_id=data.get("parent_id"),
    )
    if "attributes" in data:
        attributes = data["attributes"]
        if (
            not isinstance(attributes, Mapping)
            or dict(attributes) != context.as_attributes()
        ):
            raise CorrelationValidationError(
                "CORRELATION_ATTRIBUTES_MISMATCH",
                "fixture.attributes must exactly match the context attributes",
            )
    return context


def load_correlation_fixture(path: str | Path) -> CorrelationContext:
    """Load and validate one portable correlation fixture."""
    try:
        data = yaml.safe_load(
            read_text_capped(Path(path), MAX_SOURCE_BYTES, "correlation fixture")
        )
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise CorrelationValidationError(
            "CORRELATION_FIXTURE_UNREADABLE",
            "fixture is missing or not valid YAML/JSON",
        ) from exc
    return validate_correlation_fixture(data)


__all__ = [
    "CORRELATION_FIXTURE_TYPE",
    "CORRELATION_SCHEMA_VERSION",
    "CorrelationContext",
    "CorrelationValidationError",
    "attach_correlation_fields",
    "load_correlation_fixture",
    "validate_correlation_context",
    "validate_correlation_fixture",
]
