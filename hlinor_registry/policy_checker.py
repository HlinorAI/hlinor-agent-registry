"""Runtime enforcement for compiled declarative agent policies."""

from __future__ import annotations

import copy
import json
import logging
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

from .action_request import ActionRequest
from .decision import PolicyDecision
from .enums import ReasonCode
from .signing import (
    TrustedKey,
    VerifiedSignature,
    compute_bundle_digest,
    load_trust_store,
    normalize_trusted_keys,
    validate_signature_window,
    verify_bundle_signature,
)

logger = logging.getLogger(__name__)


class PolicyChecker:
    """Load a compiled policy bundle and check whether actions are permitted.

    The checker intentionally reads one immutable JSON bundle. It never scans
    directories or loads YAML files at runtime. The bundle digest is verified
    before any agent configuration becomes available for enforcement.
    """

    def __init__(
        self,
        bundle_path: str = "./dist/policy-bundle.json",
        *,
        registry_dir: str | None = None,
        trust_store: str | None = None,
        trusted_keys: Mapping[str, TrustedKey | str | bytes | Path] | None = None,
        signature_policy: Literal["auto", "required", "optional"] = "auto",
        required_issuer: str | None = None,
        minimum_bundle_revision: int = 0,
        clock_skew_seconds: int = 60,
    ) -> None:
        """Initialize from a bundle path.

        ``registry_dir`` is retained as a compatibility alias for callers
        migrating from the pre-0.4 API. It is interpreted as a JSON bundle
        path and is never treated as a directory.
        """
        if registry_dir is not None:
            bundle_path = registry_dir
        if signature_policy not in {"auto", "required", "optional"}:
            raise ValueError(
                "signature_policy must be 'auto', 'required', or 'optional'"
            )
        if (
            not isinstance(minimum_bundle_revision, int)
            or isinstance(minimum_bundle_revision, bool)
            or minimum_bundle_revision < 0
        ):
            raise ValueError("minimum_bundle_revision must be a non-negative integer")
        if (
            not isinstance(clock_skew_seconds, int)
            or isinstance(clock_skew_seconds, bool)
            or clock_skew_seconds < 0
        ):
            raise ValueError("clock_skew_seconds must be a non-negative integer")

        self.bundle_path = Path(bundle_path).resolve()
        self._trust_store_path = (
            Path(trust_store).resolve() if trust_store is not None else None
        )
        self._programmatic_keys = normalize_trusted_keys(trusted_keys)
        self.trusted_keys = self._load_configured_keys()
        # A deployment that configured trust roots expects signed bundles. Under
        # "auto" the signature requirement would otherwise be derived from
        # ``metadata.environment`` inside the very artifact being verified, so an
        # attacker who can rewrite the bundle could strip the signature and
        # downgrade the declared environment to disable authentication entirely.
        self.signature_policy: Literal["auto", "required", "optional"] = (
            "required"
            if signature_policy == "auto" and self.trusted_keys
            else signature_policy
        )
        self.required_issuer = required_issuer
        self.minimum_bundle_revision = minimum_bundle_revision
        self.clock_skew_seconds = clock_skew_seconds
        self.agents: dict[str, dict[str, Any]] = {}
        self.bundle_digest: str = ""
        self.schema_version: str = ""
        self.compiler_version: str = ""
        self.bundle_revision: int = 0
        self.policy_revision: str = ""
        self.environment: str = "development"
        self.verified_signature: VerifiedSignature | None = None
        self._bundle_snapshot: dict[str, Any] | None = None
        self._bundle_fingerprint: tuple[int, int] | None = None
        self._load_bundle()

    def _load_configured_keys(self) -> dict[str, TrustedKey]:
        configured_keys = dict(self._programmatic_keys)
        if self._trust_store_path is not None:
            trust_store_keys = load_trust_store(self._trust_store_path)
            duplicate_keys = set(configured_keys).intersection(trust_store_keys)
            if duplicate_keys:
                raise ValueError(f"Duplicate trusted key IDs: {sorted(duplicate_keys)}")
            configured_keys.update(trust_store_keys)
        return configured_keys

    @staticmethod
    def _compute_bundle_digest(bundle: dict[str, Any]) -> str:
        """Compute the canonical digest for a bundle with its digest cleared."""
        return compute_bundle_digest(bundle)

    def _load_bundle(self) -> None:
        """Load and integrity-check the compiled JSON bundle."""
        if not self.bundle_path.is_file():
            raise FileNotFoundError(
                f"Policy bundle not found at {self.bundle_path}. "
                "Run `hlinor-registry compile` first."
            )

        try:
            with self.bundle_path.open("r", encoding="utf-8") as stream:
                bundle = json.load(stream)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in policy bundle: {exc}") from exc

        if not isinstance(bundle, dict):
            raise TypeError("Policy bundle root must be an object")

        schema_version = bundle.get("schema_version", bundle.get("version"))
        if not isinstance(schema_version, str) or not schema_version.strip():
            raise ValueError("Policy bundle is missing a schema version")
        schema_major = schema_version.split(".", maxsplit=1)[0]
        if not schema_major.isdigit() or int(schema_major) != 1:
            raise ValueError(f"Unsupported policy bundle schema: {schema_version}")

        bundle_digest = bundle.get("digest")
        if not isinstance(bundle_digest, str) or not bundle_digest:
            raise ValueError("Policy bundle is missing a digest")

        expected_digest = self._compute_bundle_digest(bundle)
        if bundle_digest != expected_digest:
            raise ValueError("Policy bundle digest mismatch")

        metadata = bundle.get("metadata", {})
        if not isinstance(metadata, dict):
            raise TypeError("Policy bundle metadata must be an object")
        environment = metadata.get("environment", "development")
        if not isinstance(environment, str) or not environment.strip():
            raise ValueError("Policy bundle environment must be a non-empty string")

        revision = bundle.get("bundle_revision", 0)
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
            raise ValueError("Policy bundle revision must be a positive integer")
        if revision < self.minimum_bundle_revision:
            raise ValueError(
                f"Policy bundle revision {revision} is below the trusted minimum "
                f"{self.minimum_bundle_revision}"
            )

        signature = bundle.get("signature")
        verified_signature: VerifiedSignature | None = None
        if signature is not None:
            verified_signature = verify_bundle_signature(
                bundle,
                trusted_keys=self.trusted_keys,
                required_issuer=self.required_issuer,
                clock_skew_seconds=self.clock_skew_seconds,
            )
        elif self.signature_policy == "required":
            raise ValueError("Policy bundle signature is required")
        elif self.signature_policy == "auto" and environment.casefold() not in {
            "development",
            "test",
            "local",
        }:
            raise ValueError(
                "Unsigned policy bundles are allowed only in development, test, "
                "or local environments; use signature_policy='optional' only as "
                "an explicit unsafe override"
            )

        agents = bundle.get("agents")
        if not isinstance(agents, dict):
            raise TypeError("Policy bundle must contain an agents object")

        loaded_agents: dict[str, dict[str, Any]] = {}
        for agent_id, agent_data in agents.items():
            if not isinstance(agent_id, str) or not agent_id:
                raise ValueError("Policy bundle contains an invalid agent ID")
            if not isinstance(agent_data, dict):
                raise TypeError(f"Invalid bundle entry for agent '{agent_id}'")

            config = agent_data.get("config")
            if not isinstance(config, dict):
                raise TypeError(f"Missing config for agent '{agent_id}'")

            enforcement_mode = config.get("enforcement_mode", "strict")
            if enforcement_mode not in ("strict", "permissive"):
                enforcement_mode = "strict"

            for field in ("allowed_actions", "blocked_actions"):
                values = config.get(field, [])
                if values is not None and not isinstance(values, list):
                    raise ValueError(
                        f"Invalid {field} for agent '{agent_id}': expected a list"
                    )

            loaded_agents[agent_id] = {
                "data": config,
                "enforcement_mode": enforcement_mode,
                "source_path": agent_data.get("source_path", "unknown"),
                "digest": agent_data.get("digest", ""),
            }

        bundle_stat = self.bundle_path.stat()
        self.agents = loaded_agents
        self.bundle_digest = bundle_digest
        self.schema_version = schema_version
        self.compiler_version = str(bundle.get("compiler_version", "unknown"))
        self.bundle_revision = revision
        self.policy_revision = str(bundle.get("policy_revision", "unknown"))
        self.environment = environment
        self.verified_signature = verified_signature
        self._bundle_snapshot = copy.deepcopy(bundle)
        self._bundle_fingerprint = (bundle_stat.st_mtime_ns, bundle_stat.st_size)
        logger.info(
            "Loaded %d agents from compiled bundle (digest: %s)",
            len(self.agents),
            self.bundle_digest[:8],
        )

    def reload_if_changed(self) -> bool:
        """Reload the bundle when its on-disk fingerprint changes.

        A reload is atomic from the caller's perspective: a new bundle must
        pass digest verification before replacing the active policy set.
        """
        if not self.bundle_path.is_file():
            raise FileNotFoundError(
                f"Policy bundle not found at {self.bundle_path}. "
                "Run `hlinor-registry compile` first."
            )

        bundle_stat = self.bundle_path.stat()
        fingerprint = (bundle_stat.st_mtime_ns, bundle_stat.st_size)
        if fingerprint == self._bundle_fingerprint:
            self._assert_runtime_trust()
            return False

        self._load_bundle()
        return True

    def _assert_runtime_trust(self) -> None:
        """Recheck time-sensitive trust constraints for a loaded snapshot."""
        if self.verified_signature is not None:
            if self._trust_store_path is not None:
                if self._bundle_snapshot is None:  # pragma: no cover - invariant
                    raise RuntimeError("Policy bundle snapshot is unavailable")
                current_keys = self._load_configured_keys()
                current_signature = verify_bundle_signature(
                    self._bundle_snapshot,
                    trusted_keys=current_keys,
                    required_issuer=self.required_issuer,
                    clock_skew_seconds=self.clock_skew_seconds,
                )
                self.trusted_keys = current_keys
                self.verified_signature = current_signature
            else:
                validate_signature_window(
                    self.verified_signature,
                    clock_skew_seconds=self.clock_skew_seconds,
                )

    def audit_event(self, decision: PolicyDecision) -> dict[str, Any]:
        """Return a structured, provenance-aware record for a decision."""
        return {
            "schema_version": "1.1",
            "event_type": "policy_decision",
            "timestamp": decision.checked_at,
            "decision_id": decision.decision_id,
            "request_id": decision.request_id,
            "agent_id": decision.agent_id,
            "action": decision.action,
            "result": decision.result,
            "reason_code": decision.reason_code,
            "policy_bundle_digest": decision.bundle_digest,
            "request_digest": decision.request_digest,
            "matched_policy_ids": list(decision.matched_policy_ids),
            "enforcement_mode": decision.enforcement_mode,
            "environment": decision.environment,
            "actor_id": decision.actor_id,
            "bundle_schema_version": decision.bundle_schema_version,
            "compiler_version": decision.compiler_version,
            "bundle_revision": decision.bundle_revision,
            "policy_revision": decision.policy_revision,
            "signature_key_id": decision.signature_key_id,
            "signature_key_fingerprint": decision.signature_key_fingerprint,
            "signature_issuer": decision.signature_issuer,
            "signature_issued_at": decision.signature_issued_at,
            "signature_expires_at": decision.signature_expires_at,
        }

    def _decision_provenance(
        self,
        request: ActionRequest,
        enforcement_mode: str,
        matched_policy_ids: tuple[str, ...] = (),
    ) -> dict[str, Any]:
        signature = self.verified_signature
        return {
            "request_id": request.request_id,
            "bundle_digest": self.bundle_digest,
            "request_digest": request.request_digest,
            "matched_policy_ids": matched_policy_ids,
            "enforcement_mode": enforcement_mode,
            "environment": request.environment or self.environment,
            "actor_id": request.actor_id,
            "bundle_schema_version": self.schema_version,
            "compiler_version": self.compiler_version,
            "bundle_revision": self.bundle_revision,
            "policy_revision": self.policy_revision,
            "signature_key_id": signature.key_id if signature else None,
            "signature_key_fingerprint": (
                signature.key_fingerprint if signature else None
            ),
            "signature_issuer": signature.issuer if signature else None,
            "signature_issued_at": signature.issued_at if signature else None,
            "signature_expires_at": signature.expires_at if signature else None,
        }

    def evaluate(self, request: ActionRequest) -> PolicyDecision:
        """Evaluate one immutable request against the active bundle snapshot.

        Unknown agents and actions are denied by default in strict mode.
        """
        self._assert_runtime_trust()
        agent_config = self.agents.get(request.agent_id)

        if agent_config is None:
            return PolicyDecision.deny(
                request.agent_id,
                request.action,
                ReasonCode.UNKNOWN_AGENT,
                **self._decision_provenance(request, "strict"),
            )

        mode = agent_config.get("enforcement_mode", "strict")
        allowed = agent_config["data"].get("allowed_actions") or []
        blocked = agent_config["data"].get("blocked_actions") or []

        if request.action in blocked:
            matched_policy_ids = self._matched_policy_ids(agent_config, request.action)
            return PolicyDecision.deny(
                request.agent_id,
                request.action,
                ReasonCode.ACTION_BLOCKLISTED,
                **self._decision_provenance(request, mode, matched_policy_ids),
            )

        if mode == "strict" and request.action not in allowed:
            return PolicyDecision.deny(
                request.agent_id,
                request.action,
                ReasonCode.ACTION_NOT_ALLOWLISTED,
                **self._decision_provenance(request, mode),
            )

        return PolicyDecision.allow(
            request.agent_id,
            request.action,
            **self._decision_provenance(request, mode),
        )

    def check_action(self, agent_id: str, action: str) -> PolicyDecision:
        """Compatibility wrapper for action-only callers.

        New integrations should construct an ActionRequest and call evaluate().
        """
        request = ActionRequest(
            agent_id=agent_id,
            action=action,
            environment=self.environment,
        )
        return self.evaluate(request)

    @staticmethod
    def _matched_policy_ids(
        agent_config: dict[str, Any], action: str
    ) -> tuple[str, ...]:
        """Map known sensitive actions to declared explanatory policy IDs."""
        policies = agent_config.get("data", {}).get("policies") or []
        policy_by_action = {
            "send_external_email": "no_pii_in_logs",
            "send_email": "no_pii_in_logs",
            "initiate_transfer": "require_human_approval_for_high_value",
        }
        policy_name = policy_by_action.get(action)
        if policy_name is not None and policy_name in policies:
            return (policy_name,)
        return ()

    def get_agent_info(self, agent_id: str) -> dict[str, Any] | None:
        """Return a defensive copy of a loaded agent configuration."""
        config = self.agents.get(agent_id)
        if config:
            return {
                "data": copy.deepcopy(config["data"]),
                "enforcement_mode": config["enforcement_mode"],
                "source_path": config["source_path"],
                "digest": config["digest"],
                "bundle_digest": self.bundle_digest,
                "schema_version": self.schema_version,
                "compiler_version": self.compiler_version,
                "bundle_revision": self.bundle_revision,
                "policy_revision": self.policy_revision,
                "environment": self.environment,
                "signature_key_id": (
                    self.verified_signature.key_id
                    if self.verified_signature is not None
                    else None
                ),
                "signature_key_fingerprint": (
                    self.verified_signature.key_fingerprint
                    if self.verified_signature is not None
                    else None
                ),
                "signature_issuer": (
                    self.verified_signature.issuer
                    if self.verified_signature is not None
                    else None
                ),
                "signature_issued_at": (
                    self.verified_signature.issued_at
                    if self.verified_signature is not None
                    else None
                ),
                "signature_expires_at": (
                    self.verified_signature.expires_at
                    if self.verified_signature is not None
                    else None
                ),
            }
        return None
