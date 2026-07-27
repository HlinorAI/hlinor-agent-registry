"""Runtime enforcement for compiled declarative agent policies."""

from __future__ import annotations

import copy
import hashlib
import json
import logging
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

from ._limits import MAX_BUNDLE_BYTES, read_text_capped
from ._matching import find_block_match, find_match, request_key
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
        self.capabilities: dict[str, dict[str, Any]] = {}
        self.bundle_digest: str = ""
        self.schema_version: str = ""
        self.compiler_version: str = ""
        self.bundle_revision: int = 0
        self.policy_revision: str = ""
        self.environment: str = "development"
        self.verified_signature: VerifiedSignature | None = None
        self._bundle_snapshot: dict[str, Any] | None = None
        self._bundle_fingerprint: tuple[int, int] | None = None
        self._trust_fingerprint: str | None = None
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
            bundle = json.loads(
                read_text_capped(self.bundle_path, MAX_BUNDLE_BYTES, "Policy bundle")
            )
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

            # Coercing an unrecognized mode to "strict" would fail closed, but
            # it would also hide the fact that the bundle says something the
            # runtime does not understand. A bundle is compiler output: an
            # unknown value means the compiler and the runtime disagree, and
            # that is worth stopping for rather than papering over.
            enforcement_mode = config.get("enforcement_mode", "strict")
            if enforcement_mode not in ("strict", "permissive"):
                raise ValueError(
                    f"Invalid enforcement_mode for agent '{agent_id}': "
                    f"{enforcement_mode!r}. Expected 'strict' or 'permissive'."
                )

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

        # Capabilities are compiled into the bundle and exposed here as
        # inventory: what the bundle declares, available for inspection and
        # tooling. They are deliberately NOT consulted by evaluate(). Writing
        # them into the enforcement artifact and then leaving them unreachable
        # was the worse of the two options, and pretending they participate in
        # decisions would be worse still.
        raw_capabilities = bundle.get("capabilities", {})
        if not isinstance(raw_capabilities, dict):
            raise TypeError("Policy bundle capabilities must be an object")
        loaded_capabilities: dict[str, dict[str, Any]] = {}
        for capability_id, capability_data in raw_capabilities.items():
            if not isinstance(capability_id, str) or not capability_id:
                raise ValueError("Policy bundle contains an invalid capability ID")
            if not isinstance(capability_data, dict):
                raise TypeError(
                    f"Invalid bundle entry for capability '{capability_id}'"
                )
            loaded_capabilities[capability_id] = capability_data

        bundle_stat = self.bundle_path.stat()
        self.agents = loaded_agents
        self.capabilities = loaded_capabilities
        self.bundle_digest = bundle_digest
        self.schema_version = schema_version
        self.compiler_version = str(bundle.get("compiler_version", "unknown"))
        self.bundle_revision = revision
        self.policy_revision = str(bundle.get("policy_revision", "unknown"))
        self.environment = environment
        self.verified_signature = verified_signature
        self._bundle_snapshot = copy.deepcopy(bundle)
        self._bundle_fingerprint = (bundle_stat.st_mtime_ns, bundle_stat.st_size)
        self._trust_fingerprint = (
            self._trust_material_fingerprint()
            if verified_signature is not None and self._trust_store_path is not None
            else None
        )
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

    def _trust_material_fingerprint(self) -> str:
        """Fingerprint the files that decide whether a key is still trusted.

        Covers the trust store itself and every PEM it points at, so a revoked
        entry and a key replaced in place are both detected. A missing file
        raises, which fails closed: a verifier that cannot read its trust roots
        must not keep serving decisions from a cached copy.

        This hashes content rather than stat metadata deliberately. Ed25519
        public key PEMs are all the same length, so a rotated key changes only
        the modification time, and on a filesystem with coarse timestamp
        granularity a rotation could land inside the same tick as the value it
        replaced. Reading a trust store and a handful of small PEMs costs far
        less than the signature verification this check exists to skip.
        """
        paths: list[Path] = []
        if self._trust_store_path is not None:
            paths.append(self._trust_store_path)
        # An explicit loop rather than a filtered comprehension: mypy does not
        # reliably narrow an optional attribute inside a generator condition,
        # and `source_path` is `Path | None`.
        for key in self.trusted_keys.values():
            key_path = key.source_path
            if key_path is not None:
                paths.append(key_path)

        digest = hashlib.sha256()
        for path in sorted(set(paths)):
            digest.update(str(path).encode("utf-8"))
            digest.update(b"\0")
            digest.update(path.read_bytes())
            digest.update(b"\0")
        return digest.hexdigest()

    def _assert_runtime_trust(self) -> None:
        """Recheck time-sensitive trust constraints for a loaded snapshot.

        Two costs are separated here. Re-reading the trust store and verifying
        the Ed25519 signature over the whole bundle is what makes key
        revocation take effect, and it is also disk I/O plus a full canonical
        serialization. Doing that on every governed tool call was the dominant
        cost of an authorization. The validity window still has to be rechecked
        every time, because an expiry passes without any file changing.
        """
        if self.verified_signature is None:
            return

        if self._trust_store_path is None:
            validate_signature_window(
                self.verified_signature,
                clock_skew_seconds=self.clock_skew_seconds,
            )
            return

        if self._bundle_snapshot is None:  # pragma: no cover - invariant
            raise RuntimeError("Policy bundle snapshot is unavailable")

        fingerprint = self._trust_material_fingerprint()
        if fingerprint == self._trust_fingerprint:
            validate_signature_window(
                self.verified_signature,
                clock_skew_seconds=self.clock_skew_seconds,
            )
            return

        current_keys = self._load_configured_keys()
        current_signature = verify_bundle_signature(
            self._bundle_snapshot,
            trusted_keys=current_keys,
            required_issuer=self.required_issuer,
            clock_skew_seconds=self.clock_skew_seconds,
        )
        self.trusted_keys = current_keys
        self.verified_signature = current_signature
        self._trust_fingerprint = self._trust_material_fingerprint()

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
            "matched_pattern": decision.matched_pattern,
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
        matched_pattern: str | None = None,
    ) -> dict[str, Any]:
        signature = self.verified_signature
        return {
            "request_id": request.request_id,
            "bundle_digest": self.bundle_digest,
            "request_digest": request.request_digest,
            "matched_pattern": matched_pattern,
            # Reserved for real policy attribution. ``PolicyChecker`` is an
            # action-name gate: decisions come from the allow and block lists,
            # not from evaluating the named policies declared on an agent.
            # Emitting a guessed policy ID here would put an unverifiable claim
            # into an audit record, so the field stays empty until policy
            # evaluation exists.
            "matched_policy_ids": (),
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

        # The key an action list is matched against. Without a resource it is
        # the action alone, so an agent written before resources existed keeps
        # matching exactly as before.
        key = request_key(request.action, request.resource)

        # Block matching ignores case and allow matching does not. The
        # asymmetry is deliberate and always resolves toward denial: no
        # spelling of a blocked name gets through, and an approval is never
        # extended to a spelling nobody approved.
        blocked_by = find_block_match(blocked, request.action, key)
        if blocked_by is not None:
            return PolicyDecision.deny(
                request.agent_id,
                request.action,
                ReasonCode.ACTION_BLOCKLISTED,
                **self._decision_provenance(request, mode, blocked_by),
            )

        allowed_by = find_match(allowed, key)
        if mode == "strict" and allowed_by is None:
            return PolicyDecision.deny(
                request.agent_id,
                request.action,
                ReasonCode.ACTION_NOT_ALLOWLISTED,
                **self._decision_provenance(request, mode),
            )

        # Two different facts, recorded as two different codes. An action the
        # allow list covers was permitted by a decision someone made. An action
        # permitted in permissive mode was permitted because the policy is
        # silent about it. Recording the second as EXPLICITLY_ALLOWED puts a
        # claim in the audit record that the policy does not support.
        reason = (
            ReasonCode.EXPLICITLY_ALLOWED
            if allowed_by is not None
            else ReasonCode.ALLOWED_NOT_BLOCKLISTED
        )
        return PolicyDecision.allow(
            request.agent_id,
            request.action,
            reason,
            **self._decision_provenance(request, mode, allowed_by),
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

    def get_capability_info(self, capability_id: str) -> dict[str, Any] | None:
        """Return a declared capability, or None.

        Inventory only. A capability being present says the bundle declares it
        and that its registration passed compile-time validation. It says
        nothing about any decision: ``evaluate`` does not read this.
        """
        capability = self.capabilities.get(capability_id)
        return copy.deepcopy(capability) if capability is not None else None

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
