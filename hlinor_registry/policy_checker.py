"""Runtime enforcement for compiled declarative agent policies."""

from __future__ import annotations

import copy
import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional

from .decision import PolicyDecision

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
        registry_dir: Optional[str] = None,
    ) -> None:
        """Initialize from a bundle path.

        ``registry_dir`` is retained as a compatibility alias for callers
        migrating from the pre-0.4 API. It is interpreted as a JSON bundle
        path and is never treated as a directory.
        """
        if registry_dir is not None:
            bundle_path = registry_dir

        self.bundle_path = Path(bundle_path).resolve()
        self.agents: Dict[str, Dict[str, Any]] = {}
        self.bundle_digest: str = ""
        self._load_bundle()

    @staticmethod
    def _compute_bundle_digest(bundle: dict[str, Any]) -> str:
        """Compute the canonical digest for a bundle with its digest cleared."""
        unsigned_bundle = dict(bundle)
        unsigned_bundle["digest"] = ""
        payload = json.dumps(
            unsigned_bundle,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def _load_bundle(self) -> None:
        """Load and authenticate the compiled JSON bundle."""
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
            raise ValueError("Policy bundle root must be an object")

        bundle_digest = bundle.get("digest")
        if not isinstance(bundle_digest, str) or not bundle_digest:
            raise ValueError("Policy bundle is missing a digest")

        expected_digest = self._compute_bundle_digest(bundle)
        if bundle_digest != expected_digest:
            raise ValueError("Policy bundle digest mismatch")

        agents = bundle.get("agents")
        if not isinstance(agents, dict):
            raise ValueError("Policy bundle must contain an agents object")

        for agent_id, agent_data in agents.items():
            if not isinstance(agent_id, str) or not agent_id:
                raise ValueError("Policy bundle contains an invalid agent ID")
            if not isinstance(agent_data, dict):
                raise ValueError(f"Invalid bundle entry for agent '{agent_id}'")

            config = agent_data.get("config")
            if not isinstance(config, dict):
                raise ValueError(f"Missing config for agent '{agent_id}'")

            enforcement_mode = config.get("enforcement_mode", "strict")
            if enforcement_mode not in ("strict", "permissive"):
                enforcement_mode = "strict"

            for field in ("allowed_actions", "blocked_actions"):
                values = config.get(field, [])
                if values is not None and not isinstance(values, list):
                    raise ValueError(
                        f"Invalid {field} for agent '{agent_id}': expected a list"
                    )

            self.agents[agent_id] = {
                "data": config,
                "enforcement_mode": enforcement_mode,
                "source_path": agent_data.get("source_path", "unknown"),
                "digest": agent_data.get("digest", ""),
            }

        self.bundle_digest = bundle_digest
        logger.info(
            "Loaded %d agents from compiled bundle (digest: %s)",
            len(self.agents),
            self.bundle_digest[:8],
        )

    def check_action(self, agent_id: str, action: str) -> PolicyDecision:
        """Evaluate policy and return an immutable decision.

        Unknown agents and actions are denied by default in strict mode.
        """
        agent_config = self.agents.get(agent_id)

        if agent_config is None:
            return PolicyDecision.deny(agent_id, action, "UNKNOWN_AGENT")

        mode = agent_config.get("enforcement_mode", "strict")
        allowed = agent_config["data"].get("allowed_actions") or []
        blocked = agent_config["data"].get("blocked_actions") or []

        if action in blocked:
            policy_name = self._find_triggered_policy(agent_config, action)
            reason = "ACTION_BLOCKLISTED"
            if policy_name:
                reason += f"_VIOLATED_POLICY_{policy_name.upper()}"
            return PolicyDecision.deny(agent_id, action, reason)

        if mode == "strict" and action not in allowed:
            return PolicyDecision.deny(agent_id, action, "ACTION_NOT_ALLOWLISTED")

        return PolicyDecision.allow(agent_id, action)

    @staticmethod
    def _find_triggered_policy(
        agent_config: Dict[str, Any], action: str
    ) -> Optional[str]:
        """Map known sensitive actions to explanatory policy names."""
        policies = agent_config.get("data", {}).get("policies") or []
        policy_by_action = {
            "send_external_email": "no_pii_in_logs",
            "send_email": "no_pii_in_logs",
            "initiate_transfer": "require_human_approval_for_high_value",
        }
        policy_name = policy_by_action.get(action)
        return policy_name if policy_name in policies else None

    def get_agent_info(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Return a defensive copy of a loaded agent configuration."""
        config = self.agents.get(agent_id)
        if config:
            return {
                "data": copy.deepcopy(config["data"]),
                "enforcement_mode": config["enforcement_mode"],
                "source_path": config["source_path"],
                "digest": config["digest"],
                "bundle_digest": self.bundle_digest,
            }
        return None
