"""Runtime enforcement for declarative agent action policies."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple

import yaml

logger = logging.getLogger(__name__)


class PolicyChecker:
    """Load agent YAML files and check whether actions are permitted.

    An explicit blocklist always wins. When ``allowed_actions`` is non-empty,
    it acts as an allowlist and every other action is denied. If neither list
    is present, the checker preserves the permissive behavior of the registry
    proposal and allows the action.
    """

    def __init__(self, registry_dir: str = "./") -> None:
        self.registry_dir = Path(registry_dir)
        self.agents: Dict[str, Dict[str, Any]] = {}
        self._load_registry()

    def _candidate_paths(self) -> Iterable[Path]:
        """Yield YAML files from the root, examples, and agents directories."""
        search_paths = (
            self.registry_dir,
            self.registry_dir / "examples",
            self.registry_dir / "agents",
        )
        seen = set()
        for path in search_paths:
            if not path.is_dir():
                continue
            for yaml_file in sorted((*path.glob("*.yaml"), *path.glob("*.yml"))):
                resolved = yaml_file.resolve()
                if resolved not in seen:
                    seen.add(resolved)
                    yield yaml_file

    def _load_registry(self) -> None:
        """Load valid agent configurations, logging malformed files."""
        for yaml_file in self._candidate_paths():
            try:
                with yaml_file.open("r", encoding="utf-8") as stream:
                    config = yaml.safe_load(stream)
                if not isinstance(config, dict) or not config.get("id"):
                    logger.warning("Skipping %s: expected a mapping with an id", yaml_file)
                    continue
                agent_id = config["id"]
                if not isinstance(agent_id, str):
                    logger.warning("Skipping %s: id must be a string", yaml_file)
                    continue
                if agent_id in self.agents:
                    logger.warning("Replacing duplicate agent id %r from %s", agent_id, yaml_file)
                self.agents[agent_id] = config
            except (OSError, yaml.YAMLError) as exc:
                logger.warning("Failed to load %s: %s", yaml_file, exc)

        logger.info("Loaded %d agent configurations", len(self.agents))

    def check_action(self, agent_id: str, action: str) -> Tuple[bool, str]:
        """Return ``(allowed, reason)`` for an agent/action pair."""
        agent_config = self.agents.get(agent_id)
        if agent_config is None:
            return False, f"Agent '{agent_id}' not found in the registry."

        blocked_actions = agent_config.get("blocked_actions") or []
        allowed_actions = agent_config.get("allowed_actions") or []

        if action in blocked_actions:
            policy_name = self._find_triggered_policy(agent_config, action)
            reason = f"Action '{action}' is explicitly blocked for agent '{agent_id}' (Blocklist)."
            if policy_name:
                reason += f" Violated policy: {policy_name}."
            return False, reason

        if allowed_actions:
            if action in allowed_actions:
                return True, "Action allowed (Allowlist)."
            return False, f"Action '{action}' is not in the allowed_actions list for agent '{agent_id}'."

        return True, "Action allowed (no explicit restrictions defined)."

    @staticmethod
    def _find_triggered_policy(agent_config: Dict[str, Any], action: str) -> Optional[str]:
        """Map known sensitive actions to explanatory policy names."""
        policies = agent_config.get("policies") or []
        policy_by_action = {
            "send_external_email": "no_pii_in_logs",
            "send_email": "no_pii_in_logs",
            "initiate_transfer": "require_human_approval_for_high_value",
        }
        policy_name = policy_by_action.get(action)
        return policy_name if policy_name in policies else None

    def get_agent_info(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Return the loaded configuration for an agent, if it exists."""
        return self.agents.get(agent_id)
