"""Runtime enforcement for declarative agent action policies."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

import yaml

from .decision import PolicyDecision

logger = logging.getLogger(__name__)


class PolicyChecker:
    """Load agent YAML files and check whether actions are permitted.

    Enforces a fail-closed security model by default.
    """

    def __init__(self, registry_dir: str = "./") -> None:
        self.registry_dir = Path(registry_dir).resolve()
        self.agents: Dict[str, Dict[str, Any]] = {}
        self._load_registry()

    def _candidate_paths(self) -> Iterable[Path]:
        """Yield YAML files from the root and agents directories.
        
        Note: 'examples/' is intentionally excluded from runtime loading 
        to prevent accidental or malicious configuration overrides.
        """
        search_paths = (
            self.registry_dir,
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
        """Load valid agent configurations, failing fast on errors."""
        for yaml_file in self._candidate_paths():
            try:
                with yaml_file.open("r", encoding="utf-8") as stream:
                    config = yaml.safe_load(stream)
                
                if not isinstance(config, dict):
                    logger.warning("Skipping %s: expected a mapping", yaml_file)
                    continue
                    
                agent_id = config.get("id")
                if not isinstance(agent_id, str) or not agent_id:
                    logger.warning("Skipping %s: 'id' must be a non-empty string", yaml_file)
                    continue
                    
                # FAIL-CLOSED: Reject duplicates to prevent silent overrides
                if agent_id in self.agents:
                    raise ValueError(
                        f"Duplicate agent ID '{agent_id}' found in {yaml_file}. "
                        "Aborting load to prevent silent override."
                    )
                
                # Default to strict enforcement
                enforcement_mode = config.get("enforcement_mode", "strict")
                if enforcement_mode not in ("strict", "permissive"):
                    logger.warning(
                        "Unknown enforcement_mode '%s' for agent '%s'. Defaulting to 'strict'.",
                        enforcement_mode, agent_id
                    )
                    enforcement_mode = "strict"

                self.agents[agent_id] = {
                    "data": config,
                    "enforcement_mode": enforcement_mode,
                    "filepath": str(yaml_file),
                }
            except ValueError:
                # Re-raise ValueError (like duplicate ID) to fail fast
                raise
            except (OSError, yaml.YAMLError) as exc:
                logger.warning("Failed to load %s: %s", yaml_file, exc)

        logger.info("Loaded %d agent configurations", len(self.agents))

    def check_action(self, agent_id: str, action: str) -> PolicyDecision:
        """Evaluate policy and return an immutable decision.
        
        Fails closed: unknown agents and actions are denied by default in strict mode.
        """
        agent_config = self.agents.get(agent_id)
        
        # FAIL-CLOSED: unknown agent = deny
        if agent_config is None:
            return PolicyDecision.deny(agent_id, action, "UNKNOWN_AGENT")
        
        mode = agent_config.get("enforcement_mode", "strict")
        allowed = agent_config["data"].get("allowed_actions") or []
        blocked = agent_config["data"].get("blocked_actions") or []
        
        # Blocklist always wins
        if action in blocked:
            policy_name = self._find_triggered_policy(agent_config, action)
            reason = "ACTION_BLOCKLISTED"
            if policy_name:
                reason += f"_VIOLATED_POLICY_{policy_name.upper()}"
            return PolicyDecision.deny(agent_id, action, reason)
        
        # In strict mode (default), only explicitly allowed actions pass
        if mode == "strict":
            if action not in allowed:
                return PolicyDecision.deny(agent_id, action, "ACTION_NOT_ALLOWLISTED")
        
        return PolicyDecision.allow(agent_id, action)

    @staticmethod
    def _find_triggered_policy(agent_config: Dict[str, Any], action: str) -> Optional[str]:
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
        """Return a copy of the loaded configuration for an agent, if it exists.
        
        Returns a copy to prevent external mutation of the registry state.
        """
        config = self.agents.get(agent_id)
        if config:
            return {
                "data": config["data"].copy(),
                "enforcement_mode": config["enforcement_mode"],
                "filepath": config["filepath"],
            }
        return None