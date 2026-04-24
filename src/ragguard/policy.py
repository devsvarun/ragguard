"""Policy engine: loads and evaluates YAML-based policy rules."""

import pathlib
from typing import List, Optional, Union
import yaml

from .models import PolicyRule, Action, Trigger


# Built-in policy paths shipped with the library
_POLICY_DIR = pathlib.Path(__file__).parent / "policies"


class BuiltinPolicy:
    """Named references to built-in policy files."""
    DEFAULT = _POLICY_DIR / "default.yaml"
    HIPAA = _POLICY_DIR / "hipaa.yaml"
    FINANCE = _POLICY_DIR / "finance.yaml"
    GDPR = _POLICY_DIR / "gdpr.yaml"


class PolicyEngine:
    """Loads and manages policy rules from YAML files."""

    def __init__(self, policy_path: Optional[Union[str, pathlib.Path]] = None):
        self.rules: List[PolicyRule] = []

        if policy_path is None:
            # Default to built-in default policy
            policy_path = BuiltinPolicy.DEFAULT

        self.load_policy(pathlib.Path(policy_path))

    def load_policy(self, policy_path: pathlib.Path) -> None:
        """Load rules from a YAML file."""
        if not policy_path.exists():
            raise FileNotFoundError(
                f"Policy file not found: {policy_path}\n"
                f"Built-in policies available: DEFAULT, HIPAA, FINANCE, GDPR"
            )

        with open(policy_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        self.rules = []
        for rule_data in data.get("rules", []):
            trigger_data = rule_data.get("trigger", {})
            trigger = Trigger(
                all_present=trigger_data.get("all_present", [])
            )
            rule = PolicyRule(
                name=rule_data["name"],
                description=rule_data.get("description", ""),
                action=Action(rule_data.get("action", "block").lower()),
                trigger=trigger,
                message=rule_data.get("message", rule_data["name"]),
            )
            self.rules.append(rule)

    def get_rules(self) -> List[PolicyRule]:
        return self.rules