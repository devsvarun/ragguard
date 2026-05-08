from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Action(str, Enum):
    BLOCK = "block"
    WARN = "warn"


@dataclass
class Trigger:
    all_present: List[str] = field(default_factory=list)


@dataclass
class PolicyRule:
    name: str
    description: str
    action: Action
    trigger: Trigger
    message: str


@dataclass
class Chunk:
    """A retrieved document chunk with its metadata."""

    text: str
    meta: dict = field(default_factory=dict)

    @property
    def classifications(self) -> List[str]:
        """
        Return all classifications for this chunk as a flat list.
        Supports both:
          - meta["classification"] = "financial"                        (single string)
          - meta["classification"] = ["financial", "entity_identifier"] (list)
          - meta["classifications"] = ["financial", "entity_identifier"] (list)
        """
        # Prefer the explicit "classifications" field if present
        multi = self.meta.get("classifications")
        if multi and isinstance(multi, list):
            return multi

        # Fall back to "classification" — can be string OR list
        single = self.meta.get("classification")
        if single:
            if isinstance(single, list):
                return single
            return [single]

        return []


@dataclass
class Violation:
    rule_name: str
    message: str
    triggering_chunks: List[Chunk]
    action: Action

    def __str__(self):
        chunk_previews = [c.text[:60] + "..." for c in self.triggering_chunks]
        return (
            f"Rule '{self.rule_name}' violated ({self.action.value}): "
            f"{self.message}\n"
            f"Triggering chunks: {chunk_previews}"
        )

    def to_dict(self) -> dict:
        """Serialize violation to a plain dict."""
        return {
            "rule_name": self.rule_name,
            "message": self.message,
            "action": self.action.value,
            "triggering_chunk_count": len(self.triggering_chunks),
            "triggering_chunk_previews": [c.text[:200] for c in self.triggering_chunks],
        }


@dataclass
class AnalysisResult:
    is_safe: bool
    violations: List[Violation] = field(default_factory=list)
    warnings: List[Violation] = field(default_factory=list)
    safe_subset: List[Chunk] = field(default_factory=list)
    risk_explanation: str = ""

    def to_dict(self) -> dict:
        """Serialize result to a plain dict for JSON logging or API responses."""
        return {
            "is_safe": self.is_safe,
            "violations": [v.to_dict() for v in self.violations],
            "warnings": [w.to_dict() for w in self.warnings],
            "safe_chunk_count": len(self.safe_subset),
            "risk_explanation": self.risk_explanation,
        }
