"""GuardMiddleware: main entry point for rag-context-guard."""

import logging
import pathlib
from typing import Callable, Dict, List, Optional, Union

from .models import AnalysisResult, Action, Chunk
from .policy import PolicyEngine, BuiltinPolicy
from .graph_analyzer import GraphAnalyzer

logger = logging.getLogger(__name__)

# Classifier contract:
#   Takes: text (str)
#   Returns: list of classification strings (e.g. ["financial", "entity_identifier"])
#            or a single string (e.g. "financial") — both are accepted
ClassifierFn = Callable[[str], Union[List[str], Optional[str]]]


class GuardMiddleware:
    """
    Analyzes a set of RAG chunks for dangerous classification combinations
    before they reach the LLM.

    Primary usage (metadata-first — no classifier needed):
        chunks = [
            {"text": "Acme Corp revenue is $5M", "meta": {"classification": "financial"}},
            {"text": "Acme is a confidential client", "meta": {"classification": "confidential"}},
        ]
        guard = GuardMiddleware()
        result = guard.analyze(chunks)

    With a classifier (for pipelines without pre-classified metadata):
        def my_classifier(text: str) -> list[str]:
            ...
        guard = GuardMiddleware(classifier=my_classifier)
    """

    def __init__(
        self,
        policy_path: Optional[Union[str, pathlib.Path]] = None,
        classifier: Optional[ClassifierFn] = None,
    ):
        """
        Args:
            policy_path: Path to a YAML policy file, or a BuiltinPolicy path.
                         Defaults to BuiltinPolicy.DEFAULT if not provided.
            classifier:  Optional callable. Takes chunk text, returns classification
                         string(s). Only needed if chunks don't have metadata.
                         Contract: (str) -> list[str] | str | None
        """
        self.policy_engine = PolicyEngine(policy_path)
        self.analyzer = GraphAnalyzer(self.policy_engine.get_rules())
        self.classifier = classifier

    def analyze(self, chunks: List[dict]) -> AnalysisResult:
        """
        Analyze a list of chunks for dangerous combinations.

        Args:
            chunks: List of dicts with:
                - "text": the chunk content (required)
                - "meta": dict with "classification" or "classifications" (optional
                          if a classifier was provided at init)

        Returns:
            AnalysisResult with is_safe, violations, warnings, safe_subset,
            and risk_explanation.
        """
        if not isinstance(chunks, list):
            raise TypeError(f"chunks must be a list, got {type(chunks).__name__}")

        typed_chunks = self._prepare_chunks(chunks)

        violations, warnings = self.analyzer.find_violations(typed_chunks)
        path_violations, path_warnings = self.analyzer.find_forbidden_paths(
            typed_chunks
        )

        all_violations = violations + path_violations
        all_warnings = warnings + path_warnings
        is_safe = len(all_violations) == 0

        # Build safe_subset — chunks not involved in any BLOCK violation
        violating_texts = {c.text for v in all_violations for c in v.triggering_chunks}
        safe_subset = [c for c in typed_chunks if c.text not in violating_texts]

        return AnalysisResult(
            is_safe=is_safe,
            violations=all_violations,
            warnings=all_warnings,
            safe_subset=safe_subset,
            risk_explanation="\n\n".join(str(v) for v in all_violations),
        )

    def _prepare_chunks(self, raw_chunks: List[dict]) -> List[Chunk]:
        """Convert raw dicts to Chunk objects, applying classifier if provided."""
        typed = []
        for item in raw_chunks:
            text = item.get("text", "")
            meta_raw = item.get("meta")
            meta = dict(meta_raw) if meta_raw else {}

            # Only call classifier if chunk has no existing classification
            if self.classifier is not None and not self._has_classification(meta):
                result = self.classifier(text)
                if result:
                    if isinstance(result, str):
                        meta["classification"] = result
                    elif isinstance(result, list):
                        # Filter out "safe" — it's a no-op label
                        labels = [r for r in result if r and r != "safe"]
                        if labels:
                            meta["classifications"] = labels
                            meta["classification"] = labels[0]  # primary

            typed.append(Chunk(text=text, meta=meta))
        return typed

    @staticmethod
    def _has_classification(meta: dict) -> bool:
        """Check if metadata already carries classification info."""
        return bool(meta.get("classification") or meta.get("classifications"))

    def get_rules(self):
        """Return the active policy rules."""
        return self.policy_engine.get_rules()
