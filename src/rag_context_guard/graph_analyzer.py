"""GraphAnalyzer: detects forbidden chunk combinations using policy rules."""

import logging
from typing import List, Tuple, Dict

from .models import Chunk, PolicyRule, Violation, Action

logger = logging.getLogger(__name__)


class GraphAnalyzer:
    """
    Evaluates a set of chunks against policy rules.

    Core insight: authorization here is a SET MEMBERSHIP problem, not a graph
    traversal problem. The question is always:
      "Does the combined context window contain ALL classifications
       required to trigger a rule?"
    """

    def __init__(self, rules: List[PolicyRule]):
        self.rules = rules

    def _build_classification_map(self, chunks: List[Chunk]) -> Dict[str, Chunk]:
        """
        Build a map of classification -> chunk across all chunks.
        Supports both single-label and multi-label chunks via chunk.classifications.
        Last chunk wins if duplicate classifications exist.
        """
        classification_map: Dict[str, Chunk] = {}
        for chunk in chunks:
            for clf in chunk.classifications:
                classification_map[clf] = chunk
                logger.debug("Chunk carries '%s': %s", clf, chunk.text[:60])
        return classification_map

    def find_violations(
        self, chunks: List[Chunk]
    ) -> Tuple[List[Violation], List[Violation]]:
        """
        Check the full chunk set against every policy rule.

        A rule fires when ALL its required classifications are present
        across the chunk set — regardless of which chunk carries which label.

        Returns:
            (block_violations, warn_violations)
        """
        violations: List[Violation] = []
        warnings: List[Violation] = []

        classification_map = self._build_classification_map(chunks)
        all_classifications = set(classification_map.keys())

        logger.debug("Classifications in context window: %s", all_classifications)

        for rule in self.rules:
            required = set(rule.trigger.all_present)
            if not required:
                continue

            if required.issubset(all_classifications):
                triggering_chunks = list(
                    {
                        id(classification_map[clf]): classification_map[clf]
                        for clf in required
                        if clf in classification_map
                    }.values()
                )

                violation = Violation(
                    rule_name=rule.name,
                    message=rule.message,
                    triggering_chunks=triggering_chunks,
                    action=rule.action,
                )

                if rule.action == Action.BLOCK:
                    violations.append(violation)
                    logger.warning("BLOCK rule fired: '%s'", rule.name)
                else:
                    warnings.append(violation)
                    logger.info("WARN rule fired: '%s'", rule.name)

        return violations, warnings

    def find_forbidden_paths(
        self, chunks: List[Chunk]
    ) -> Tuple[List[Violation], List[Violation]]:
        """
        Multi-hop collusion detection.

        Detects when a shared classification bridges two rules, making the
        combined context window dangerous even if no single rule fires alone.

        Example:
            Rule A requires [financial, entity_identifier]
            Rule B requires [entity_identifier, confidential]
            If financial + entity_identifier + confidential are all present,
            entity_identifier is the bridge — both rules are jointly implicated.
        """
        violations: List[Violation] = []
        warnings: List[Violation] = []

        classification_map = self._build_classification_map(chunks)
        all_classifications = set(classification_map.keys())

        # Need at least 3 distinct classifications for a multi-hop
        if len(all_classifications) < 3:
            return violations, warnings

        seen_combinations = set()

        for bridge_clf in all_classifications:
            # Find all rules that involve this classification
            bridging_rules = [
                r for r in self.rules if bridge_clf in r.trigger.all_present
            ]
            if len(bridging_rules) < 2:
                continue

            # Collect all classifications involved across the bridging rules
            combined_required = set()
            for r in bridging_rules:
                combined_required.update(r.trigger.all_present)

            # Deduplicate — same combination may be detected via different bridges
            combo_key = frozenset(combined_required)
            if combo_key in seen_combinations:
                continue
            seen_combinations.add(combo_key)

            # Only fire if ALL combined classifications are present
            if not combined_required.issubset(all_classifications):
                continue

            triggering_chunks = list(
                {
                    id(classification_map[clf]): classification_map[clf]
                    for clf in combined_required
                    if clf in classification_map
                }.values()
            )

            violation = Violation(
                rule_name=f"multi_hop_via_{bridge_clf}",
                message=(
                    f"Multi-hop collusion via '{bridge_clf}': "
                    f"classifications {combined_required} are all present, "
                    f"bridging {len(bridging_rules)} rules."
                ),
                triggering_chunks=triggering_chunks,
                action=Action.BLOCK,
            )
            violations.append(violation)
            logger.warning("Multi-hop violation via bridge '%s'", bridge_clf)

        return violations, warnings
