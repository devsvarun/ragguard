"""
ragguard — Context-aware authorization layer for RAG pipelines.

Analyzes retrieved chunks before they reach the LLM and signals
whether the combination is safe or risks data leakage.

Quick start:
    from ragguard import GuardMiddleware

    guard = GuardMiddleware()  # uses built-in default policy
    result = guard.analyze(chunks)

    if not result.is_safe:
        print(result.risk_explanation)

Using a built-in policy:
    from ragguard import GuardMiddleware, policies

    guard = GuardMiddleware(policy_path=policies.HIPAA)

With a custom classifier:
    def my_classifier(text: str) -> list[str]:
        ...  # return classification labels for this text

    guard = GuardMiddleware(classifier=my_classifier)
"""

from .guard import GuardMiddleware
from .models import AnalysisResult, Chunk, Violation, Action
from .policy import BuiltinPolicy as policies

__all__ = [
    "GuardMiddleware",
    "AnalysisResult",
    "Chunk",
    "Violation",
    "Action",
    "policies",
]

__version__ = "0.1.0"
