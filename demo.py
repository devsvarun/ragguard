#!/usr/bin/env python3
"""
RagGuard Quick Demo — no external LLM required.

This demonstrates how RagGuard analyzes retrieved document chunks
and blocks queries that would combine sensitive information.
"""

import sys
import os

# Add src to path for installation-less development
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from ragguard import GuardMiddleware, policies


def main():
    print("=" * 65)
    print("RAGGUARD — Quick Demo")
    print("=" * 65)

    # Step 1: Initialize the guard with a policy
    guard = GuardMiddleware(policies.DEFAULT)
    print(f"\n[INFO] Loaded policy 'default' with {len(guard.get_rules())} rules\n")

    # Step 2: Simulate retrieved chunks from a RAG retriever
    # (In practice, these come from your vector DB + retriever)
    chunks = [
        {
            "text": "Acme Corp reported Q3 revenue of $5.2 million.",
            "meta": {"classification": "financial", "entity": "Acme Corp"},
        },
        {
            "text": "Acme Corp is a confidential client since 2020.",
            "meta": {
                "classification": ["entity_identifier", "confidential"],
                "entity": "Acme Corp",
            },
        },
        {
            "text": "The engineering team uses Kubernetes and PostgreSQL.",
            "meta": {"classification": "technology"},
        },
    ]

    print("Retrieved chunks:")
    for i, c in enumerate(chunks):
        cls = c["meta"].get("classification") or c["meta"].get(
            "classifications", "unclassified"
        )
        print(f"  [{i}] {c['text'][:55]}...")
        print(f"       classifications: {cls}")

    # Step 3: Run policy analysis
    print("\n" + "-" * 65)
    print("Analyzing for dangerous combinations...")
    print("-" * 65)

    result = guard.analyze(chunks)

    # Step 4: Report results
    print(f"\nResult: {'SAFE' if result.is_safe else 'BLOCKED'}")
    print(f"Violations: {len(result.violations)}")
    print(f"Warnings:   {len(result.warnings)}")

    if result.violations:
        print("\n[!] Policy violations detected:\n")
        for v in result.violations:
            print(f"  Rule: {v.rule_name}")
            print(f"  Message: {v.message}")
            print(f"  Involving chunks:")
            for tc in v.triggering_chunks:
                print(f"    • {tc.text[:50]}...")
            print()

    if result.warnings:
        print("\n[!] Warnings:\n")
        for w in result.warnings:
            print(f"  Rule: {w.rule_name} — {w.message}")
        print()

    if result.safe_subset:
        print(
            f"Safe subset available: {len(result.safe_subset)}/{len(chunks)} chunks\n"
        )
        print("Safe chunks (could be used for partial answer):")
        for sc in result.safe_subset:
            print(f"  • {sc.text[:50]}...")
        print()

    # Step 5: Decision
    print("=" * 65)
    print("DECISION")
    print("=" * 65)
    if not result.is_safe:
        print("""
The retrieved context contains dangerous combinations.
Recommended action:
  1. HALT — do not send to LLM, OR
  2. FILTER — answer using only the safe_subset (partial answer)
        """)
    else:
        print("""
The retrieved context is safe.
Recommended action:
  PROCEED — send full context to LLM for generation.
        """)


if __name__ == "__main__":
    main()
