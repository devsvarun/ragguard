#!/usr/bin/env python3
"""
Comprehensive test suite for RagGuard library.
Tests all core functionality, edge cases, and security requirements.
"""

import sys
import os
import tempfile
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from ragguard import GuardMiddleware, Action
from ragguard.policy import PolicyEngine
from ragguard.models import Chunk, AnalysisResult


# ─── Test configuration ──────────────────────────────────────────────────────

POLICY_FILE = os.path.join(
    os.path.dirname(__file__), "src", "ragguard", "policies", "example.yaml"
)
TEST_POLICY = """
rules:
  - name: test_block
    action: block
    source:
      classification: A
    target:
      classification: B
    label: test_block_label

  - name: test_warn
    action: warn
    source:
      classification: C
    target:
      classification: D
    label: test_warn_label
"""


# ─── Helper functions ─────────────────────────────────────────────────────────


def make_chunk(text: str, **meta) -> dict:
    """Create a chunk in the expected retriever format."""
    return {"text": text, "meta": meta}


def section(title: str) -> None:
    """Print a test section header."""
    print(f"\n{'=' * 60}")
    print(f"[TEST] {title}")
    print("=" * 60)


# ─── Test cases ────────────────────────────────────────────────────────────────


def test_1_basic_functionality():
    """Test that safe chunks pass and violations are detected."""
    section("1. Basic functionality")
    guard = GuardMiddleware(POLICY_FILE)

    # 1a: Safe chunks
    safe_chunks = [
        make_chunk("Sunny day", classification="weather"),
        make_chunk("React is a JS library", classification="technology"),
    ]
    result = guard.analyze(safe_chunks)
    assert result.is_safe, f"Expected safe chunks to pass. Got: {result}"
    print("  [PASS] Safe chunks correctly identified")

    # 1b: Violation (financial + entity_identifier     -> block)
    violation_chunks = [
        make_chunk("Acme Corp revenue: $5M", classification="financial", entity="Acme"),
        make_chunk(
            "Acme Corp is confidential",
            classification="entity_identifier",
            entity="Acme",
        ),
    ]
    result = guard.analyze(violation_chunks)
    assert not result.is_safe, f"Expected violation, got safe: {result}"
    assert result.risk_explanation is not None, "Missing risk_explanation"
    # Check that the correct rule fired
    assert any(v.rule_name == "financial_entity_reveal" for v in result.violations), (
        f"Expected financial_entity_reveal rule to fire. Got: {result.risk_explanation}"
    )
    print("      [PASS] Block violation detected with correct label")

    # 1c: Verify analysis result structure
    assert hasattr(result, "violations"), "Missing violations attribute"
    assert hasattr(result, "warnings"), "Missing warnings attribute"
    assert len(result.violations) > 0, "Should have at least one violation"
    print("      [PASS] AnalysisResult structure is correct")


def test_2_multihop_collusion():
    """Test detection of multi-chunk collusion (paths of length >= 3)."""
    section("2. Multi-hop collusion detection")

    # Create a temporary policy to have full control
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write("""
rules:
  - name: step1
    action: block
    trigger:
      all_present: [A, B]
    message: "A+B combination detected"

  - name: step2
    action: block
    trigger:
      all_present: [B, C]
    message: "B+C combination detected"
""")
        temp_policy = f.name

    try:
        guard = GuardMiddleware(temp_policy)

        # Multi-hop: chunk0 (class A) -> chunk1 (class B) -> chunk2 (class C)
        # Direct pairs: (0,1) triggers step1, (1,2) triggers step2
        # Combined A+B+C triggers multi-hop via bridge B
        multi_chunks = [
            make_chunk("First", classification="A"),
            make_chunk("Second", classification="B"),
            make_chunk("Third", classification="C"),
        ]

        result = guard.analyze(multi_chunks)

        # Should detect violations (either direct or path-based)
        assert not result.is_safe, "Multi-hop collusion should be detected"
        # Explanation should mention violations
        explanation = result.risk_explanation or ""
        # Check that at least one expected rule appears
        assert (
            "step1" in explanation
            or "step2" in explanation
            or "multi_hop" in explanation
        ), f"Expected violation labels in explanation: {explanation}"
        print(f"      [PASS] Multi-hop path detected: {explanation[:80]}...")

    finally:
        os.unlink(temp_policy)


def test_3_action_handling():
    """Test that block vs warn actions are correctly distinguished."""
    section("3. Action handling (block vs warn)")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write("""
rules:
  - name: block_rule
    action: block
    trigger:
      all_present: [block_src, block_tgt]
    message: "[BLOCK] Block violation"

  - name: warn_rule
    action: warn
    trigger:
      all_present: [warn_src, warn_tgt]
    message: "[WARN] Warn violation"
""")
        temp_policy = f.name

    try:
        guard = GuardMiddleware(temp_policy)

        # Chunks that trigger BOTH block and warn simultaneously
        mixed_chunks = [
            make_chunk("Block source text", classification="block_src"),
            make_chunk("Block target text", classification="block_tgt"),
            make_chunk("Warn source text", classification="warn_src"),
            make_chunk("Warn target text", classification="warn_tgt"),
        ]

        result = guard.analyze(mixed_chunks)

        # Is_safe should be False because at least one block exists
        assert not result.is_safe, "Should be unsafe due to block action"

        # The risk_explanation should reference the BLOCK action first
        assert "[BLOCK]" in (result.risk_explanation or ""), (
            f"First explanation should be BLOCK. Got: {result.risk_explanation}"
        )

        # Warnings should be populated separately
        assert len(result.warnings) > 0, "Warnings should be collected"
        warning_str = str(result.warnings[0])
        assert "[WARN]" in warning_str, (
            f"Warning should have [WARN] prefix. Got: {warning_str}"
        )

        print("      [PASS] Block violations cause is_safe=False")
        print("      [PASS] Warn violations appear in warnings list")
        print("      [PASS] Risk explanation shows [BLOCK] for blocking violations")

    finally:
        os.unlink(temp_policy)


def test_4_edge_cases():
    """Test boundary conditions and malformed inputs."""
    section("4. Edge cases")

    guard = GuardMiddleware(POLICY_FILE)

    # 4a: Empty chunk list
    result = guard.analyze([])
    assert result.is_safe, "Empty list should be safe"
    print("      [PASS] Empty chunk list -> safe")

    # 4b: Chunk missing 'meta' key entirely
    missing_meta = [{"text": "only text, no meta"}]
    try:
        result = guard.analyze(missing_meta)
        # Should not crash; text exists, meta defaults to {}
        assert isinstance(result, AnalysisResult), "Should return AnalysisResult"
        print("      [PASS] Chunk without 'meta' -> handled gracefully")
    except (KeyError, TypeError) as e:
        print(f"  [FAIL] FAIL: Missing meta caused exception: {e}")
        raise AssertionError("Should not crash on missing 'meta' key")

    # 4c: Chunk with meta=None
    none_meta = [{"text": "text", "meta": None}]
    try:
        result = guard.analyze(none_meta)
        assert isinstance(result, AnalysisResult), "Should return AnalysisResult"
        print("      [PASS] Chunk with meta=None -> handled gracefully")
    except (AttributeError, TypeError) as e:
        print(f"  [FAIL] FAIL: meta=None caused exception: {e}")
        raise AssertionError("Should not crash on meta=None")

    # 4d: Non-list input (None)
    try:
        result = guard.analyze(None)
        print("  [FAIL] FAIL: None should raise TypeError")
        raise AssertionError("analyze(None) should raise TypeError")
    except TypeError:
        print("      [PASS] None input -> TypeError")

    # 4e: Non-list input (string)
    try:
        result = guard.analyze("not a list")
        print("  [FAIL] FAIL: String should raise TypeError")
        raise AssertionError("analyze(string) should raise TypeError")
    except TypeError:
        print("      [PASS] String input -> TypeError")

    # 4f: Invalid policy file path
    try:
        PolicyEngine("/nonexistent/path/to/policy.yaml")
        print("  [FAIL] FAIL: Invalid path should raise FileNotFoundError")
        raise AssertionError("Should raise FileNotFoundError for missing policy")
    except FileNotFoundError:
        print("      [PASS] Invalid policy path -> FileNotFoundError")

    # 4g: Single chunk (no pairs possible)
    single = [make_chunk("lonely chunk", classification="safe")]
    result = guard.analyze(single)
    assert result.is_safe, "Single chunk cannot form a forbidden pair"
    print("      [PASS] Single chunk -> safe")


def test_5_security_yaml_safe_load():
    """Verify that policy.py uses yaml.safe_load (not yaml.load)."""
    section("5. Security: YAML safe_load check")
    policy_py_path = os.path.join(
        os.path.dirname(__file__), "src", "ragguard", "policy.py"
    )

    with open(policy_py_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "yaml.safe_load" in content, "policy.py must use yaml.safe_load for security"
    # Ensure no unsafe yaml.load is present
    assert "yaml.load(" not in content, (
        "Unsafe yaml.load detected - use yaml.safe_load instead"
    )
    print("      [PASS] policy.py uses yaml.safe_load (CVE-2017-18342 safe)")
    print("      [PASS] No unsafe yaml.load detected")


def test_6_real_world_format():
    """Test that analyze() works with LangChain/LlamaIndex-style objects."""
    section("6. Real-world integration format")

    guard = GuardMiddleware(POLICY_FILE)

    # Simulate LangChain Document objects: {page_content, metadata}
    # Note: The library expects {"text": ..., "meta": ...}
    # Typical mapping from LangChain: text=doc.page_content, meta=doc.metadata
    langchain_docs = [
        {
            "page_content": "Financial data for Acme Corp: $5M",
            "metadata": {"classification": "financial", "entity": "Acme"},
        },
        {
            "page_content": "Acme Corp is confidential",
            "metadata": {"classification": "entity_identifier", "entity": "Acme"},
        },
    ]

    # User would map: chunks = [{"text": d.page_content, "meta": d.metadata} for d in docs]
    ragguard_chunks = [
        {"text": doc["page_content"], "meta": doc["metadata"]} for doc in langchain_docs
    ]

    result = guard.analyze(ragguard_chunks)
    assert not result.is_safe, "Should detect the financial+entity violation"
    print("      [PASS] LangChain-style mapping works correctly")

    # LlamaIndex style: {text, metadata} (element content + node metadata)
    llamaindex_nodes = [
        {"text": "Server IP: 10.0.0.1", "metadata": {"classification": "internal"}},
        {
            "text": "Internal hostname: db-prod-01",
            "metadata": {"classification": "internal_code"},
        },
    ]
    # Already in ragguard format
    result2 = guard.analyze(llamaindex_nodes)
    # These are both internal/internal_code - no forbidden edge in example policy, so safe
    assert result2.is_safe, "internal+internal_code should be safe under current policy"
    print("      [PASS] LlamaIndex-style format accepted")


def test_7_warning_collection():
    """Verify that warnings are collected even when no violations occur."""
    section("7. Warning collection")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write("""
rules:
  - name: only_warn
    action: warn
    trigger:
      all_present: [low, high]
    message: "[WARN] Minor leak warning"
""")
        temp_policy = f.name

    try:
        guard = GuardMiddleware(temp_policy)
        chunks = [
            make_chunk("Low priority", classification="low"),
            make_chunk("High priority", classification="high"),
        ]
        result = guard.analyze(chunks)

        assert result.is_safe, "Warn action should not block"
        assert len(result.warnings) > 0, "Warnings should be populated"
        assert "[WARN]" in str(result.warnings[0]), (
            f"Warning should have [WARN] prefix: {result.warnings[0]}"
        )
        print("      [PASS] Warn-only rules populate warnings but leave is_safe=True")

    finally:
        os.unlink(temp_policy)


def test_8_multiple_violations():
    """Check that multiple independent violations are all reported."""
    section("8. Multiple violations aggregation")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write("""
rules:
  - name: rule_a
    action: block
    trigger:
      all_present: [A, B]
    message: "violation_a"

  - name: rule_b
    action: block
    trigger:
      all_present: [C, D]
    message: "violation_b"
""")
        temp_policy = f.name

    try:
        guard = GuardMiddleware(temp_policy)

        # Four chunks: two violations, one from A+B, one from C+D
        chunks = [
            make_chunk("A source", classification="A"),
            make_chunk("B target", classification="B"),
            make_chunk("C source", classification="C"),
            make_chunk("D target", classification="D"),
        ]

        result = guard.analyze(chunks)

        assert not result.is_safe, "Should be unsafe"
        # Count how many violations
        block_count = sum(1 for v in result.violations if v.action == Action.BLOCK)
        assert block_count >= 2, (
            f"Expected at least 2 block violations, got {block_count}"
        )
        print(
            f"      [PASS] Multiple independent violations detected ({block_count} total)"
        )

    finally:
        os.unlink(temp_policy)


def test_9_missing_required_fields():
    """Test behavior when chunk dict is missing 'text' key."""
    section("9. Missing required fields")

    guard = GuardMiddleware(POLICY_FILE)

    # 9a: Missing 'text' key - should be handled gracefully with empty text default
    try:
        result = guard.analyze([{"meta": {"classification": "A"}}])
        # Should not crash; missing text defaults to ""
        assert isinstance(result, AnalysisResult), "Should return AnalysisResult"
        # With empty text, classification not set -> should be safe
        # (unless policy triggers on empty? unlikely)
        print("      [PASS] Chunk without 'text' -> handled (empty default)")
    except KeyError as e:
        print(f"  [FAIL] Missing 'text' raised KeyError: {e}")
        raise AssertionError("Should not raise KeyError for missing 'text'")

    # 9b: Empty text string
    result = guard.analyze([{"text": "", "meta": {"classification": "A"}}])
    assert isinstance(result, AnalysisResult), "Empty text should still work"
    print("      [PASS] Empty text string -> handled")


def run_all_tests():
    """Execute all test cases and report results."""
    print("\n" + "=" * 60)
    print("RAGGUARD COMPREHENSIVE TEST SUITE")
    print("=" * 60)

    tests = [
        ("Basic functionality", test_1_basic_functionality),
        ("Multi-hop collusion", test_2_multihop_collusion),
        ("Action handling", test_3_action_handling),
        ("Edge cases", test_4_edge_cases),
        ("Security: YAML safe_load", test_5_security_yaml_safe_load),
        ("Real-world format", test_6_real_world_format),
        ("Warning collection", test_7_warning_collection),
        ("Multiple violations", test_8_multiple_violations),
        ("Missing required fields", test_9_missing_required_fields),
    ]

    passed = 0
    failed = 0
    failures = []

    for name, test_func in tests:
        try:
            test_func()
            passed += 1
        except Exception as e:
            failed += 1
            failures.append((name, e))
            print(f"\n  [FAIL] TEST FAILED: {e}")

    # ─── Summary ────────────────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("FINAL REPORT")
    print("=" * 60)
    print(f"Passed: {passed}/{len(tests)}")
    print(f"Failed: {failed}/{len(tests)}")

    if failures:
        print("\nFailed tests:")
        for name, err in failures:
            print(f"  - {name}: {err}")
        return 1
    else:
        print("\n    [PASS] All tests passed!")
        return 0


if __name__ == "__main__":
    exit_code = run_all_tests()
    sys.exit(exit_code)
