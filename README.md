# RagContextGuard

**Prevent sensitive information leakage in RAG pipelines.**

RagContextGuard is a lightweight Python middleware that analyzes retrieved document chunks before they reach your LLM. It detects when innocent-looking chunks combine to reveal secrets.

## Installation

```bash
pip install -e .
```

This installs `rag-context-guard` with its dependencies (`pyyaml`).

## Quick Demo

Run the included demo to see RagContextGuard in action:

```bash
python demo.py
```

The demo simulates a RAG retrieval with 3 chunks — one combines financial data with an entity identifier, triggering a policy violation.

## Running Tests

The project includes a comprehensive test suite. Run it to verify the installation:

```bash
python test_comprehensive.py
```

Expected output: `[PASS] All tests passed!` (9/9 tests). If you've added custom policies or modified the engine, run this to verify correctness.

## How It Works

1. **Classifications**: Each chunk carries one or more labels (e.g., `"financial"`, `"pii"`, `"confidential"`). These come from your existing metadata or an optional LLM classifier you provide.
2. **Set Analysis**: RagContextGuard checks whether the union of all chunk classifications satisfies any policy rule's `trigger.all_present` condition.
3. **Path Analysis**: Multi-hop collusion detection finds when a shared classification bridges two otherwise-safe rules, creating a dangerous combination.
4. **Actions**: Rules can `block` (halt pipeline) or `warn` (log only).

## Policy Format

Policies are YAML files. Create your own or use the built-ins.

```yaml
rules:
  - name: financial_entity_reveal
    description: "Block combining financial metrics with entity identifiers"
    action: block   # or "warn"
    trigger:
      all_present:
        - financial
        - entity_identifier
    message: "Financial data combined with entity identifier — client financials exposed"
```

**Matching**: A rule fires when all classifications listed in `trigger.all_present` appear across the retrieved chunk set (any chunk, any order). A chunk may carry multiple classifications.

## Usage

```python
from rag_context_guard import GuardMiddleware, policies

# Use built-in policy
guard = GuardMiddleware(policies.DEFAULT)

# Or your custom file
# guard = GuardMiddleware("my_policy.yaml")
```

### Chunk format

Each chunk is a `dict` with:
- `text` (str): The document content
- `meta` (dict): At minimum, include `classification` (str or list) or `classifications` (list)

Any extra metadata fields are ignored by the policy engine.

## Built-in Policies

| Policy | Use case | Rules |
|---|---|---|
| `policies.DEFAULT` | General data leakage prevention | 7 |
| `policies.FINANCE` | Financial services confidentiality | 6 |
| `policies.HIPAA` | Protected Health Information (PHI) | 6 |
| `policies.GDPR` | EU personal data compliance | 6 |

```python
from rag_context_guard import GuardMiddleware, policies

guard = GuardMiddleware(policies.FINANCE)
```

## Optional: LLM-Based Classification

If your chunks lack pre-computed classification metadata, you can provide a classifier function that runs an LLM to tag chunks:

```python
from rag_context_guard import GuardMiddleware
from langchain_ollama import OllamaLLM   # pip install langchain-ollama
```

The classifier is called only for chunks without existing classifications.

## Running Tests

The project includes a comprehensive test suite:

```bash
python test_comprehensive.py
```

Expected output: `[PASS] All tests passed!` (9/9 tests). If you've added custom policies or modified the engine, run this to verify correctness.

## API Reference

### `GuardMiddleware`
Main entry point.

```python
GuardMiddleware(policy_path=None, classifier=None)
```
- `policy_path`: `BuiltinPolicy` constant or path to YAML file (default: built-in DEFAULT)
- `classifier`: Optional callable `(str) -> str | list[str] | None`

Methods:
- `analyze(chunks: List[dict]) -> AnalysisResult`
- `get_rules() -> List[PolicyRule]`

### `AnalysisResult`
Returned by `analyze()`:
- `is_safe: bool` — `True` if no block violations
- `violations: List[Violation]` — all blocking issues
- `warnings: List[Violation]` — all warn-level issues
- `safe_subset: List[Chunk]` — chunks not involved in any block violation
- `risk_explanation: str` — human-readable summary

### `Violation`
- `rule_name: str`
- `message: str`
- `triggering_chunks: List[Chunk]`
- `action: Action` (`Action.BLOCK` or `Action.WARN`)

## Creating Custom Policies

Copy `src/rag_context_guard/policies/example.yaml` and adapt:

```yaml
rules:
  - name: healthcare_pii_exposure
    action: block
    trigger:
      all_present: [healthcare, pii]
    message: "Healthcare data combined with PII — exposure risk"
```

Then load it:

```python
guard = GuardMiddleware("my_policy.yaml")
```

## Project Structure

```
rag-context-guard/
├── src/rag_context_guard/
│   ├── guard.py           # GuardMiddleware
│   ├── graph_analyzer.py  # Policy evaluation engine
│   ├── policy.py          # YAML policy loader
│   ├── models.py          # Dataclasses (Chunk, Violation, AnalysisResult)
│   └── policies/          # Built-in YAML policies
│       ├── default.yaml
│       ├── finance.yaml
│       ├── hipaa.yaml
│       └── gdpr.yaml
├── demo.py                # Example usage (no external LLM needed)
├── test_comprehensive.py  # Full test suite
├── pyproject.toml         # Dependency + build config
└── README.md
```

## License

MIT
