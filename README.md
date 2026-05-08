# RagContextGuard

**Prevent sensitive information leakage in RAG pipelines.**

RagContextGuard is a lightweight Python middleware that analyzes retrieved document chunks before they reach your LLM. It detects when innocent-looking chunks combine to reveal secrets.

[![PyPI version](https://img.shields.io/pypi/v/rag-context-guard)](https://pypi.org/project/rag-context-guard/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

## Installation

```bash
pip install rag-context-guard
```

## Why This Exists

RAG systems retrieve multiple document chunks to answer questions. Even if each chunk is safe individually, their combination can expose secrets. For example, one chunk might contain salary ranges while another lists employee names—separately they're harmless, together they reveal payroll data. RagContextGuard prevents this by analyzing the full context set before it reaches the LLM.

### Security model

**Classified metadata is a trusted input.** RagContextGuard assumes classification labels come from a trusted source (your ingestion pipeline, vetted taxonomies, or a carefully-controlled LLM classifier). The guard does not validate label semantics; it only checks whether the *set* of labels triggers a policy rule.

If an attacker can inject arbitrary classification labels into chunk metadata (e.g., by compromising your vector DB or classifier), they can bypass or trigger rules at will. **Treat classification metadata as security-critical configuration.**

For production, we recommend:
- Label only from trusted ingestion-time classifiers (not per-query)
- Validating classification strings against an allowlist (`/^[a-z_]+$/`)
- Auditing classification sources regularly

## How It Works

1. **Classifications**: Each chunk carries one or more labels (e.g., `"financial"`, `"pii"`, `"confidential"`). These come from your existing metadata or an optional LLM classifier you provide.
2. **Set Analysis**: RagContextGuard checks whether the union of all chunk classifications satisfies any policy rule's `trigger.all_present` condition.
3. **Path Analysis**: Multi-hop collusion detection finds when a shared classification bridges two otherwise-safe rules, creating a dangerous combination.
4. **Actions**: Rules can `block` (halt pipeline) or `warn` (log only).

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

**⚠️ Important:** The classifier feature is intended for prototyping and evaluation only. Running an LLM per chunk at query time is slow (adds latency) and expensive (cost scales with retrieval chunk count). For production, pre-classify documents at ingestion time and store classifications with your vector DB entries. See "Why This Exists" above for the trusted-classification model.

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

**Methods:**
- `to_dict() -> dict` — serialize to plain dict for JSON logging or API responses

### `Violation`
- `rule_name: str`
- `message: str`
- `triggering_chunks: List[Chunk]`
- `action: Action` (`Action.BLOCK` or `Action.WARN`)

**Methods:**
- `to_dict() -> dict` — serialize to plain dict

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
