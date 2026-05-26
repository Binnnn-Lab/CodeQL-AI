## Run demo

```bash
python src/demo_main.py
```

## MCP Knowledge MVP

The MCP server can now persist sanitizer experience learned from false-positive
analysis and reuse it in later database scans.

Current scope:

- repo/global JSONL knowledge store under `knowledge/`
- call-style sanitizer experience, for example `strip_parent_traversal(path)`
- low-confidence-by-default records to avoid silently hiding true positives
- MCP tools:
  - `save_experience_pattern`
  - `load_applicable_experiences`
  - `update_experience_validation`

Example experience:

```json
{
  "scope": "repo",
  "repo_id": "example/project",
  "language": "cpp",
  "cwe": "CWE-22",
  "query_id": "path-injection",
  "type": "call_sanitizer",
  "function_name": "strip_parent_traversal",
  "effect": "remove_parent_traversal_risk",
  "confidence": "low",
  "evidence": {
    "file": "src/path.c",
    "reason": "removes '..' from the path buffer"
  }
}
```

The first version only stores and retrieves experience. Query patch generation
and stronger validation can be layered on top of these MCP tools later.
