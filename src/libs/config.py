"""Shared project-wide path constants."""

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

# CodeQL-AI managed directories (consistent with scripts/swap_ql.py)
CODEQL_AI_DIR = PROJECT_ROOT / "scripts" / ".CODEQL-AI"
PATCHED_QL_DIR = CODEQL_AI_DIR / "patched-ql"
QL_MAPPINGS_PATH = CODEQL_AI_DIR / "ql_mappings.json"
OLD_QL_DIR = CODEQL_AI_DIR / "old-ql"

# Knowledge base
DEFAULT_KNOWLEDGE_BASE = PROJECT_ROOT / "knowledge"
DEFAULT_RULE_MAP = PROJECT_ROOT / "knowledge" / "rule_id_map.json"
