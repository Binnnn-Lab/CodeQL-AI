#!/usr/bin/env python3
"""Scan a QL query directory, extract @id metadata from each .ql file,
and save a ruleId -> filepath mapping as JSON."""

import json
import re
import sys
from pathlib import Path
from typing import Dict, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_QL_DIR = Path("/opt/codeql-lib/cpp/ql/src")
DEFAULT_OUTPUT = PROJECT_ROOT / "knowledge" / "rule_id_map.json"

_ID_PATTERN = re.compile(r"@id\s+(\S+)")


def extract_ql_id(ql_path: Path) -> Optional[str]:
    with open(ql_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read(4096)
    match = _ID_PATTERN.search(content)
    return match.group(1) if match else None


def build_rule_id_map(ql_dir: str, output_path: str) -> Dict[str, str]:
    ql_dir = Path(ql_dir).expanduser()
    if not ql_dir.is_dir():
        print(f"Error: QL directory not found: {ql_dir}", file=sys.stderr)
        sys.exit(1)

    mapping: Dict[str, str] = {}
    for ql_file in sorted(ql_dir.rglob("*.ql")):
        rule_id = extract_ql_id(ql_file)
        if rule_id:
            if rule_id in mapping:
                print(
                    f"Warning: duplicate @id '{rule_id}' "
                    f"({mapping[rule_id]} vs {ql_file})",
                    file=sys.stderr,
                )
            mapping[rule_id] = str(ql_file.resolve())

    output_path = Path(output_path).expanduser()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(mapping, f, indent=2, ensure_ascii=False, sort_keys=True)

    print(f"Built rule_id map: {len(mapping)} entries -> {output_path}")
    return mapping


if __name__ == "__main__":
    ql_dir = sys.argv[1] if len(sys.argv) > 1 else str(DEFAULT_QL_DIR)
    output = sys.argv[2] if len(sys.argv) > 2 else str(DEFAULT_OUTPUT)
    build_rule_id_map(ql_dir, output)
