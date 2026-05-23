"""
Compile Config — dataset-level compile.sh discovery and creation.
"""

import os
import stat
from pathlib import Path


def resolve_compile_config(dataset_path: str) -> dict:
    path = Path(dataset_path)
    if not path.exists():
        return {
            "found": False,
            "dataset_path": dataset_path,
            "directory_listing": [],
        }

    script_path = path / ".CodeQL-AI" / "compile.sh"
    if script_path.exists():
        return {
            "found": True,
            "compile_script": str(script_path),
        }

    listing = sorted([
        entry.name for entry in path.iterdir()
        if not entry.name.startswith('.')
    ])

    return {
        "found": False,
        "dataset_path": str(path),
        "directory_listing": listing,
    }


def write_compile_config(dataset_path: str, script_content: str) -> dict:
    path = Path(dataset_path)
    config_dir = path / ".CodeQL-AI"

    try:
        config_dir.mkdir(parents=True, exist_ok=True)
        script_path = config_dir / "compile.sh"
        script_path.write_text(script_content, encoding='utf-8')
        script_path.chmod(script_path.stat().st_mode | stat.S_IEXEC)

        return {
            "success": True,
            "compile_script": str(script_path),
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }
