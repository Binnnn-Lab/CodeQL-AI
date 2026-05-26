#!/usr/bin/env python3
"""MCP Server: Symbolic Sanitizer (4-tool path-guided selective sym-exec)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastmcp import FastMCP
from libs.symbolic_sanitizer import (
    parse_sarif as _parse_sarif,
    build_harness as _build_harness,
    scan_path_branches as _scan_path_branches,
    verify_with_decisions as _verify_with_decisions,
    resolve_compile_config as _resolve_compile_config,
    write_compile_config as _write_compile_config,
    DEFAULT_COMPILE_SH,
)

mcp = FastMCP(
    name="symbolic_sanitizer",
    instructions=(
        "Path-guided selective symbolic execution. Workflow: "
        "parse_sarif -> build_harness -> scan_path_branches -> "
        "(agent decides branch include/exclude + attack predicate) -> "
        "verify_with_decisions."
    ),
)


@mcp.tool()
def parse_sarif(sarif_path: str, dataset_root: str) -> dict:
    """Parse SARIF and return taint paths with absolute paths + function source."""
    return _parse_sarif(sarif_path, dataset_root)


@mcp.tool()
def build_harness(source_file: str, vuln_entry: str, source_api: str,
                  compile_script: str, entry_signature: str = "void") -> dict:
    """Compile a template harness linked with the original source file."""
    return _build_harness(source_file, vuln_entry, source_api,
                          compile_script, entry_signature=entry_signature)


@mcp.tool()
def scan_path_branches(binary_path: str, path: dict, source_mode: str,
                       timeout: int = 120) -> dict:
    """Enumerate tainted branches along the SARIF path. Agent decides which to
    treat as sanitizers."""
    return _scan_path_branches(binary_path, path, source_mode, timeout=timeout)


@mcp.tool()
def verify_with_decisions(binary_path: str, path: dict, source_mode: str,
                          branch_decisions: dict,
                          attack_predicate: dict | None = None,
                          timeout: int = 120) -> dict:
    """Re-execute path applying chosen sanitizer guards + attack predicate."""
    return _verify_with_decisions(binary_path, path, source_mode,
                                  branch_decisions, attack_predicate,
                                  timeout=timeout)


@mcp.tool()
def resolve_compile_config(dataset_path: str) -> dict:
    """Locate an existing compile.sh under dataset_path."""
    return _resolve_compile_config(dataset_path)


@mcp.tool()
def write_compile_config(dataset_path: str, script_content: str | None = None) -> dict:
    """Write a compile.sh into dataset_path. Defaults to the template that
    enforces -g -O0 -fno-inline."""
    return _write_compile_config(dataset_path,
                                 script_content or DEFAULT_COMPILE_SH)


if __name__ == "__main__":
    mcp.run()
