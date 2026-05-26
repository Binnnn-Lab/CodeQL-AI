"""Symbolic Sanitizer — path-guided selective symbolic execution."""

from .sarif_parser import (
    load_sarif_from_file,
    extract_taint_paths,
    parse_sarif,
    TaintPath,
)
from .path_context import find_enclosing_function
from .harness_builder import (
    build_harness,
    render_harness,
    select_source_mode,
    DEFAULT_COMPILE_SH,
)
from .compile_config import resolve_compile_config, write_compile_config
from .path_executor import PathExecutor
from .branch_scanner import scan_path_branches
from .verifier import verify_with_decisions

__all__ = [
    "load_sarif_from_file", "extract_taint_paths", "parse_sarif", "TaintPath",
    "find_enclosing_function",
    "build_harness", "render_harness", "select_source_mode", "DEFAULT_COMPILE_SH",
    "resolve_compile_config", "write_compile_config",
    "PathExecutor",
    "scan_path_branches",
    "verify_with_decisions",
]
