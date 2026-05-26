"""
Symbolic Sanitizer — branch-level selective symbolic execution for SAST false positive reduction.
"""

from .sarif_parser import (
    load_sarif_from_file,
    extract_taint_paths,
    TaintPath,
    parse_sarif,
)
from .path_context import read_path_context, find_enclosing_function
from .harness_generator import generate_harness, compile_harness
from .harness_builder import (
    build_harness, render_harness, select_source_mode, DEFAULT_COMPILE_SH,
)
from .compile_config import resolve_compile_config, write_compile_config
from .symbolic_sanitizer import SymbolicExecutor
from .branch_scanner import scan_path_branches
from .verifier import verify_with_decisions

__all__ = [
    'load_sarif_from_file',
    'extract_taint_paths',
    'TaintPath',
    'parse_sarif',
    'read_path_context',
    'find_enclosing_function',
    'generate_harness',
    'compile_harness',
    'build_harness',
    'render_harness',
    'select_source_mode',
    'DEFAULT_COMPILE_SH',
    'resolve_compile_config',
    'write_compile_config',
    'SymbolicExecutor',
    'scan_path_branches',
    'verify_with_decisions',
]
