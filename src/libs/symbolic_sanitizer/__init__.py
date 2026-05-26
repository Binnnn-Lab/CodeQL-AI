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
from .compile_config import resolve_compile_config, write_compile_config
from .symbolic_sanitizer import SymbolicExecutor

__all__ = [
    'load_sarif_from_file',
    'extract_taint_paths',
    'TaintPath',
    'parse_sarif',
    'read_path_context',
    'find_enclosing_function',
    'generate_harness',
    'compile_harness',
    'resolve_compile_config',
    'write_compile_config',
    'SymbolicExecutor',
]
