#!/usr/bin/env python3
"""MCP Server: Symbolic Sanitizer (4-tool path-guided selective sym-exec)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastmcp import FastMCP
from libs.symbolic_sanitizer import (
    parse_sarif as _parse_sarif,
    build_binary as _build_binary,
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
        "parse_sarif -> build_binary -> scan_path_branches -> "
        "(agent decides branch include/exclude + attack predicate) -> "
        "verify_with_decisions."
    ),
)


@mcp.tool()
def parse_sarif(sarif_path: str, dataset_root: str,
                output_dir: str | None = None) -> dict:
    """Parse SARIF and save each taint path as a separate JSON file.

    ``dataset_root`` is the root of the source tree (e.g. the Juliet
    test-suite-c checkout).  It is used to resolve relative SARIF URIs to
    absolute file paths.  Use the same value you would pass as
    ``dataset_path`` to ``build_binary``.

    Saves ``{path_id}.json`` files and ``_index.json`` into ``output_dir``
    (default: ``{sarif_path}_paths/``).  Returns a lightweight dict with
    ``count``, ``paths_dir``, and ``index_file`` — no path content in the
    response.  Use ``Read`` on the ``_index.json`` to see all paths, then
    ``Read`` individual ``path_file`` entries to load a full path object.
    That full path object is the ``path`` dict you pass to
    ``scan_path_branches`` and ``verify_with_decisions``."""
    return _parse_sarif(sarif_path, dataset_root, output_dir=output_dir)


@mcp.tool()
def build_binary(source_file: str, source_api: str, compile_script: str,
                 dataset_path: str | None = None) -> dict:
    """Compile the original source file into a debuggable analysis binary.

    ``source_api`` names the libc input function that reads attacker-controlled
    data.  Valid values: ``"scanf"``, ``"fscanf"``, ``"sscanf"``, ``"fgets"``,
    ``"gets"``, ``"getc"``, ``"getchar"``, ``"read"``, ``"recv"``, ``"fread"``,
    ``"recvfrom"``, ``"recvmsg"``.  Derive it from the SARIF ``message`` field
    — e.g. ``"value read by fscanf"`` → source_api = ``"fscanf"``; ``"value
    read from fgets"`` → source_api = ``"fgets"``.  If none of the known APIs
    appear, use ``"fscanf"`` as a safe default for Juliet CWE-190 test cases.

    ``source_file`` comes from the path JSON's ``source.file_path`` field.

    ``dataset_path`` is the dataset root (same value as ``dataset_root`` in
    ``parse_sarif``).  Forwarded as the 4th positional arg to compile.sh so
    dataset-specific scripts can resolve testcasesupport and shared headers.

    Returns ``binary_path``, ``source_mode`` (pass verbatim to scan/verify),
    and ``dwarf_ok``."""
    return _build_binary(source_file, source_api, compile_script,
                         dataset_path=dataset_path)


@mcp.tool()
def scan_path_branches(binary_path: str, path: dict, source_mode: str,
                       timeout: int = 120) -> dict:
    """Enumerate tainted branches along the SARIF path.

    ``binary_path`` is the path returned by ``build_binary``.
    ``source_mode`` is the mode string returned by ``build_binary`` — pass it
    verbatim, do not guess or change it.
    ``path`` is the **full path JSON object** from ``parse_sarif``.  Use
    ``Read`` on one of the ``path_file`` entries in ``_index.json`` to get it.

    Returns ``tainted_branches[]`` — one entry per conditional jump address
    where tainted data influences a branch decision.  Each entry has a
    ``branch_id`` (stable across runs), ``file``/``line``, the source-level
    ``condition_src``, ``surrounding_code``, ``taint_vars``, and
    ``alternatives`` (the two fork-side guard expressions).  The agent inspects
    these and decides which branches to mark as sanitizers in the next step."""
    return _scan_path_branches(binary_path, path, source_mode, timeout=timeout)


@mcp.tool()
def verify_with_decisions(binary_path: str, path: dict, source_mode: str,
                          branch_decisions: dict,
                          attack_predicate: dict | None = None,
                          timeout: int = 120) -> dict:
    """Re-execute path applying chosen sanitizer guards + attack predicate.

    ``binary_path`` / ``source_mode`` / ``path`` — same values passed to
    ``scan_path_branches``.

    ``branch_decisions`` is ``{branch_id: bool}``:
    - ``true`` → treat this conditional as a sanitizer; the verifier prunes
      states unsatisfiable with the attack predicate.  Both fork sides are
      considered — only the satisfiable one survives.
    - ``false`` or omitted → no pruning, angr explores both sides naturally.

    ``attack_predicate`` describes the attacker-controlled input value that
    should trigger the vulnerability:
    ``{"byte_offset": <int>, "width": <1|2|4|8>, "op": "<="|">="|"=="|"!="|"<"|">",
      "value": <int>, "signed": <bool>}``

    ``byte_offset`` indexes into the symbolic input buffer (0 for most
    single-input cases).  ``width`` is the byte-width of the tainted variable
    (1 for char, 2 for short, 4 for int/unsigned int, 8 for int64_t).
    ``signed`` should be ``true`` when the tainted variable is a signed type
    (char, short, int, int64_t) and ``false`` for unsigned types.  For
    CWE-190, the attack value is typically the threshold at which arithmetic
    overflows — e.g. ``CHAR_MAX`` (127) for signed char addition, ``>= 65536``
    for unsigned int multiplication.

    Returns ``reachable`` (bool), ``counterexample`` (string, empty if not
    reachable), ``sat_branches`` (which sanitizer branches had satisfiable
    states), ``paths_explored`` (angr step count)."""
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
