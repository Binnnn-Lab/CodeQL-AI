"""Binary builder for symbolic sanitizer analysis.

The preferred path is to compile the dataset's original source into a debuggable
binary and let the executor target SARIF source/sink addresses directly.  The
old harness helpers remain as compatibility shims for existing tests and tools.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

LIBC_SOURCE_APIS = frozenset({
    "scanf", "fscanf", "sscanf", "fgets", "gets", "getc", "getchar",
    "read", "recv", "fread", "recvfrom", "recvmsg",
})

DEFAULT_COMPILE_SH = r"""#!/bin/bash
# Args: <source_src> <output_binary> <lang>
SRC="$1"; OUT="$2"; LANG="${3:-c}"
case "$LANG" in
  cpp) CC=g++ ; STD=-std=c++17 ;;
  *)   CC=gcc ; STD=-std=c11   ;;
esac
"$CC" $STD -g -O0 -fno-inline "$SRC" -o "$OUT" -lm 2>&1
"""

DEFAULT_HARNESS_COMPILE_SH = r"""#!/bin/bash
# Args: <harness_src> <original_src> <output_binary> <lang>
HARNESS="$1"; ORIG="$2"; OUT="$3"; LANG="${4:-c}"
case "$LANG" in
  cpp) CC=g++ ; STD=-std=c++17 ;;
  *)   CC=gcc ; STD=-std=c11   ;;
esac
"$CC" $STD -g -O0 -fno-inline "$HARNESS" "$ORIG" -o "$OUT" -lm 2>&1
"""


def select_source_mode(source_api: Optional[str]) -> str:
    if source_api and source_api in LIBC_SOURCE_APIS:
        return "libc_stdin"
    return "mid_function"


def render_harness(vuln_entry: str, entry_signature: str = "void") -> str:
    """Render a minimal harness that calls the original vuln entry function.

    entry_signature: 'void' (no return value handling) or 'int' (cast away).
    """
    if entry_signature == "void":
        extern = f"extern void {vuln_entry}(void);"
        call = f"{vuln_entry}();"
    else:
        extern = f"extern int {vuln_entry}(void);"
        call = f"(void){vuln_entry}();"
    return (
        "#include <stdio.h>\n"
        f"{extern}\n"
        "void __sink_reached(void) {}\n"
        "int main(void) {\n"
        f"    {call}\n"
        "    return 0;\n"
        "}\n"
    )


_CPP_EXTS = {".cpp", ".cc", ".cxx", ".c++", ".C", ".hpp", ".hh", ".hxx"}


def _infer_lang(source_file: str) -> str:
    return "cpp" if Path(source_file).suffix in _CPP_EXTS else "c"


def _has_dwarf(binary_path: str) -> bool:
    try:
        from elftools.elf.elffile import ELFFile
        with open(binary_path, "rb") as f:
            return ELFFile(f).has_dwarf_info()
    except Exception:
        return False


def build_binary(
    source_file: str,
    source_api: Optional[str],
    compile_script: str,
) -> dict:
    """Compile an original dataset source file into a debuggable binary.

    The compile script contract is:
        bash compile.sh <source_src> <output_binary> <lang>
    """
    if not os.path.exists(source_file):
        return {"success": False, "error": f"source_file missing: {source_file}"}
    if not os.path.exists(compile_script):
        return {"success": False, "error": f"compile_script missing: {compile_script}"}

    lang = _infer_lang(source_file)
    tmpdir = tempfile.mkdtemp(prefix="symbolic_binary_")
    binary_path = os.path.join(tmpdir, "analysis_bin")

    try:
        proc = subprocess.run(
            ["bash", compile_script, source_file, binary_path, lang],
            capture_output=True, text=True, timeout=120,
        )
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "compile timed out (120s)"}

    if proc.returncode != 0:
        return {
            "success": False,
            "error": f"compile failed: {proc.stderr.strip() or proc.stdout.strip()}",
        }

    return {
        "success": True,
        "binary_path": binary_path,
        "source_mode": select_source_mode(source_api),
        "dwarf_ok": _has_dwarf(binary_path),
        "error": None,
    }


def build_harness(
    source_file: str,
    vuln_entry: str,
    source_api: Optional[str],
    compile_script: str,
    entry_signature: str = "void",
) -> dict:
    if not os.path.exists(source_file):
        return {"success": False, "error": f"source_file missing: {source_file}"}
    if not os.path.exists(compile_script):
        return {"success": False, "error": f"compile_script missing: {compile_script}"}

    lang = _infer_lang(source_file)
    harness_ext = ".cpp" if lang == "cpp" else ".c"
    tmpdir = tempfile.mkdtemp(prefix="symbolic_harness_")
    harness_path = os.path.join(tmpdir, f"harness{harness_ext}")
    binary_path = os.path.join(tmpdir, "harness_bin")

    code = render_harness(vuln_entry, entry_signature=entry_signature)
    with open(harness_path, "w") as f:
        f.write(code)

    try:
        proc = subprocess.run(
            ["bash", compile_script, harness_path, source_file, binary_path, lang],
            capture_output=True, text=True, timeout=120,
        )
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "compile timed out (120s)", "harness_path": harness_path}

    if proc.returncode != 0:
        return {
            "success": False,
            "error": f"compile failed: {proc.stderr.strip() or proc.stdout.strip()}",
            "harness_path": harness_path,
        }

    return {
        "success": True,
        "binary_path": binary_path,
        "harness_path": harness_path,
        "source_mode": select_source_mode(source_api),
        "dwarf_ok": _has_dwarf(binary_path),
        "error": None,
    }
