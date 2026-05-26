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
# Args: <source_src> <output_binary> <lang> [<dataset_root>]
# dataset_root is forwarded as $SRCROOT so dataset-specific compile.sh scripts
# (Juliet/SARD/custom benches) can resolve testcasesupport, headers, etc.
SRC="$1"; OUT="$2"; LANG="${3:-c}"; SRCROOT="${4:-}"
case "$LANG" in
  cpp) CC=g++ ; STD=-std=c++17 ;;
  *)   CC=gcc ; STD=-std=c11   ;;
esac
INC=""
[ -n "$SRCROOT" ] && INC="-I$SRCROOT"
"$CC" $STD -g -O0 -fno-inline $INC "$SRC" -o "$OUT" -lm 2>&1
"""


def select_source_mode(source_api: Optional[str]) -> str:
    if source_api and source_api in LIBC_SOURCE_APIS:
        return "libc_stdin"
    return "mid_function"


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
    dataset_path: Optional[str] = None,
) -> dict:
    """Compile an original dataset source file into a debuggable binary.

    The compile script contract is:
        bash compile.sh <source_src> <output_binary> <lang> [<dataset_root>]

    `dataset_path` is forwarded as the 4th positional arg so dataset-specific
    compile.sh scripts (Juliet/SARD/custom) can resolve testcasesupport, shared
    headers, or multi-file companions without hardcoding paths.
    """
    if not os.path.exists(source_file):
        return {"success": False, "error": f"source_file missing: {source_file}"}
    if not os.path.exists(compile_script):
        return {"success": False, "error": f"compile_script missing: {compile_script}"}

    lang = _infer_lang(source_file)
    tmpdir = tempfile.mkdtemp(prefix="symbolic_binary_")
    binary_path = os.path.join(tmpdir, "analysis_bin")

    cmd = ["bash", compile_script, source_file, binary_path, lang]
    if dataset_path:
        cmd.append(dataset_path)

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
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


