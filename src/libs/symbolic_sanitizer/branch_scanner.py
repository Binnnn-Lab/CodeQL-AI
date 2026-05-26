"""scan_path_branches -- enumerate tainted branches on a SARIF path."""
from __future__ import annotations

import os
from typing import Dict, Any

from .path_executor import PathExecutor
from .dwarf_resolver import addr_to_line, func_entry, nearest_line_addr


def _read_source_line(file_path: str, line: int, context: int = 2) -> Dict[str, str]:
    if not os.path.exists(file_path):
        return {"condition_src": "", "surrounding_code": ""}
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()
    if line < 1 or line > len(lines):
        return {"condition_src": "", "surrounding_code": ""}
    cond = lines[line - 1].rstrip("\n")
    lo = max(0, line - 1 - context)
    hi = min(len(lines), line - 1 + context + 1)
    surrounding = "".join(lines[lo:hi])
    return {"condition_src": cond, "surrounding_code": surrounding}


def _resolve_sink_addr(binary_path: str, path: Dict[str, Any], ex: PathExecutor) -> tuple[int | None, str | None]:
    sink = path.get("sink", {})
    sink_file = sink.get("file_path")
    sink_line = sink.get("line_number")
    if sink_file and sink_line:
        addr = nearest_line_addr(binary_path, sink_file, sink_line)
        if addr is not None:
            return addr, None

    legacy_addr = ex.func_addr("__sink_reached")
    if legacy_addr is not None:
        return legacy_addr, "legacy_sink_symbol"

    return None, "sink_addr_unresolved"


def scan_path_branches(binary_path: str, path: Dict[str, Any],
                       source_mode: str, timeout: int = 120) -> Dict[str, Any]:
    if not os.path.exists(binary_path):
        return {"success": False, "error": f"binary not found: {binary_path}",
                "tainted_branches": []}

    ex = PathExecutor(binary_path)
    angr_base = ex.project.loader.main_object.min_addr

    if source_mode == "libc_stdin":
        state = ex.initial_state_libc_stdin()
    elif source_mode == "mid_function":
        src_file = path["source"]["file_path"]
        src_line = path["source"]["line_number"]
        from .dwarf_resolver import line_to_addr
        addr = line_to_addr(binary_path, src_file, src_line)
        if addr is None:
            func_name = path["source"].get("function_name") or "main"
            faddr = func_entry(binary_path, func_name)
            if faddr is None:
                return {"success": False,
                        "error": "DWARF cannot resolve source address",
                        "tainted_branches": [], "degraded": "no_dwarf_for_source"}
            state = ex.initial_state_entry_fallback(faddr + angr_base)
        else:
            state = ex.initial_state_mid_function(addr + angr_base)
    else:
        return {"success": False, "error": f"unknown source_mode: {source_mode}",
                "tainted_branches": []}

    sink_addr, degraded_sink = _resolve_sink_addr(binary_path, path, ex)
    if sink_addr is None:
        return {"success": False, "error": "sink address not found from SARIF/DWARF",
                "tainted_branches": []}

    # DWARF returns section offsets; angr uses rebased addresses.
    if sink_addr < angr_base:
        sink_addr += angr_base

    raw = ex.collect_tainted_branches(state, sink_addr, timeout=timeout)

    # Build a basename -> absolute-path lookup from the SARIF path nodes.
    known_files = {}
    for node in [path.get("source"), path.get("sink"),
                 *path.get("intermediate_locations", [])]:
        fp = (node or {}).get("file_path", "")
        if fp:
            known_files.setdefault(os.path.basename(fp), fp)

    enriched = []
    for b in raw:
        dwarf_addr = b["guard_addr"] - angr_base
        fl = addr_to_line(binary_path, dwarf_addr)
        if fl is None:
            file, line = "", 0
            src = {"condition_src": "", "surrounding_code": ""}
        else:
            file, line = fl
            if not os.path.isabs(file):
                file = known_files.get(os.path.basename(file), file)
            src = _read_source_line(file, line)
        enriched.append({
            "branch_id": b["branch_id"],
            "file": file,
            "line": line,
            "condition_src": src["condition_src"],
            "surrounding_code": src["surrounding_code"],
            "taint_vars": b["taint_vars"],
            "guard_repr": b["guard_repr"],
        })

    result = {"success": True, "tainted_branches": enriched, "error": None}
    if degraded_sink:
        result["degraded"] = degraded_sink
    return result
