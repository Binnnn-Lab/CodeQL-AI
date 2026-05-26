"""verify_with_decisions -- re-execute path applying chosen sanitizer guards."""
from __future__ import annotations

import os
from typing import Dict, Any, Optional

from .path_executor import PathExecutor
from .dwarf_resolver import line_to_addr, func_entry, nearest_line_addr


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


def verify_with_decisions(
    binary_path: str,
    path: Dict[str, Any],
    source_mode: str,
    branch_decisions: Dict[str, bool],
    attack_predicate: Optional[Dict[str, Any]] = None,
    timeout: int = 120,
) -> Dict[str, Any]:
    if not os.path.exists(binary_path):
        return {"success": False, "error": f"binary not found: {binary_path}",
                "reachable": False, "counterexample": None, "sat_branches": []}

    ex = PathExecutor(binary_path)

    if source_mode == "libc_stdin":
        state = ex.initial_state_libc_stdin()
        degraded = None
    elif source_mode == "mid_function":
        src_file = path["source"]["file_path"]
        src_line = path["source"]["line_number"]
        addr = line_to_addr(binary_path, src_file, src_line)
        if addr is None:
            func_name = path["source"].get("function_name") or "main"
            faddr = func_entry(binary_path, func_name)
            if faddr is None:
                return {"success": False, "error": "no DWARF for source line",
                        "reachable": False, "counterexample": None,
                        "sat_branches": [], "degraded": "no_dwarf_for_source"}
            state = ex.initial_state_entry_fallback(faddr)
            degraded = "no_dwarf_for_source"
        else:
            state = ex.initial_state_mid_function(addr)
            degraded = None
    else:
        return {"success": False, "error": f"unknown source_mode: {source_mode}",
                "reachable": False, "counterexample": None, "sat_branches": []}

    sink_addr, degraded_sink = _resolve_sink_addr(binary_path, path, ex)
    if sink_addr is None:
        return {"success": False, "error": "sink address not found from SARIF/DWARF",
                "reachable": False, "counterexample": None, "sat_branches": []}

    res = ex.solve_with_decisions(state, sink_addr, branch_decisions,
                                  attack_predicate, timeout=timeout)
    degradations = [d for d in (degraded, degraded_sink) if d]
    if degradations:
        res["degraded"] = ",".join(degradations)
    return res
