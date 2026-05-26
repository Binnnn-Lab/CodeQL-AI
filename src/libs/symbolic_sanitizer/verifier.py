"""verify_with_decisions -- re-execute path applying chosen sanitizer guards."""
from __future__ import annotations

import os
from typing import Dict, Any, Optional

from .path_executor import PathExecutor
from .dwarf_resolver import line_to_addr, func_entry


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

    sink_addr = ex.func_addr("__sink_reached")
    if sink_addr is None:
        return {"success": False, "error": "__sink_reached not in binary",
                "reachable": False, "counterexample": None, "sat_branches": []}

    res = ex.solve_with_decisions(state, sink_addr, branch_decisions,
                                  attack_predicate, timeout=timeout)
    if degraded:
        res["degraded"] = degraded
    return res
