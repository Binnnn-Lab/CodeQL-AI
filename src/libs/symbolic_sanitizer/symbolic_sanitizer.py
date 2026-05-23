"""
Symbolic Execution — angr-based sink reachability verification.
"""

import logging
from typing import List, Dict, Any, Optional

import angr
import claripy

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SymbolicExecutor:

    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.project = angr.Project(binary_path, auto_load_libs=False)
        logger.info(f"Loaded binary: {binary_path}")

    def execute_reachability(
        self, constraints: dict, sink_marker: str, timeout: int
    ) -> dict:
        try:
            main_addr = self._find_function("main")
            if not main_addr:
                return self._error_result("main function not found")

            sink_addr = self._find_function(sink_marker)
            if not sink_addr:
                return self._error_result(f"{sink_marker} function not found in binary")

            sym_bytes = [claripy.BVS(f'byte_{i}', 8) for i in range(64)]
            input_addr = 0x500000

            state = self.project.factory.call_state(main_addr, input_addr)
            for i, b in enumerate(sym_bytes):
                state.memory.store(input_addr + i, b)

            input_constraints = constraints.get("input_constraints", [])
            self.apply_input_constraints(state, sym_bytes, input_constraints)

            if not state.solver.satisfiable():
                return {
                    "success": True,
                    "reachable": False,
                    "paths_explored": 0,
                    "paths_to_sink": 0,
                    "counterexample": None,
                    "error": None,
                }

            simgr = self.project.factory.simgr(state)
            logger.info(f"Exploring reachability to {sink_marker} at 0x{sink_addr:x}")
            simgr.explore(find=sink_addr)

            paths_to_sink = len(simgr.found)
            paths_explored = (
                len(simgr.found)
                + len(getattr(simgr, 'deadended', []))
                + len(getattr(simgr, 'active', []))
                + len(getattr(simgr, 'errored', []))
            )

            counterexample = None
            if simgr.found:
                try:
                    found_state = simgr.found[0]
                    concrete = bytes([
                        found_state.solver.eval(b, cast_to=int) for b in sym_bytes[:32]
                    ])
                    counterexample = concrete.hex()
                except Exception:
                    counterexample = "extraction_failed"

            return {
                "success": True,
                "reachable": paths_to_sink > 0,
                "paths_explored": paths_explored,
                "paths_to_sink": paths_to_sink,
                "counterexample": counterexample,
                "error": None,
            }

        except Exception as e:
            logger.error(f"Reachability analysis failed: {e}")
            return self._error_result(str(e))

    def _find_function(self, name: str) -> Optional[int]:
        try:
            symbol = self.project.loader.find_symbol(name)
            if symbol:
                return symbol.rebased_addr
        except Exception:
            pass

        for sym in self.project.loader.symbols:
            if sym.name == name:
                return sym.rebased_addr
        return None

    def apply_input_constraints(
        self, state, sym_bytes: List, input_constraints: List[Dict]
    ) -> None:
        constraint = self._build_input_constraint(sym_bytes, input_constraints)
        state.solver.add(constraint)

    def _build_input_constraint(self, sym_bytes: List, input_constraints: List[Dict]):
        combined = []
        for c in input_constraints:
            ctype = c.get("type")
            if ctype == "contains_any":
                chars = c.get("chars", [])
                if chars:
                    combined.append(self._build_contains_any_constraint(sym_bytes, chars))
            elif ctype == "length_range":
                min_len = c.get("min", 0)
                max_len = c.get("max", len(sym_bytes))
                combined.append(self._build_length_range_constraint(sym_bytes, min_len, max_len))
        if combined:
            return claripy.And(*combined)
        return claripy.true

    def _build_contains_any_constraint(self, sym_bytes: List, chars: List[str]):
        char_vals = [ord(ch[0]) if len(ch) > 0 else ord(' ') for ch in chars]
        byte_matches = []
        for byte in sym_bytes:
            char_matches = [byte == val for val in char_vals]
            byte_matches.append(claripy.Or(*char_matches))
        return claripy.Or(*byte_matches)

    def _build_length_range_constraint(self, sym_bytes: List, min_len: int, max_len: int):
        constraints = []
        if min_len > 0 and min_len <= len(sym_bytes):
            for i in range(min_len):
                if i < len(sym_bytes):
                    constraints.append(sym_bytes[i] != 0)
        if max_len < len(sym_bytes):
            constraints.append(sym_bytes[max_len] == 0)
        if constraints:
            return claripy.And(*constraints)
        return claripy.true

    @staticmethod
    def _error_result(error: str) -> dict:
        return {
            "success": False,
            "reachable": False,
            "paths_explored": 0,
            "paths_to_sink": 0,
            "counterexample": None,
            "error": error,
        }
