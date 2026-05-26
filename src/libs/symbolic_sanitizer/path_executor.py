"""Shared angr driver for branch scanning and verification."""
from __future__ import annotations

import logging
from typing import List, Optional

import angr
import claripy

logger = logging.getLogger(__name__)

TAINT_BUF_SIZE = 64


class PathExecutor:
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.project = angr.Project(binary_path, auto_load_libs=False)
        self._sym_bytes: List[claripy.ast.bv.BV] = []

    def func_addr(self, name: str) -> Optional[int]:
        sym = self.project.loader.find_symbol(name)
        if sym is not None:
            return sym.rebased_addr
        for s in self.project.loader.symbols:
            if s.name == name:
                return s.rebased_addr
        return None

    def make_symbolic_bytes(self) -> List[claripy.ast.bv.BV]:
        self._sym_bytes = [claripy.BVS(f"sym_byte_{i}", 8) for i in range(TAINT_BUF_SIZE)]
        return self._sym_bytes

    @property
    def sym_bytes(self) -> List[claripy.ast.bv.BV]:
        return self._sym_bytes

    def initial_state_libc_stdin(self) -> angr.SimState:
        sym_bytes = self.make_symbolic_bytes()
        stdin_content = claripy.Concat(*sym_bytes)
        state = self.project.factory.full_init_state(
            stdin=angr.SimFileStream(name="stdin", content=stdin_content, has_end=True),
        )
        return state

    def initial_state_mid_function(self, source_addr: int) -> angr.SimState:
        sym_bytes = self.make_symbolic_bytes()
        state = self.project.factory.call_state(source_addr)
        # Reserve a region for symbolic input (caller stores into target var via DWARF).
        # We allocate at a fixed scratch address inside angr-managed memory:
        scratch = state.heap.allocate(TAINT_BUF_SIZE)
        for i, b in enumerate(sym_bytes):
            state.memory.store(scratch + i, b)
        state.globals["symbolic_input_addr"] = scratch
        return state

    def initial_state_entry_fallback(self, func_addr: int) -> angr.SimState:
        return self.initial_state_mid_function(func_addr)
