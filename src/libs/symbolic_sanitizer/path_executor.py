"""Shared angr driver for branch scanning and verification."""
from __future__ import annotations

import hashlib
import logging
from typing import Any, Dict, List, Optional, Set

import angr
import claripy

logger = logging.getLogger(__name__)

TAINT_BUF_SIZE = 64


# ---------------------------------------------------------------------------
# Helpers for branch collection
# ---------------------------------------------------------------------------

def _ast_taint_vars(ast) -> List[str]:
    """Return sorted names of symbolic byte variables the AST depends on."""
    if not hasattr(ast, "variables"):
        return []
    return sorted(v for v in ast.variables if v.startswith("sym_byte_"))


def _branch_id(guard_addr: int, ast) -> str:
    h = hashlib.sha1(f"{guard_addr:x}:{ast!r}".encode()).hexdigest()[:8]
    return f"b_{h}"


class _BranchCollector:
    """Records every symbolic conditional branch guard that depends on tainted
    bytes.  Called once per step via a SimulationManager step_func."""

    def __init__(self):
        self.branches: List[Dict[str, Any]] = []
        self._seen_ids: set = set()

    def maybe_record(self, state) -> None:
        # Try the indexable history list first (angr >= 9.2)
        guard = None
        try:
            guards = state.history.jump_guards
            guard = guards[-1]
        except Exception:
            pass

        # Fall back to parent's singular jump_guard (older angr)
        if guard is None:
            try:
                guard = state.history.parent.jump_guard
            except Exception:
                return

        if guard is None:
            return

        # Only consider symbolic (non-concrete) guards
        try:
            if not guard.symbolic:
                return
        except AttributeError:
            return

        taint_vars = _ast_taint_vars(guard)
        if not taint_vars:
            return

        # Resolve the address of the basic block that produced the branch
        guard_addr = 0
        try:
            bbl_addrs = state.history.bbl_addrs
            if len(bbl_addrs):
                guard_addr = bbl_addrs[-1]
        except Exception:
            pass

        bid = _branch_id(guard_addr, guard)
        if bid in self._seen_ids:
            return
        self._seen_ids.add(bid)
        self.branches.append({
            "branch_id": bid,
            "guard_addr": guard_addr,
            "guard_repr": str(guard)[:512],
            "taint_vars": taint_vars,
        })


# ---------------------------------------------------------------------------
# SimProcedure: symbolic fread hook
# ---------------------------------------------------------------------------

def _make_fread_hook(sym_bytes: List[claripy.ast.bv.BV]) -> angr.SimProcedure:
    """Return a SimProcedure subclass that injects *sym_bytes* on every fread call."""

    class _SymbolicFread(angr.SimProcedure):
        _sym_bytes = sym_bytes  # captured via closure over the class body

        def run(self, ptr, size, nmemb, stream):  # noqa: ARG002
            # Determine how many bytes the caller requested (concrete or bounded)
            try:
                n_bytes = self.state.solver.eval(size * nmemb)
            except Exception:
                n_bytes = TAINT_BUF_SIZE

            n_bytes = min(n_bytes, len(self._sym_bytes))

            for i in range(n_bytes):
                self.state.memory.store(ptr + i, self._sym_bytes[i])

            return claripy.BVV(n_bytes, self.state.arch.bits)

    return _SymbolicFread()


# ---------------------------------------------------------------------------
# PathExecutor
# ---------------------------------------------------------------------------

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
        """Return a full_init_state where stdin carries our symbolic bytes.

        Hooks fread/fgets so that the symbolic bytes are written directly into
        the destination buffer — this guarantees taint propagation even when
        angr's built-in SimProcedure does not forward SimFileStream content.
        """
        sym_bytes = self.make_symbolic_bytes()

        # Hook fread with our symbolic injector
        self.project.hook_symbol(
            "fread",
            _make_fread_hook(sym_bytes),
        )

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

    def collect_tainted_branches(
        self,
        initial_state: angr.SimState,
        sink_addr: int,
        timeout: int = 120,
    ) -> List[Dict[str, Any]]:
        """Explore from *initial_state* toward *sink_addr*, recording every
        conditional branch guard that depends on tainted (``sym_byte_*``)
        variables.

        Exploration stops once *sink_addr* is found (up to ``num_find=4``
        paths) or the step budget is exhausted.  No constraints are solved;
        no path is steered.  Results are deduplicated by branch_id.

        Returns
        -------
        list[dict]
            Each entry has: branch_id, guard_addr, guard_repr, taint_vars.
        """
        collector = _BranchCollector()

        def _step_cb(simgr):
            for s in simgr.active:
                collector.maybe_record(s)
            return simgr

        simgr = self.project.factory.simgr(initial_state, save_unsat=False)
        simgr.use_technique(angr.exploration_techniques.LengthLimiter(max_length=2000))
        simgr.explore(find=sink_addr, step_func=_step_cb, num_find=4)

        return collector.branches

    # ------------------------------------------------------------------
    # Constraint solver
    # ------------------------------------------------------------------

    _CMP_OPS = {
        ">=": lambda a, b: a >= b,
        "<=": lambda a, b: a <= b,
        ">":  lambda a, b: a > b,
        "<":  lambda a, b: a < b,
        "==": lambda a, b: a == b,
        "!=": lambda a, b: a != b,
    }

    def solve_with_decisions(
        self,
        initial_state: angr.SimState,
        sink_addr: int,
        branch_decisions: Dict[str, bool],
        attack_predicate: Optional[Dict[str, Any]] = None,
        timeout: int = 120,
    ) -> Dict[str, Any]:
        """Explore toward *sink_addr* under constraints.

        Parameters
        ----------
        initial_state : angr.SimState
            Symbolic state (usually from :meth:`initial_state_libc_stdin`).
        sink_addr : int
            Address of the target / sink function.
        branch_decisions : dict[str, bool]
            Maps ``branch_id`` to ``True`` (include — force the guard's accept
            side) or ``False`` (exclude).  Only keys with value ``True`` are
            enforced; ``False`` entries are ignored.
        attack_predicate : dict, optional
            If provided, composes symbolic bytes at ``byte_offset`` with
            ``width`` into a single BV and adds a comparison constraint:
            ``composed OP value``.  Keys: ``byte_offset``, ``width``, ``op``
            (one of ``>= <= > < == !=``), ``value`` (int).
        timeout : int
            Exploration timeout in seconds (default 120).

        Returns
        -------
        dict
            ``success`` (bool), ``reachable`` (bool), ``counterexample``
            (32-byte hex string or ``""``), ``sat_branches`` (list of
            branch_ids whose guards were satisfiable), ``paths_explored``
            (int), ``error`` (str or ``""``).
        """
        result: Dict[str, Any] = {
            "success": False,
            "reachable": False,
            "counterexample": "",
            "sat_branches": [],
            "paths_explored": 0,
            "error": "",
        }

        include_ids: Set[str] = {bid for bid, val in branch_decisions.items() if val}

        # --- Apply attack predicate as a pre-exploration constraint -------------
        if attack_predicate is not None:
            try:
                off = attack_predicate["byte_offset"]
                width = attack_predicate["width"]
                op_name = attack_predicate["op"]
                val = attack_predicate["value"]
                if width < 1 or width > TAINT_BUF_SIZE:
                    raise ValueError(f"width {width} out of range")
                if off + width > TAINT_BUF_SIZE:
                    raise ValueError(f"byte_offset+width exceeds buffer")
                raw_bytes = self._sym_bytes[off : off + width]
                # Compose in the target's native endianness so the BV matches
                # how the program interprets the bytes in memory.  Concat places
                # the first argument at the MSB; for little-endian, byte at
                # offset 0 is the LSB so we reverse.
                if self.project.arch.memory_endness == "Iend_LE":
                    composed = claripy.Concat(*reversed(raw_bytes))
                else:
                    composed = claripy.Concat(*raw_bytes)
                cmp_fn = self._CMP_OPS[op_name]
                constraint = cmp_fn(composed, val)
                initial_state.add_constraints(constraint)
            except Exception as exc:
                result["error"] = f"attack_predicate error: {exc}"
                result["success"] = True
                return result

        # --- Step function: record branches + force include guards ---------------
        sat_branches: List[str] = []
        paths_explored = 0

        def _step(simgr):
            nonlocal paths_explored
            paths_explored += len(simgr.active)

            to_remove = []
            for s in list(simgr.active):
                guard = None
                try:
                    guards = s.history.jump_guards
                    guard = guards[-1]
                except Exception:
                    pass
                if guard is None:
                    try:
                        guard = s.history.parent.jump_guard
                    except Exception:
                        continue
                if guard is None:
                    continue

                # Only care about symbolic guards tied to tainted bytes
                try:
                    if not guard.symbolic:
                        continue
                except AttributeError:
                    continue

                taint_vars = _ast_taint_vars(guard)
                if not taint_vars:
                    continue

                guard_addr = 0
                try:
                    bbl_addrs = s.history.bbl_addrs
                    if len(bbl_addrs):
                        guard_addr = bbl_addrs[-1]
                except Exception:
                    pass

                bid = _branch_id(guard_addr, guard)

                # If this branch is in the include set, add the guard as a
                # constraint so the state is forced down the accept path.
                if bid in include_ids:
                    if s.solver.satisfiable(extra_constraints=(guard,)):
                        s.add_constraints(guard)
                        if bid not in sat_branches:
                            sat_branches.append(bid)
                    else:
                        # Guard unsatisfiable with current constraints;
                        # drop this state.
                        to_remove.append(s)

            for s in to_remove:
                if s in simgr.active:
                    simgr.active.remove(s)

            return simgr

        # --- Explore ------------------------------------------------------------
        try:
            simgr = self.project.factory.simgr(initial_state, save_unsat=False)
            simgr.use_technique(angr.exploration_techniques.LengthLimiter(max_length=2000))
            simgr.explore(find=sink_addr, step_func=_step, num_find=1)
        except Exception as exc:
            result["error"] = str(exc)
            result["success"] = True
            result["paths_explored"] = paths_explored
            return result

        # --- Extract results ----------------------------------------------------
        result["paths_explored"] = paths_explored
        result["sat_branches"] = sat_branches

        if simgr.found:
            found_state = simgr.found[0]
            result["reachable"] = True
            # Evaluate 32 symbolic bytes to produce a concrete counterexample
            try:
                concrete = []
                for i in range(32):
                    if i < len(self._sym_bytes):
                        val = found_state.solver.eval(self._sym_bytes[i])
                    else:
                        val = 0
                    concrete.append(val)
                result["counterexample"] = bytes(concrete).hex()
            except Exception:
                result["counterexample"] = ""

        result["success"] = True
        return result
