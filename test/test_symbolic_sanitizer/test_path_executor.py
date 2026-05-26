import pytest
from libs.symbolic_sanitizer.path_executor import PathExecutor


def test_loads_binary(two_branches_binary):
    ex = PathExecutor(two_branches_binary)
    assert ex.project is not None


def test_finds_function_address(two_branches_binary):
    ex = PathExecutor(two_branches_binary)
    addr = ex.func_addr("vuln_entry")
    assert addr is not None and addr > 0


def test_finds_sink_address(two_branches_binary):
    ex = PathExecutor(two_branches_binary)
    assert ex.func_addr("__sink_reached") is not None


def test_enumerates_two_tainted_branches(two_branches_binary):
    ex = PathExecutor(two_branches_binary)
    state = ex.initial_state_libc_stdin()
    sink_addr = ex.func_addr("__sink_reached")
    assert sink_addr is not None

    branches = ex.collect_tainted_branches(state, sink_addr, timeout=60)
    # Expect at least 2 (the two `if` statements). The exact count may include
    # extra compiler-generated branches but our two should always be there.
    assert len(branches) >= 2
    # Each branch has guard ast info and at least one taint variable name.
    for b in branches:
        assert "guard_addr" in b
        assert "taint_vars" in b
        assert len(b["taint_vars"]) >= 1


def test_solve_reachable_with_no_decisions(two_branches_binary):
    """With no constraints and no attack predicate, the sink should be reachable
    because some concrete input satisfies both branch guards (e.g. data=1)."""
    ex = PathExecutor(two_branches_binary)
    state = ex.initial_state_libc_stdin()
    sink_addr = ex.func_addr("__sink_reached")
    assert sink_addr is not None

    result = ex.solve_with_decisions(state, sink_addr, branch_decisions={})
    assert result["success"] is True
    assert result["reachable"] is True
    assert isinstance(result["counterexample"], str)
    assert len(result["counterexample"]) == 64  # 32 bytes hex
    # Verify the counterexample is valid hex
    bytes.fromhex(result["counterexample"])


def test_solve_unreachable_with_attack_predicate(two_branches_binary):
    """With attack predicate data >= 200 (byte_offset=0, width=4, op='>=', value=200),
    the sink is unreachable because the first guard 'data >= 100' would trigger
    an early return, blocking the path to __sink_reached."""
    ex = PathExecutor(two_branches_binary)
    state = ex.initial_state_libc_stdin()
    sink_addr = ex.func_addr("__sink_reached")
    assert sink_addr is not None

    attack_pred = {
        "byte_offset": 0,
        "width": 4,
        "op": ">=",
        "value": 200,
    }
    result = ex.solve_with_decisions(
        state, sink_addr, branch_decisions={}, attack_predicate=attack_pred
    )
    assert result["success"] is True
    assert result["reachable"] is False
