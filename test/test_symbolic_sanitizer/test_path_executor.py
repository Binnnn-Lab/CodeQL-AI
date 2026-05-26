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
