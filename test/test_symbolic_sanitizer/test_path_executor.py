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
