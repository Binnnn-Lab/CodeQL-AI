import os
from libs.symbolic_sanitizer.dwarf_resolver import (
    line_to_addr, addr_to_line,
)
from libs.symbolic_sanitizer.dwarf_resolver import func_entry, var_storage

FIXTURE_C = "two_branches.c"


def test_line_to_addr_resolves_known_line(two_branches_binary):
    addr = line_to_addr(two_branches_binary, FIXTURE_C, 12)  # memcpy(&data, buf, 4);
    assert addr is not None and addr > 0


def test_line_to_addr_returns_none_for_unknown_line(two_branches_binary):
    assert line_to_addr(two_branches_binary, FIXTURE_C, 99999) is None


def test_addr_to_line_round_trip(two_branches_binary):
    addr = line_to_addr(two_branches_binary, FIXTURE_C, 12)
    file_line = addr_to_line(two_branches_binary, addr)
    assert file_line is not None
    file, line = file_line
    assert file.endswith(FIXTURE_C)
    assert line == 12


def test_func_entry_resolves_vuln_entry(two_branches_binary):
    addr = func_entry(two_branches_binary, "vuln_entry")
    assert addr is not None and addr > 0


def test_func_entry_unknown_returns_none(two_branches_binary):
    assert func_entry(two_branches_binary, "no_such_function") is None


def test_var_storage_finds_local_data(two_branches_binary):
    # PC at the first tainted branch line (`if (data >= 100)`) — line 16
    addr_at_branch = line_to_addr(two_branches_binary, "two_branches.c", 16)
    assert addr_at_branch is not None
    storage = var_storage(two_branches_binary, "vuln_entry", "data", addr_at_branch)
    assert storage is not None
    assert storage.kind in ("register", "frame_offset")
