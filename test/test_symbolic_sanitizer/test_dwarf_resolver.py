import os
from libs.symbolic_sanitizer.dwarf_resolver import (
    line_to_addr, addr_to_line,
)

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
