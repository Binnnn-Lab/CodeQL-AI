import os
import pytest

from libs.symbolic_sanitizer.branch_scanner import scan_path_branches

FIX = os.path.join(os.path.dirname(__file__), "fixtures")


def test_scan_returns_enriched_branches(two_branches_binary):
    path = {
        "source": {
            "file_path": os.path.join(FIX, "two_branches.c"),
            "line_number": 10,
            "function_name": "vuln_entry",
        },
        "sink": {
            "file_path": os.path.join(FIX, "two_branches.c"),
            "line_number": 17,
            "function_name": "vuln_entry",
        },
        "intermediate_locations": [],
    }
    result = scan_path_branches(
        binary_path=two_branches_binary,
        path=path,
        source_mode="libc_stdin",
    )
    assert result["success"] is True
    branches = result["tainted_branches"]
    assert len(branches) >= 2
    for b in branches:
        assert "branch_id" in b
        assert "file" in b
        assert "line" in b
        assert "condition_src" in b
