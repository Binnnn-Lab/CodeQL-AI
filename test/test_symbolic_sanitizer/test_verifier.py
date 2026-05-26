import os
import pytest

from libs.symbolic_sanitizer.verifier import verify_with_decisions

FIX = os.path.join(os.path.dirname(__file__), "fixtures")


def _path():
    return {
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


def test_verify_reachable_no_constraints(two_branches_binary):
    r = verify_with_decisions(
        binary_path=two_branches_binary,
        path=_path(),
        source_mode="libc_stdin",
        branch_decisions={},
        attack_predicate=None,
    )
    assert r["success"] is True
    assert r["reachable"] is True


def test_verify_unreachable_with_attack_predicate(two_branches_binary):
    r = verify_with_decisions(
        binary_path=two_branches_binary,
        path=_path(),
        source_mode="libc_stdin",
        branch_decisions={},
        attack_predicate={
            "byte_offset": 0,
            "width": 4,
            "op": ">=",
            "value": 200,
            "signed": False,
        },
    )
    assert r["success"] is True
    assert r["reachable"] is False


def test_verify_uses_real_sink_line_without_marker(two_branches_no_marker_binary):
    path = {
        "source": {
            "file_path": os.path.join(FIX, "two_branches_no_marker.c"),
            "line_number": 8,
            "function_name": "vuln_entry",
        },
        "sink": {
            "file_path": os.path.join(FIX, "two_branches_no_marker.c"),
            "line_number": 15,
            "function_name": "vuln_entry",
        },
        "intermediate_locations": [],
    }
    r = verify_with_decisions(
        binary_path=two_branches_no_marker_binary,
        path=path,
        source_mode="libc_stdin",
        branch_decisions={},
        attack_predicate=None,
    )
    assert r["success"] is True
    assert r["reachable"] is True
    assert r.get("degraded") is None
