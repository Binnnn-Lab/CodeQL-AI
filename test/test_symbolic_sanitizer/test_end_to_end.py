"""End-to-end 4-tool pipeline validation using the two_branches fixture.

Exercises the full flow:
  build_harness -> scan_path_branches -> verify_with_decisions
"""
import os
import pytest

from libs.symbolic_sanitizer import (
    build_harness,
    scan_path_branches,
    verify_with_decisions,
    DEFAULT_HARNESS_COMPILE_SH,
)

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
            "line_number": 19,
            "function_name": "vuln_entry",
        },
        "intermediate_locations": [],
    }


class TestEndToEndFlow:
    """Full 4-tool pipeline: build_harness -> scan -> verify."""

    def test_full_pipeline_sink_reachable(self, two_branches_binary):
        """No branch decisions, no attack predicate -> sink reachable."""
        path = _path()

        # Step 1: scan
        scan = scan_path_branches(
            binary_path=two_branches_binary,
            path=path,
            source_mode="libc_stdin",
        )
        assert scan["success"] is True
        assert len(scan["tainted_branches"]) >= 2

        # Step 2: verify with no constraints -> reachable
        result = verify_with_decisions(
            binary_path=two_branches_binary,
            path=path,
            source_mode="libc_stdin",
            branch_decisions={},
            attack_predicate=None,
        )
        assert result["success"] is True
        assert result["reachable"] is True
        assert result["counterexample"] != ""

    def test_full_pipeline_sink_blocked(self, two_branches_binary):
        """Attack predicate data >= 200 -> sink unreachable (data >= 100 guard triggers)."""
        path = _path()

        result = verify_with_decisions(
            binary_path=two_branches_binary,
            path=path,
            source_mode="libc_stdin",
            branch_decisions={},
            attack_predicate={
                "byte_offset": 0, "width": 4, "op": ">=",
                "value": 200, "signed": False,
            },
        )
        assert result["success"] is True
        assert result["reachable"] is False

    def test_build_harness_integration(self, tmp_path):
        """build_harness compiles a harness-compatible source and produces a
        working binary that supports scan + verify.

        We write a source file *without* main/__sink_reached (the harness
        template provides those) but with the same branch logic so the scan
        and verify stages work on the harness-built binary.
        """
        # Source file that only contains vuln_entry (no main, no __sink_reached)
        src = tmp_path / "vuln.c"
        src.write_text(
            '#include <stdio.h>\n'
            '#include <string.h>\n'
            '#include <stdint.h>\n'
            '\n'
            'int vuln_entry(void) {\n'
            '    unsigned char buf[8];\n'
            '    if (fread(buf, 1, 8, stdin) != 8) return 0;\n'
            '    uint32_t data;\n'
            '    memcpy(&data, buf, 4);\n'
            '    if (data >= 100) return 1;\n'
            '    if ((data & 1) == 0) return 2;\n'
            '    __sink_reached();\n'
            '    return 0;\n'
            '}\n'
        )

        compile_sh = tmp_path / "compile.sh"
        compile_sh.write_text(DEFAULT_HARNESS_COMPILE_SH)
        compile_sh.chmod(0o755)

        r = build_harness(
            source_file=str(src),
            vuln_entry="vuln_entry",
            source_api="fread",
            compile_script=str(compile_sh),
            entry_signature="int",
        )
        assert r["success"] is True, r.get("error")
        assert os.path.exists(r["binary_path"])
        assert r["source_mode"] == "libc_stdin"
        assert r["dwarf_ok"] is True

        # Build a path dict pointing at the inline source
        harness_path = {
            "source": {
                "file_path": str(src),
                "line_number": 5,
                "function_name": "vuln_entry",
            },
            "sink": {
                "file_path": str(src),
                "line_number": 13,
                "function_name": "vuln_entry",
            },
            "intermediate_locations": [],
        }

        # The built binary should work for scan
        scan = scan_path_branches(
            binary_path=r["binary_path"],
            path=harness_path,
            source_mode="libc_stdin",
        )
        assert scan["success"] is True
        assert len(scan["tainted_branches"]) >= 2

        # And verify: sink should be reachable with no constraints
        v = verify_with_decisions(
            binary_path=r["binary_path"],
            path=harness_path,
            source_mode="libc_stdin",
            branch_decisions={},
            attack_predicate=None,
        )
        assert v["success"] is True
        assert v["reachable"] is True
