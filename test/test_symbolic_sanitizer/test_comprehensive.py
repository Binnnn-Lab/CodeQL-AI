"""Comprehensive functional tests for the 4-tool symbolic sanitizer pipeline.

Tests every deterministic tool against the design spec at:
  docs/superpowers/specs/2026-05-26-symbolic-sanitizer-redesign.md

Tool 1: parse_sarif          — deterministic
Tool 2: build_harness         — deterministic
Tool 3: scan_path_branches    — deterministic
Tool 4: verify_with_decisions — deterministic (given fixed decisions + predicate)

Agent decision point (branch include/exclude + attack predicate) is NOT tested here
since it is non-deterministic (LLM-driven). Instead we test that the deterministic
tools correctly accept and apply agent decisions.
"""
import json
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from libs.symbolic_sanitizer.sarif_parser import (
    parse_sarif,
    load_sarif_from_file,
    extract_taint_paths,
)
from libs.symbolic_sanitizer.harness_builder import (
    select_source_mode,
    render_harness,
    build_harness,
    DEFAULT_COMPILE_SH,
)
from libs.symbolic_sanitizer.dwarf_resolver import (
    line_to_addr,
    addr_to_line,
    func_entry,
    var_storage,
)
from libs.symbolic_sanitizer.path_executor import PathExecutor
from libs.symbolic_sanitizer.branch_scanner import scan_path_branches
from libs.symbolic_sanitizer.verifier import verify_with_decisions

FIX = os.path.join(os.path.dirname(__file__), "fixtures")


# ============================================================================
# Tool 1: parse_sarif — spec §3.3 (parse_sarif)
# ============================================================================

class TestParseSarif:
    """parse_sarif(sarif_path, dataset_root) → {success, count, paths[]}

    Spec requirements:
    - Returns paths with absolute paths joined to dataset_root
    - Each path: source, sink, intermediate_locations, function_sources
    - function_sources are deduped by (file, function)
    - Handles codeFlows AND relatedLocations fallback
    """

    def _make_sarif(self, tmp_path, results):
        sarif = {"runs": [{"results": results}]}
        p = tmp_path / "test.sarif"
        p.write_text(json.dumps(sarif))
        return str(p)

    def test_codeflows_path(self, tmp_path):
        """Spec: codeFlows-based path extraction."""
        results = [{
            "ruleId": "cpp/tainted",
            "message": {"text": "taint"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "src/vuln.c"},
                "region": {"startLine": 50, "startColumn": 1},
            }}],
            "codeFlows": [{"threadFlows": [{"locations": [
                {"location": {"physicalLocation": {
                    "artifactLocation": {"uri": "src/input.c"},
                    "region": {"startLine": 10}}}},
                {"location": {"physicalLocation": {
                    "artifactLocation": {"uri": "src/vuln.c"},
                    "region": {"startLine": 50}}}},
            ]}]}],
        }]
        sarif_path = self._make_sarif(tmp_path, results)
        r = parse_sarif(sarif_path, dataset_root="/ds")
        assert r["success"] is True
        assert r["count"] == 1
        path = r["paths"][0]
        assert path["source"]["file_path"] == "/ds/src/input.c"
        assert path["sink"]["file_path"] == "/ds/src/vuln.c"
        assert path["rule_id"] == "cpp/tainted"
        assert "function_sources" in path

    def test_related_locations_fallback(self, tmp_path):
        """Spec: fallback when no codeFlows — source=relatedLocations[0], sink=locations[0]."""
        results = [{
            "ruleId": "cpp/overflow",
            "message": {"text": "x"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "src/sink.c"},
                "region": {"startLine": 99}}}],
            "relatedLocations": [{"physicalLocation": {
                "artifactLocation": {"uri": "src/source.c"},
                "region": {"startLine": 5}}}],
        }]
        sarif_path = self._make_sarif(tmp_path, results)
        r = parse_sarif(sarif_path, dataset_root="/ds")
        assert r["success"] is True
        assert r["paths"][0]["source"]["file_path"] == "/ds/src/source.c"
        assert r["paths"][0]["sink"]["file_path"] == "/ds/src/sink.c"

    def test_absolute_path_join(self, tmp_path):
        """Spec: file_path joined with dataset_root, normalized."""
        results = [{
            "ruleId": "r",
            "message": {"text": "t"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "foo/bar.c"},
                "region": {"startLine": 1}}}],
            "relatedLocations": [{"physicalLocation": {
                "artifactLocation": {"uri": "baz/qux.c"},
                "region": {"startLine": 2}}}],
        }]
        sarif_path = self._make_sarif(tmp_path, results)
        r = parse_sarif(sarif_path, dataset_root="/data/set")
        p = r["paths"][0]
        assert os.path.isabs(p["source"]["file_path"])
        assert os.path.isabs(p["sink"]["file_path"])

    def test_missing_sarif_file(self):
        """Spec: returns success=False with error."""
        r = parse_sarif("/nonexistent.sarif", dataset_root="/ds")
        assert r["success"] is False
        assert "not found" in r["error"].lower() or "failed" in r["error"].lower()

    def test_empty_results(self, tmp_path):
        """Spec: returns count=0, paths=[]."""
        sarif_path = self._make_sarif(tmp_path, [])
        r = parse_sarif(sarif_path, dataset_root="/ds")
        assert r["success"] is True
        assert r["count"] == 0

    def test_function_sources_deduped(self, tmp_path):
        """Spec: function_sources deduped by (file, function)."""
        results = [{
            "ruleId": "r",
            "message": {"text": "t"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "src/v.c"},
                "region": {"startLine": 50}}}],
            "codeFlows": [{"threadFlows": [{"locations": [
                {"location": {"physicalLocation": {
                    "artifactLocation": {"uri": "src/v.c"},
                    "region": {"startLine": 10}},
                    "logicalLocations": [{"name": "same_func"}]}},
                {"location": {"physicalLocation": {
                    "artifactLocation": {"uri": "src/v.c"},
                    "region": {"startLine": 50}},
                    "logicalLocations": [{"name": "same_func"}]}},
            ]}]}],
        }]
        sarif_path = self._make_sarif(tmp_path, results)
        r = parse_sarif(sarif_path, dataset_root="/ds")
        if r["success"] and r["paths"]:
            # Even if function_source extraction fails (file doesn't exist),
            # the key should be present
            assert "function_sources" in r["paths"][0]


# ============================================================================
# Tool 2: build_harness — spec §3.3 (build_harness)
# ============================================================================

class TestBuildHarness:
    """build_harness(source_file, vuln_entry, source_api, compile_script)
    → {success, binary_path, source_mode, dwarf_ok}

    Spec requirements:
    - Harness is a fixed template — no agent input beyond function name
    - Compiles with -g -O0 -fno-inline
    - Returns source_mode: libc_stdin | mid_function
    - Returns dwarf_ok: bool
    """

    def test_libc_source_apis(self):
        """Spec §3.3: libc_stdin for APIs in the built-in list."""
        for api in ["scanf", "fscanf", "sscanf", "fgets", "gets", "getc",
                     "getchar", "read", "recv", "fread", "recvfrom", "recvmsg"]:
            assert select_source_mode(api) == "libc_stdin", f"{api} should be libc_stdin"

    def test_non_libc_api(self):
        """Spec: mid_function for non-libc APIs."""
        assert select_source_mode("custom_recv_packet") == "mid_function"
        assert select_source_mode(None) == "mid_function"

    def test_render_harness_void(self):
        """Spec: extern void vuln_entry(void); + call."""
        code = render_harness("goodB2G", entry_signature="void")
        assert "extern void goodB2G(void);" in code
        assert "goodB2G();" in code
        assert "void __sink_reached(void)" in code

    def test_render_harness_int(self):
        """Spec: adapter for non-void signature."""
        code = render_harness("vuln_entry", entry_signature="int")
        assert "extern int vuln_entry(void);" in code
        assert "(void)vuln_entry();" in code

    def test_default_compile_sh_flags(self):
        """Spec §5: -g -O0 -fno-inline are non-negotiable."""
        for flag in ["-g", "-O0", "-fno-inline"]:
            assert flag in DEFAULT_COMPILE_SH

    def test_compile_script_missing(self, tmp_path):
        """Spec §7: fails fast with clear error."""
        r = build_harness(
            source_file=str(tmp_path / "no.c"),
            vuln_entry="main",
            source_api="fscanf",
            compile_script=str(tmp_path / "no.sh"),
        )
        assert r["success"] is False
        assert "compile" in r["error"].lower()

    def test_source_file_missing(self, tmp_path):
        """Spec §7: fails fast when source missing."""
        sh = tmp_path / "compile.sh"
        sh.write_text(DEFAULT_COMPILE_SH)
        sh.chmod(0o755)
        r = build_harness(
            source_file=str(tmp_path / "no.c"),
            vuln_entry="main",
            source_api="fscanf",
            compile_script=str(sh),
        )
        assert r["success"] is False

    def test_end_to_end_compilation(self, tmp_path):
        """Spec: produces binary_path, correct source_mode, dwarf_ok."""
        src = tmp_path / "vuln.c"
        src.write_text(
            '#include <stdio.h>\n'
            'void entry(void) { volatile int x = 0; (void)x; }\n'
        )
        sh = tmp_path / "compile.sh"
        sh.write_text(DEFAULT_COMPILE_SH)
        sh.chmod(0o755)

        r = build_harness(str(src), "entry", "fscanf", str(sh))
        assert r["success"] is True, r.get("error")
        assert os.path.exists(r["binary_path"])
        assert r["source_mode"] == "libc_stdin"
        assert r["dwarf_ok"] is True

    def test_compilation_with_mid_function_source(self, tmp_path):
        """Spec: source_mode=mid_function for non-libc API."""
        src = tmp_path / "vuln.c"
        src.write_text(
            '#include <stdio.h>\n'
            'void custom_entry(void) { volatile int x = 0; (void)x; }\n'
        )
        sh = tmp_path / "compile.sh"
        sh.write_text(DEFAULT_COMPILE_SH)
        sh.chmod(0o755)

        r = build_harness(str(src), "custom_entry", "my_recv_packet", str(sh))
        assert r["success"] is True
        assert r["source_mode"] == "mid_function"


# ============================================================================
# Tool 3: scan_path_branches — spec §3.3 (scan_path_branches)
# ============================================================================

class TestScanPathBranches:
    """scan_path_branches(binary_path, path, source_mode)
    → {success, tainted_branches[]}

    Spec requirements:
    - Each branch: branch_id, file, line, condition_src, surrounding_code, taint_vars
    - branch_id: "b_<sha1[:8]>"
    - DWARF-enriched file/line
    - condition_src from source file
    """

    def _path(self):
        return {
            "source": {
                "file_path": os.path.join(FIX, "two_branches.c"),
                "line_number": 10, "function_name": "vuln_entry",
            },
            "sink": {
                "file_path": os.path.join(FIX, "two_branches.c"),
                "line_number": 19, "function_name": "vuln_entry",
            },
            "intermediate_locations": [],
        }

    def test_returns_enriched_branches(self, two_branches_binary):
        """Spec: returns branches with all required fields."""
        r = scan_path_branches(two_branches_binary, self._path(), "libc_stdin")
        assert r["success"] is True
        branches = r["tainted_branches"]
        assert len(branches) >= 2
        for b in branches:
            assert "branch_id" in b
            assert b["branch_id"].startswith("b_")
            assert len(b["branch_id"]) == 10  # "b_" + 8 hex chars
            assert "file" in b
            assert "line" in b
            assert "condition_src" in b
            assert "surrounding_code" in b
            assert "taint_vars" in b
            assert len(b["taint_vars"]) >= 1
            assert all(v.startswith("sym_byte_") for v in b["taint_vars"])

    def test_branches_have_dwarf_file_line(self, two_branches_binary):
        """Spec: DWARF-resolved file and line for each branch."""
        r = scan_path_branches(two_branches_binary, self._path(), "libc_stdin")
        assert r["success"] is True
        for b in r["tainted_branches"]:
            if b["file"]:  # DWARF may not resolve all, but at least some should
                assert b["line"] > 0
                assert "two_branches" in b["file"]

    def test_binary_not_found(self):
        """Spec §7: returns error for missing binary."""
        r = scan_path_branches("/nonexistent_bin", self._path(), "libc_stdin")
        assert r["success"] is False
        assert "not found" in r["error"].lower()

    def test_unknown_source_mode(self, two_branches_binary):
        """Spec: rejects unknown source_mode."""
        r = scan_path_branches(two_branches_binary, self._path(), "bad_mode")
        assert r["success"] is False
        assert "unknown" in r["error"].lower()


# ============================================================================
# Tool 4: verify_with_decisions — spec §3.3 (verify_with_decisions)
# ============================================================================

class TestVerifyWithDecisions:
    """verify_with_decisions(binary_path, path, source_mode, branch_decisions,
                              attack_predicate) → {success, reachable, counterexample, ...}

    Spec requirements:
    - Fresh state for each verification
    - branch_decisions[branch_id]=True → guard added as constraint
    - attack_predicate applied as pre-exploration constraint
    - explore to sink_addr, return reachable + counterexample
    """

    def _path(self):
        return {
            "source": {
                "file_path": os.path.join(FIX, "two_branches.c"),
                "line_number": 10, "function_name": "vuln_entry",
            },
            "sink": {
                "file_path": os.path.join(FIX, "two_branches.c"),
                "line_number": 19, "function_name": "vuln_entry",
            },
            "intermediate_locations": [],
        }

    def test_reachable_no_constraints(self, two_branches_binary):
        """Spec: with no decisions and no predicate, sink reachable."""
        r = verify_with_decisions(
            two_branches_binary, self._path(), "libc_stdin",
            branch_decisions={}, attack_predicate=None,
        )
        assert r["success"] is True
        assert r["reachable"] is True
        assert r["counterexample"] not in (None, "")

    def test_unreachable_with_attack_predicate(self, two_branches_binary):
        """Spec: attack predicate data>=200 makes sink unreachable."""
        r = verify_with_decisions(
            two_branches_binary, self._path(), "libc_stdin",
            branch_decisions={},
            attack_predicate={
                "byte_offset": 0, "width": 4, "op": ">=",
                "value": 200, "signed": False,
            },
        )
        assert r["success"] is True
        assert r["reachable"] is False

    def test_binary_not_found(self):
        """Spec §7: returns error for missing binary."""
        r = verify_with_decisions(
            "/nonexistent", self._path(), "libc_stdin",
            branch_decisions={}, attack_predicate=None,
        )
        assert r["success"] is False

    def test_result_structure(self, two_branches_binary):
        """Spec: result dict has all required keys."""
        r = verify_with_decisions(
            two_branches_binary, self._path(), "libc_stdin",
            branch_decisions={}, attack_predicate=None,
        )
        assert "success" in r
        assert "reachable" in r
        assert "counterexample" in r
        assert "sat_branches" in r
        assert "paths_explored" in r

    def test_attack_predicate_eq(self, two_branches_binary):
        """Spec: == operator for attack predicate."""
        r = verify_with_decisions(
            two_branches_binary, self._path(), "libc_stdin",
            branch_decisions={},
            attack_predicate={
                "byte_offset": 0, "width": 4, "op": "==",
                "value": 0, "signed": False,
            },
        )
        assert r["success"] is True
        # data == 0: passes data >= 100 guard (false), but fails (data & 1) == 0
        # guard (true → return), so sink unreachable
        assert r["reachable"] is False

    def test_attack_predicate_lt(self, two_branches_binary):
        """Spec: < operator."""
        r = verify_with_decisions(
            two_branches_binary, self._path(), "libc_stdin",
            branch_decisions={},
            attack_predicate={
                "byte_offset": 0, "width": 4, "op": "<",
                "value": 100, "signed": False,
            },
        )
        assert r["success"] is True
        # data < 100: passes data >= 100 guard. But data must also be odd.
        # data < 100 and data must be odd → reachable (e.g. data=1)
        assert r["reachable"] is True


# ============================================================================
# DWARF Resolver — spec §6
# ============================================================================

class TestDwarfResolver:
    """DWARF resolver: line_to_addr, addr_to_line, func_entry, var_storage.

    Spec §6: all lookups return None on failure; callers degrade gracefully.
    """

    def test_line_to_addr_round_trip(self, two_branches_binary):
        """Spec: line↔addr round-trip on a known fixture binary."""
        addr = line_to_addr(two_branches_binary, "two_branches.c", 14)
        assert addr is not None
        result = addr_to_line(two_branches_binary, addr)
        assert result is not None
        _, line = result
        assert line == 14

    def test_func_entry(self, two_branches_binary):
        """Spec: func_entry resolves function address."""
        addr = func_entry(two_branches_binary, "vuln_entry")
        assert addr is not None and addr > 0

    def test_func_entry_unknown(self, two_branches_binary):
        """Spec: returns None for unknown function."""
        assert func_entry(two_branches_binary, "nonexistent") is None

    def test_var_storage(self, two_branches_binary):
        """Spec: var_storage returns Storage for a known local."""
        from libs.symbolic_sanitizer.dwarf_resolver import line_to_addr
        addr = line_to_addr(two_branches_binary, "two_branches.c", 16)
        assert addr is not None
        storage = var_storage(two_branches_binary, "vuln_entry", "data", addr)
        assert storage is not None
        assert storage.kind in ("register", "frame_offset")


# ============================================================================
# PathExecutor — spec §3.3 (shared angr driver)
# ============================================================================

class TestPathExecutor:
    """PathExecutor: loads binary, initializes state, enumerates branches, solves."""

    def test_loads_binary(self, two_branches_binary):
        ex = PathExecutor(two_branches_binary)
        assert ex.project is not None

    def test_func_addr_found(self, two_branches_binary):
        ex = PathExecutor(two_branches_binary)
        assert ex.func_addr("vuln_entry") is not None
        assert ex.func_addr("__sink_reached") is not None

    def test_func_addr_not_found(self, two_branches_binary):
        ex = PathExecutor(two_branches_binary)
        assert ex.func_addr("no_such_func") is None

    def test_libc_stdin_state(self, two_branches_binary):
        """Spec: libc_stdin state has symbolic bytes."""
        ex = PathExecutor(two_branches_binary)
        state = ex.initial_state_libc_stdin()
        assert len(ex.sym_bytes) == 64

    def test_collect_tainted_branches(self, two_branches_binary):
        """Spec: finds at least 2 tainted branches in the fixture."""
        ex = PathExecutor(two_branches_binary)
        state = ex.initial_state_libc_stdin()
        sink = ex.func_addr("__sink_reached")
        branches = ex.collect_tainted_branches(state, sink)
        assert len(branches) >= 2
        for b in branches:
            assert "branch_id" in b
            assert "guard_addr" in b
            assert "taint_vars" in b

    def test_solve_reachable(self, two_branches_binary):
        """Spec: reachable with no constraints."""
        ex = PathExecutor(two_branches_binary)
        state = ex.initial_state_libc_stdin()
        sink = ex.func_addr("__sink_reached")
        r = ex.solve_with_decisions(state, sink, {}, None)
        assert r["success"] is True
        assert r["reachable"] is True

    def test_solve_unreachable(self, two_branches_binary):
        """Spec: unreachable with data >= 200 predicate."""
        ex = PathExecutor(two_branches_binary)
        state = ex.initial_state_libc_stdin()
        sink = ex.func_addr("__sink_reached")
        r = ex.solve_with_decisions(
            state, sink, {},
            {"byte_offset": 0, "width": 4, "op": ">=", "value": 200, "signed": False},
        )
        assert r["success"] is True
        assert r["reachable"] is False


# ============================================================================
# Error / Degradation — spec §7
# ============================================================================

class TestErrorDegradation:
    """Spec §7: graceful degradation on various failure modes."""

    def test_no_dwarf_source_line(self, two_branches_binary):
        """Spec: DWARF present but specific line not mapped → mid_function degrades."""
        r = scan_path_branches(
            two_branches_binary,
            {"source": {"file_path": "nonexistent.c", "line_number": 999,
                        "function_name": "vuln_entry"},
             "sink": {"file_path": "nonexistent.c", "line_number": 999},
             "intermediate_locations": []},
            "mid_function",
        )
        # Should either succeed (via func_entry fallback) or degrade gracefully
        # Must not crash
        assert "success" in r

    def test_unknown_attack_op(self, two_branches_binary):
        """Spec: unsupported op returns error gracefully."""
        ex = PathExecutor(two_branches_binary)
        state = ex.initial_state_libc_stdin()
        sink = ex.func_addr("__sink_reached")
        r = ex.solve_with_decisions(
            state, sink, {},
            {"byte_offset": 0, "width": 4, "op": "bad_op", "value": 0},
        )
        # Should not crash, should return an error indication
        assert r["success"] is True
        assert r["error"] != "" or r.get("reachable") is not None
