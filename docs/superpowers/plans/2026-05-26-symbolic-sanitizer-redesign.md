# Symbolic Sanitizer Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the current 7-tool MCP pipeline with a 4-tool path-guided selective symbolic execution flow that runs angr over the real compiled binary, with DWARF-driven branch/variable resolution, and reduces agent reasoning to one decision point per path.

**Architecture:** `parse_sarif` (merged with path-context) → `build_harness` (template + compile original .c with `-g -O0 -fno-inline`) → `scan_path_branches` (taint-aware enumeration of guard conditions on the SARIF path) → agent picks include/exclude per branch + supplies an attack predicate over taint vars → `verify_with_decisions` (re-walk the path, add chosen guards as constraints, explore to sink). Shared angr driver in `path_executor.py`; DWARF in `dwarf_resolver.py`.

**Tech Stack:** Python 3.10+, `angr`, `claripy`, `pyelftools`, `fastmcp`, `pytest`. Juliet C testsuite as e2e fixture (`/data/benchmark/juliet/juliet-test-suite-c/`).

**Spec:** `docs/superpowers/specs/2026-05-26-symbolic-sanitizer-redesign.md`

---

## File Structure

**Create:**
- `src/libs/symbolic_sanitizer/dwarf_resolver.py` — pyelftools wrapper: `line_to_addr`, `addr_to_line`, `var_storage`, `func_entry`.
- `src/libs/symbolic_sanitizer/harness_builder.py` — replaces `harness_generator.py`. Template harness, source-mode selection, compile.sh template with `-g -O0 -fno-inline` enforcement.
- `src/libs/symbolic_sanitizer/path_executor.py` — shared angr driver. Loads binary, initializes state per `source_mode`, tags taint, walks path via intermediates.
- `src/libs/symbolic_sanitizer/branch_scanner.py` — `scan_path_branches`: uses `path_executor` in collect-only mode.
- `src/libs/symbolic_sanitizer/verifier.py` — `verify_with_decisions`: uses `path_executor` in verify mode, applies branch decisions + attack predicate, explores to sink.
- `test/test_symbolic_sanitizer/fixtures/two_branches.c` — synthetic taint fixture with two tainted `if` branches.
- `test/test_symbolic_sanitizer/fixtures/compile_fixtures.sh` — builds fixture binaries on demand.
- `test/test_symbolic_sanitizer/test_dwarf_resolver.py`
- `test/test_symbolic_sanitizer/test_harness_builder.py`
- `test/test_symbolic_sanitizer/test_branch_scanner.py`
- `test/test_symbolic_sanitizer/test_verifier.py`
- `test/test_symbolic_sanitizer/test_end_to_end_juliet.py`

**Modify:**
- `src/libs/symbolic_sanitizer/sarif_parser.py` — add `parse_sarif` (merges SARIF parse + absolute-path join + path-context read).
- `src/libs/symbolic_sanitizer/__init__.py` — re-export new symbols, remove deleted ones.
- `src/mcptools/symbolic_sanitizer.py` — shrink to 4 tools.
- `src/libs/symbolic_sanitizer/readme.md` — rewrite agent prompt for 4-tool flow.
- `requirements.txt` — add `angr`, `pyelftools`.
- `scripts/eval_symbolic_sanitizer.py` — drive the new 4-tool flow.

**Delete (after parity reached):**
- `src/libs/symbolic_sanitizer/harness_generator.py`
- `src/libs/symbolic_sanitizer/symbolic_sanitizer.py` (replaced by `path_executor.py` + `branch_scanner.py` + `verifier.py`)
- `test/test_symbolic_sanitizer/test_step5_harness_generation.py`
- `test/test_symbolic_sanitizer/test_step6_verify_with_constraints.py`

**Keep unchanged:**
- `src/libs/symbolic_sanitizer/path_context.py` — `find_enclosing_function` still used internally by `parse_sarif`.
- `src/libs/symbolic_sanitizer/compile_config.py` — `resolve_compile_config` / `write_compile_config` still used by `build_harness` for dataset-level compile.sh discovery.

---

## Task 1: Dependencies and Fixture Binary

**Files:**
- Modify: `requirements.txt`
- Create: `test/test_symbolic_sanitizer/fixtures/two_branches.c`
- Create: `test/test_symbolic_sanitizer/fixtures/compile_fixtures.sh`
- Create: `test/test_symbolic_sanitizer/conftest.py` (modify if exists)

- [ ] **Step 1: Add deps to `requirements.txt`**

Append exactly these two lines (keep existing lines):

```
angr==9.2.103
pyelftools==0.31
```

- [ ] **Step 2: Install**

Run: `pip install -r requirements.txt`
Expected: angr and pyelftools resolve cleanly.

- [ ] **Step 3: Write the synthetic fixture source**

Create `test/test_symbolic_sanitizer/fixtures/two_branches.c`:

```c
/* Two tainted branches for testing. Reads 8 bytes from stdin, the first 4
 * are interpreted as a uint32 'data'. Two if-guards involve 'data'; both
 * must be passed for __sink_reached() to be called. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

void __sink_reached(void) {}

int vuln_entry(void) {
    unsigned char buf[8];
    if (fread(buf, 1, 8, stdin) != 8) return 0;
    uint32_t data;
    memcpy(&data, buf, 4);

    if (data >= 100) return 1;           /* sanitizer-1 */
    if ((data & 1) == 0) return 2;       /* sanitizer-2 */

    __sink_reached();
    return 0;
}

int main(void) { return vuln_entry(); }
```

- [ ] **Step 4: Write the fixture compile script**

Create `test/test_symbolic_sanitizer/fixtures/compile_fixtures.sh`:

```bash
#!/bin/bash
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
gcc -g -O0 -fno-inline -o "$DIR/two_branches" "$DIR/two_branches.c"
echo "built $DIR/two_branches"
```

`chmod +x` it: `chmod +x test/test_symbolic_sanitizer/fixtures/compile_fixtures.sh`

- [ ] **Step 5: Add conftest fixture that builds on demand**

Append (or create) `test/test_symbolic_sanitizer/conftest.py` to ensure `two_branches` is built before tests that need it:

```python
import os
import subprocess
import pytest

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")

@pytest.fixture(scope="session")
def two_branches_binary():
    binary = os.path.join(FIXTURES, "two_branches")
    if not os.path.exists(binary):
        subprocess.run(
            ["bash", os.path.join(FIXTURES, "compile_fixtures.sh")],
            check=True,
        )
    return binary
```

- [ ] **Step 6: Verify fixture builds**

Run: `bash test/test_symbolic_sanitizer/fixtures/compile_fixtures.sh`
Expected: prints `built .../two_branches`; binary exists.

- [ ] **Step 7: Commit**

```bash
git add requirements.txt test/test_symbolic_sanitizer/fixtures test/test_symbolic_sanitizer/conftest.py
git commit -m "test: add deps and fixture binary for symbolic_sanitizer redesign"
```

---

## Task 2: DWARF Resolver — line_to_addr / addr_to_line

**Files:**
- Create: `src/libs/symbolic_sanitizer/dwarf_resolver.py`
- Create: `test/test_symbolic_sanitizer/test_dwarf_resolver.py`

- [ ] **Step 1: Write failing tests for line<->addr**

Create `test/test_symbolic_sanitizer/test_dwarf_resolver.py`:

```python
import os
from libs.symbolic_sanitizer.dwarf_resolver import (
    line_to_addr, addr_to_line,
)

FIXTURE_C = "two_branches.c"


def test_line_to_addr_resolves_known_line(two_branches_binary):
    addr = line_to_addr(two_branches_binary, FIXTURE_C, 13)  # uint32_t data;
    assert addr is not None and addr > 0


def test_line_to_addr_returns_none_for_unknown_line(two_branches_binary):
    assert line_to_addr(two_branches_binary, FIXTURE_C, 99999) is None


def test_addr_to_line_round_trip(two_branches_binary):
    addr = line_to_addr(two_branches_binary, FIXTURE_C, 13)
    file_line = addr_to_line(two_branches_binary, addr)
    assert file_line is not None
    file, line = file_line
    assert file.endswith(FIXTURE_C)
    assert line == 13
```

- [ ] **Step 2: Run tests to verify failure**

Run: `pytest test/test_symbolic_sanitizer/test_dwarf_resolver.py -v`
Expected: ImportError (module missing).

- [ ] **Step 3: Implement minimal `dwarf_resolver.py`**

Create `src/libs/symbolic_sanitizer/dwarf_resolver.py`:

```python
"""DWARF resolver — file:line <-> address, variable storage lookup."""
from __future__ import annotations

import os
from typing import Optional, Tuple, NamedTuple
from elftools.elf.elffile import ELFFile


class Storage(NamedTuple):
    kind: str          # "register" | "frame_offset"
    value: int         # reg num, or signed offset from CFA/fbreg


def _open_dwarf(binary_path: str):
    f = open(binary_path, "rb")
    elf = ELFFile(f)
    if not elf.has_dwarf_info():
        f.close()
        return None, None
    return f, elf.get_dwarf_info()


def line_to_addr(binary_path: str, source_file: str, line_number: int) -> Optional[int]:
    f, dwarf = _open_dwarf(binary_path)
    if dwarf is None:
        return None
    try:
        target_basename = os.path.basename(source_file)
        for cu in dwarf.iter_CUs():
            lineprog = dwarf.line_program_for_CU(cu)
            if lineprog is None:
                continue
            file_entries = lineprog["file_entry"]
            for entry in lineprog.get_entries():
                state = entry.state
                if state is None or state.end_sequence:
                    continue
                if state.line != line_number:
                    continue
                file_idx = state.file
                if file_idx == 0 or file_idx > len(file_entries):
                    continue
                fname = file_entries[file_idx - 1].name.decode("utf-8", "replace")
                if os.path.basename(fname) == target_basename:
                    return state.address
        return None
    finally:
        f.close()


def addr_to_line(binary_path: str, addr: int) -> Optional[Tuple[str, int]]:
    f, dwarf = _open_dwarf(binary_path)
    if dwarf is None:
        return None
    try:
        for cu in dwarf.iter_CUs():
            lineprog = dwarf.line_program_for_CU(cu)
            if lineprog is None:
                continue
            file_entries = lineprog["file_entry"]
            prev_state = None
            for entry in lineprog.get_entries():
                state = entry.state
                if state is None:
                    continue
                if state.end_sequence:
                    prev_state = None
                    continue
                if prev_state is not None and prev_state.address <= addr < state.address:
                    file_idx = prev_state.file
                    if file_idx == 0 or file_idx > len(file_entries):
                        continue
                    fname = file_entries[file_idx - 1].name.decode("utf-8", "replace")
                    return fname, prev_state.line
                prev_state = state
        return None
    finally:
        f.close()
```

- [ ] **Step 4: Run tests, verify pass**

Run: `pytest test/test_symbolic_sanitizer/test_dwarf_resolver.py -v`
Expected: all three pass. If line 13 doesn't have a DWARF entry (gcc may not emit one for a pure declaration), change the test to line 12 (`memcpy(&data, buf, 4);`).

- [ ] **Step 5: Commit**

```bash
git add src/libs/symbolic_sanitizer/dwarf_resolver.py test/test_symbolic_sanitizer/test_dwarf_resolver.py
git commit -m "feat: add DWARF line<->addr resolver"
```

---

## Task 3: DWARF Resolver — func_entry and var_storage

**Files:**
- Modify: `src/libs/symbolic_sanitizer/dwarf_resolver.py`
- Modify: `test/test_symbolic_sanitizer/test_dwarf_resolver.py`

- [ ] **Step 1: Write failing tests**

Append to `test_dwarf_resolver.py`:

```python
from libs.symbolic_sanitizer.dwarf_resolver import func_entry, var_storage


def test_func_entry_resolves_vuln_entry(two_branches_binary):
    addr = func_entry(two_branches_binary, "vuln_entry")
    assert addr is not None and addr > 0


def test_func_entry_unknown_returns_none(two_branches_binary):
    assert func_entry(two_branches_binary, "no_such_function") is None


def test_var_storage_finds_local_data(two_branches_binary):
    # PC at the first tainted branch line (`if (data >= 100)`) — line ~14
    addr_at_branch = line_to_addr(two_branches_binary, "two_branches.c", 14)
    assert addr_at_branch is not None
    storage = var_storage(two_branches_binary, "vuln_entry", "data", addr_at_branch)
    assert storage is not None
    assert storage.kind in ("register", "frame_offset")
```

(Add `from libs.symbolic_sanitizer.dwarf_resolver import line_to_addr` to imports if not already.)

- [ ] **Step 2: Run, verify failure**

Run: `pytest test/test_symbolic_sanitizer/test_dwarf_resolver.py::test_func_entry_resolves_vuln_entry -v`
Expected: ImportError.

- [ ] **Step 3: Implement `func_entry` and `var_storage`**

Append to `src/libs/symbolic_sanitizer/dwarf_resolver.py`:

```python
from elftools.dwarf.descriptions import describe_form_class
from elftools.dwarf.locationlists import LocationEntry, LocationParser


def func_entry(binary_path: str, func_name: str) -> Optional[int]:
    f, dwarf = _open_dwarf(binary_path)
    if dwarf is None:
        return None
    try:
        for cu in dwarf.iter_CUs():
            for die in cu.iter_DIEs():
                if die.tag != "DW_TAG_subprogram":
                    continue
                name_attr = die.attributes.get("DW_AT_name")
                if name_attr is None:
                    continue
                if name_attr.value.decode("utf-8", "replace") != func_name:
                    continue
                low_pc = die.attributes.get("DW_AT_low_pc")
                if low_pc is None:
                    continue
                return low_pc.value
        return None
    finally:
        f.close()


def _decode_simple_location(expr_bytes: bytes) -> Optional[Storage]:
    """Decode a single-op DWARF expression. Handles common cases:
    DW_OP_regN (0x50..0x6f), DW_OP_fbreg (0x91 + sleb128), DW_OP_breg6 (0x76 + sleb128).
    """
    if not expr_bytes:
        return None
    op = expr_bytes[0]
    if 0x50 <= op <= 0x6f:
        return Storage(kind="register", value=op - 0x50)
    if op == 0x91:  # DW_OP_fbreg <sleb128>
        offset = _read_sleb128(expr_bytes[1:])
        return Storage(kind="frame_offset", value=offset)
    if op == 0x76:  # DW_OP_breg6 (rbp) <sleb128>  -- treat like frame offset
        offset = _read_sleb128(expr_bytes[1:])
        return Storage(kind="frame_offset", value=offset)
    return None


def _read_sleb128(data: bytes) -> int:
    result = 0
    shift = 0
    for b in data:
        result |= (b & 0x7f) << shift
        shift += 7
        if (b & 0x80) == 0:
            if b & 0x40:  # sign bit
                result -= (1 << shift)
            return result
    return result


def var_storage(binary_path: str, func_name: str, var_name: str, pc: int) -> Optional[Storage]:
    f, dwarf = _open_dwarf(binary_path)
    if dwarf is None:
        return None
    try:
        loc_lists = dwarf.location_lists()
        parser = LocationParser(loc_lists) if loc_lists is not None else None
        for cu in dwarf.iter_CUs():
            for die in cu.iter_DIEs():
                if die.tag != "DW_TAG_subprogram":
                    continue
                name_attr = die.attributes.get("DW_AT_name")
                if name_attr is None or name_attr.value.decode("utf-8", "replace") != func_name:
                    continue
                for child in die.iter_children():
                    if child.tag not in ("DW_TAG_variable", "DW_TAG_formal_parameter"):
                        continue
                    cname = child.attributes.get("DW_AT_name")
                    if cname is None or cname.value.decode("utf-8", "replace") != var_name:
                        continue
                    loc_attr = child.attributes.get("DW_AT_location")
                    if loc_attr is None:
                        return None
                    form = loc_attr.form
                    if form in ("DW_FORM_exprloc", "DW_FORM_block", "DW_FORM_block1"):
                        return _decode_simple_location(bytes(loc_attr.value))
                    if parser is not None and parser.attribute_has_location(loc_attr, cu["version"]):
                        loclist = parser.parse_from_attribute(loc_attr, cu["version"])
                        for entry in loclist:
                            if isinstance(entry, LocationEntry):
                                if entry.begin_offset <= pc < entry.end_offset:
                                    return _decode_simple_location(bytes(entry.loc_expr))
                    return None
        return None
    finally:
        f.close()
```

- [ ] **Step 4: Run all dwarf_resolver tests**

Run: `pytest test/test_symbolic_sanitizer/test_dwarf_resolver.py -v`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/libs/symbolic_sanitizer/dwarf_resolver.py test/test_symbolic_sanitizer/test_dwarf_resolver.py
git commit -m "feat: add DWARF func_entry and var_storage resolvers"
```

---

## Task 4: Merge `parse_sarif` with path-context read

**Files:**
- Modify: `src/libs/symbolic_sanitizer/sarif_parser.py`
- Modify: `src/libs/symbolic_sanitizer/__init__.py`
- Create: `test/test_symbolic_sanitizer/test_parse_sarif.py`

- [ ] **Step 1: Write failing test**

Create `test/test_symbolic_sanitizer/test_parse_sarif.py`:

```python
import json
import os
import pytest

from libs.symbolic_sanitizer.sarif_parser import parse_sarif

FIX = os.path.join(os.path.dirname(__file__), "fixtures")


def test_parse_sarif_joins_absolute_paths(tmp_path):
    sarif = {
        "runs": [{
            "results": [{
                "ruleId": "test/rule",
                "message": {"text": "x"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "src/foo.c"},
                        "region": {"startLine": 1, "startColumn": 1},
                    }
                }],
                "relatedLocations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "src/bar.c"},
                        "region": {"startLine": 1, "startColumn": 1},
                    }
                }],
            }]
        }]
    }
    p = tmp_path / "x.sarif"
    p.write_text(json.dumps(sarif))
    result = parse_sarif(str(p), dataset_root="/tmp/ds")
    assert result["success"] is True
    assert len(result["paths"]) == 1
    path = result["paths"][0]
    assert path["source"]["file_path"] == "/tmp/ds/src/bar.c"
    assert path["sink"]["file_path"] == "/tmp/ds/src/foo.c"
    assert "function_sources" in path  # may be empty (files don't exist), key present


def test_parse_sarif_missing_file_returns_error(tmp_path):
    result = parse_sarif(str(tmp_path / "nope.sarif"), dataset_root="/tmp/ds")
    assert result["success"] is False
```

- [ ] **Step 2: Run test, verify failure**

Run: `pytest test/test_symbolic_sanitizer/test_parse_sarif.py -v`
Expected: ImportError on `parse_sarif`.

- [ ] **Step 3: Implement `parse_sarif`**

Append to `src/libs/symbolic_sanitizer/sarif_parser.py`:

```python
import os
from .path_context import find_enclosing_function


def parse_sarif(sarif_path: str, dataset_root: str) -> dict:
    """Parse SARIF, join paths to absolute, attach enclosing-function source for
    every (file, function) appearing on any path. Single entrypoint — replaces
    the old parse_sarif_detailed + read_path_context pair.
    """
    if not os.path.exists(sarif_path):
        return {"success": False, "error": f"SARIF file not found: {sarif_path}"}

    try:
        sarif_data = load_sarif_from_file(sarif_path)
    except Exception as e:
        return {"success": False, "error": f"Failed to load SARIF: {e}"}

    try:
        taint_paths = extract_taint_paths(sarif_data)
    except Exception as e:
        return {"success": False, "error": f"Failed to extract taint paths: {e}"}

    def _absify(node: dict) -> dict:
        rel = node.get("file_path", "")
        if rel and not os.path.isabs(rel):
            node = dict(node)
            node["file_path"] = os.path.normpath(os.path.join(dataset_root, rel))
        return node

    out_paths = []
    for tp in taint_paths:
        source = _absify(tp.source)
        sink = _absify(tp.sink)
        intermediates = [_absify(loc) for loc in tp.intermediate_locations]

        sources_by_key: dict = {}
        for node in [source, sink, *intermediates]:
            file_path = node.get("file_path", "")
            line = node.get("line_number", 0)
            if not file_path or not line:
                continue
            res = find_enclosing_function(file_path, line)
            if not res.get("success"):
                continue
            key = (file_path, res.get("function_name") or "")
            sources_by_key.setdefault(key, {
                "file_path": file_path,
                "function_name": res.get("function_name"),
                "function_source": res.get("function_source") or res.get("source"),
                "start_line": res.get("start_line"),
                "end_line": res.get("end_line"),
            })

        out_paths.append({
            "path_id": tp.path_id,
            "rule_id": tp.rule_id,
            "message": tp.message,
            "source": source,
            "sink": sink,
            "intermediate_locations": intermediates,
            "function_sources": list(sources_by_key.values()),
        })

    return {"success": True, "count": len(out_paths), "paths": out_paths}
```

(If `find_enclosing_function` returns a different shape, adapt the keys accordingly — read its actual signature in `path_context.py` first and match it.)

- [ ] **Step 4: Export from package**

Modify `src/libs/symbolic_sanitizer/__init__.py` to add `parse_sarif`:

```python
from .sarif_parser import (
    load_sarif_from_file,
    extract_taint_paths,
    parse_sarif,
    TaintPath,
)
```

(Add `'parse_sarif'` to `__all__`.)

- [ ] **Step 5: Run tests**

Run: `pytest test/test_symbolic_sanitizer/test_parse_sarif.py -v`
Expected: both pass.

- [ ] **Step 6: Commit**

```bash
git add src/libs/symbolic_sanitizer/sarif_parser.py src/libs/symbolic_sanitizer/__init__.py test/test_symbolic_sanitizer/test_parse_sarif.py
git commit -m "feat: merge parse_sarif with path-context read"
```

---

## Task 5: Harness Builder — template and source-mode selection

**Files:**
- Create: `src/libs/symbolic_sanitizer/harness_builder.py`
- Create: `test/test_symbolic_sanitizer/test_harness_builder.py`
- Modify: `src/libs/symbolic_sanitizer/__init__.py`

- [ ] **Step 1: Write failing tests**

Create `test/test_symbolic_sanitizer/test_harness_builder.py`:

```python
import os
import pytest

from libs.symbolic_sanitizer.harness_builder import (
    select_source_mode, render_harness, build_harness,
    DEFAULT_COMPILE_SH,
)


def test_select_source_mode_libc():
    assert select_source_mode("fscanf") == "libc_stdin"
    assert select_source_mode("fgets") == "libc_stdin"
    assert select_source_mode("read") == "libc_stdin"


def test_select_source_mode_unknown():
    assert select_source_mode("custom_recv_packet") == "mid_function"


def test_select_source_mode_none():
    assert select_source_mode(None) == "mid_function"


def test_render_harness_void_entry():
    code = render_harness(vuln_entry="goodB2G", entry_signature="void")
    assert "extern void goodB2G(void);" in code
    assert "goodB2G();" in code
    assert "void __sink_reached(void)" in code


def test_render_harness_int_entry():
    code = render_harness(vuln_entry="vuln_entry", entry_signature="int")
    assert "extern int vuln_entry(void);" in code
    assert "(void)vuln_entry();" in code


def test_default_compile_sh_has_g_O0_fno_inline():
    assert "-g" in DEFAULT_COMPILE_SH
    assert "-O0" in DEFAULT_COMPILE_SH
    assert "-fno-inline" in DEFAULT_COMPILE_SH


def test_build_harness_missing_compile_script(tmp_path):
    res = build_harness(
        source_file=str(tmp_path / "no.c"),
        vuln_entry="vuln_entry",
        source_api="fscanf",
        compile_script=str(tmp_path / "no_compile.sh"),
    )
    assert res["success"] is False
    assert "compile" in res["error"].lower()


def test_build_harness_end_to_end(tmp_path):
    src = tmp_path / "vuln.c"
    src.write_text(
        '#include <stdio.h>\n'
        'void vuln_entry(void) { volatile int x = 0; (void)x; }\n'
    )
    compile_sh = tmp_path / "compile.sh"
    compile_sh.write_text(DEFAULT_COMPILE_SH)
    compile_sh.chmod(0o755)

    res = build_harness(
        source_file=str(src),
        vuln_entry="vuln_entry",
        source_api="fscanf",
        compile_script=str(compile_sh),
    )
    assert res["success"] is True, res.get("error")
    assert os.path.exists(res["binary_path"])
    assert res["source_mode"] == "libc_stdin"
    assert res["dwarf_ok"] is True
```

- [ ] **Step 2: Run, verify failure**

Run: `pytest test/test_symbolic_sanitizer/test_harness_builder.py -v`
Expected: ImportError.

- [ ] **Step 3: Implement `harness_builder.py`**

Create `src/libs/symbolic_sanitizer/harness_builder.py`:

```python
"""Harness builder — template harness + compile via dataset compile.sh."""
from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

LIBC_SOURCE_APIS = frozenset({
    "scanf", "fscanf", "sscanf", "fgets", "gets", "getc", "getchar",
    "read", "recv", "fread", "recvfrom", "recvmsg",
})

DEFAULT_COMPILE_SH = r"""#!/bin/bash
# Args: <harness_src> <original_src> <output_binary> <lang>
HARNESS="$1"; ORIG="$2"; OUT="$3"; LANG="${4:-c}"
case "$LANG" in
  cpp) CC=g++ ; STD=-std=c++17 ;;
  *)   CC=gcc ; STD=-std=c11   ;;
esac
"$CC" $STD -g -O0 -fno-inline "$HARNESS" "$ORIG" -o "$OUT" -lm 2>&1
"""


def select_source_mode(source_api: Optional[str]) -> str:
    if source_api and source_api in LIBC_SOURCE_APIS:
        return "libc_stdin"
    return "mid_function"


def render_harness(vuln_entry: str, entry_signature: str = "void") -> str:
    """Render a minimal harness that calls the original vuln entry function.

    entry_signature: 'void' (no return value handling) or 'int' (cast away).
    """
    if entry_signature == "void":
        extern = f"extern void {vuln_entry}(void);"
        call = f"{vuln_entry}();"
    else:
        extern = f"extern int {vuln_entry}(void);"
        call = f"(void){vuln_entry}();"
    return (
        "#include <stdio.h>\n"
        f"{extern}\n"
        "void __sink_reached(void) {}\n"
        "int main(void) {\n"
        f"    {call}\n"
        "    return 0;\n"
        "}\n"
    )


_CPP_EXTS = {".cpp", ".cc", ".cxx", ".c++", ".C", ".hpp", ".hh", ".hxx"}


def _infer_lang(source_file: str) -> str:
    return "cpp" if Path(source_file).suffix in _CPP_EXTS else "c"


def _has_dwarf(binary_path: str) -> bool:
    try:
        from elftools.elf.elffile import ELFFile
        with open(binary_path, "rb") as f:
            return ELFFile(f).has_dwarf_info()
    except Exception:
        return False


def build_harness(
    source_file: str,
    vuln_entry: str,
    source_api: Optional[str],
    compile_script: str,
    entry_signature: str = "void",
) -> dict:
    if not os.path.exists(source_file):
        return {"success": False, "error": f"source_file missing: {source_file}"}
    if not os.path.exists(compile_script):
        return {"success": False, "error": f"compile_script missing: {compile_script}"}

    lang = _infer_lang(source_file)
    harness_ext = ".cpp" if lang == "cpp" else ".c"
    tmpdir = tempfile.mkdtemp(prefix="symbolic_harness_")
    harness_path = os.path.join(tmpdir, f"harness{harness_ext}")
    binary_path = os.path.join(tmpdir, "harness_bin")

    code = render_harness(vuln_entry, entry_signature=entry_signature)
    with open(harness_path, "w") as f:
        f.write(code)

    try:
        proc = subprocess.run(
            ["bash", compile_script, harness_path, source_file, binary_path, lang],
            capture_output=True, text=True, timeout=120,
        )
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "compile timed out (120s)", "harness_path": harness_path}

    if proc.returncode != 0:
        return {
            "success": False,
            "error": f"compile failed: {proc.stderr.strip() or proc.stdout.strip()}",
            "harness_path": harness_path,
        }

    return {
        "success": True,
        "binary_path": binary_path,
        "harness_path": harness_path,
        "source_mode": select_source_mode(source_api),
        "dwarf_ok": _has_dwarf(binary_path),
        "error": None,
    }
```

- [ ] **Step 4: Re-export**

Modify `src/libs/symbolic_sanitizer/__init__.py`: add `from .harness_builder import build_harness, select_source_mode, render_harness, DEFAULT_COMPILE_SH` (and to `__all__`).

- [ ] **Step 5: Run tests**

Run: `pytest test/test_symbolic_sanitizer/test_harness_builder.py -v`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add src/libs/symbolic_sanitizer/harness_builder.py src/libs/symbolic_sanitizer/__init__.py test/test_symbolic_sanitizer/test_harness_builder.py
git commit -m "feat: add harness builder with template + source-mode selection"
```

---

## Task 6: Path Executor — shared angr driver

**Files:**
- Create: `src/libs/symbolic_sanitizer/path_executor.py`
- Create: `test/test_symbolic_sanitizer/test_path_executor.py`

`path_executor.py` is the single place that knows angr. Both `branch_scanner` and `verifier` build on it. It exposes:

- `PathExecutor(binary_path)` — loads project.
- `.initial_state(source_mode, source_addr=None, source_func=None)` — builds the entry state.
- `.symbolic_input_bvs()` — returns the list of symbolic 8-bit BVs (so callers can store them or constrain them); for `libc_stdin` they live in the SimFile content; for `mid_function` they're explicitly stored at a `symbolic_input` global region the executor allocates.
- `.walk_to(state, target_addr, avoid=()) -> simgr` — angr `explore` wrapper.
- `.find_tainted_branches_along(initial_state, intermediates, sink_addr) -> list[dict]` — used by `branch_scanner`.
- `.solve_with_decisions(initial_state, intermediates, sink_addr, decisions, predicate) -> dict` — used by `verifier`.

Decision on taint tracking: tag the initial symbolic bytes with `claripy` annotations carrying a `taint_id`; check guard ASTs for annotated leaves via `state.solver.constraints[-1].variables` (variable names are stable since we name them `sym_byte_N`).

- [ ] **Step 1: Write failing tests (skeleton)**

Create `test/test_symbolic_sanitizer/test_path_executor.py`:

```python
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
```

- [ ] **Step 2: Run, verify failure**

Run: `pytest test/test_symbolic_sanitizer/test_path_executor.py -v`
Expected: ImportError.

- [ ] **Step 3: Implement `path_executor.py` core**

Create `src/libs/symbolic_sanitizer/path_executor.py`:

```python
"""Shared angr driver for branch scanning and verification."""
from __future__ import annotations

import logging
from typing import List, Dict, Optional, Tuple, Any

import angr
import claripy

logger = logging.getLogger(__name__)

TAINT_BUF_SIZE = 64


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
        sym_bytes = self.make_symbolic_bytes()
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
```

- [ ] **Step 4: Run tests**

Run: `pytest test/test_symbolic_sanitizer/test_path_executor.py -v`
Expected: all 3 pass.

- [ ] **Step 5: Commit**

```bash
git add src/libs/symbolic_sanitizer/path_executor.py test/test_symbolic_sanitizer/test_path_executor.py
git commit -m "feat: add angr path executor scaffolding"
```

---

## Task 7: Path Executor — branch enumeration

**Files:**
- Modify: `src/libs/symbolic_sanitizer/path_executor.py`
- Modify: `test/test_symbolic_sanitizer/test_path_executor.py`

- [ ] **Step 1: Write failing test**

Append to `test_path_executor.py`:

```python
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
```

- [ ] **Step 2: Run, verify failure**

Run: `pytest test/test_symbolic_sanitizer/test_path_executor.py::test_enumerates_two_tainted_branches -v`
Expected: AttributeError — `collect_tainted_branches` missing.

- [ ] **Step 3: Implement branch collection**

Append to `src/libs/symbolic_sanitizer/path_executor.py`:

```python
import hashlib


def _ast_taint_vars(ast) -> List[str]:
    """Return the set of symbolic byte variables (by name) that the AST depends on."""
    if not hasattr(ast, "variables"):
        return []
    return sorted(v for v in ast.variables if v.startswith("sym_byte_"))


def _branch_id(guard_addr: int, ast) -> str:
    h = hashlib.sha1(f"{guard_addr:x}:{ast!r}".encode()).hexdigest()[:8]
    return f"b_{h}"


class _BranchCollector:
    """Run under angr exploration; on every symbolic conditional jump where the
    guard depends on tainted bytes, record it. We do not steer the search."""

    def __init__(self):
        self.branches: List[Dict[str, Any]] = []
        self._seen_ids: set = set()

    def maybe_record(self, state):
        # angr stores guard history via state.history.jump_guards
        try:
            guard = state.history.jump_guards[-1]
        except Exception:
            return
        if guard is None or guard.symbolic is False:
            return
        taint_vars = _ast_taint_vars(guard)
        if not taint_vars:
            return
        # Use the address of the branching IRSB
        guard_addr = state.history.bbl_addrs[-1] if len(state.history.bbl_addrs) else 0
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


def _add_method(cls, name):
    def _wrap(fn):
        setattr(cls, name, fn)
        return fn
    return _wrap


@_add_method(PathExecutor, "collect_tainted_branches")
def _collect_tainted_branches(self, initial_state, sink_addr: int, timeout: int = 120):
    """Explore from initial_state toward sink_addr, recording every tainted
    branch guard seen along ANY explored path."""
    collector = _BranchCollector()

    def _step_cb(simgr):
        for s in simgr.active:
            collector.maybe_record(s)
        return simgr

    simgr = self.project.factory.simgr(initial_state, save_unsat=False)
    simgr.use_technique(angr.exploration_techniques.LengthLimiter(max_length=2000))
    simgr.explore(find=sink_addr, step_func=_step_cb, num_find=4)
    return collector.branches
```

- [ ] **Step 4: Run test**

Run: `pytest test/test_symbolic_sanitizer/test_path_executor.py::test_enumerates_two_tainted_branches -v --timeout=120`
Expected: passes with `len(branches) >= 2`. If angr exploration takes too long, lower the LengthLimiter or add `simgr.run(n=200)` instead of `.explore(...)`.

- [ ] **Step 5: Commit**

```bash
git add src/libs/symbolic_sanitizer/path_executor.py test/test_symbolic_sanitizer/test_path_executor.py
git commit -m "feat: enumerate tainted branches via path executor"
```

---

## Task 8: Path Executor — solve_with_decisions

**Files:**
- Modify: `src/libs/symbolic_sanitizer/path_executor.py`
- Modify: `test/test_symbolic_sanitizer/test_path_executor.py`

- [ ] **Step 1: Write failing tests**

Append to `test_path_executor.py`:

```python
def test_solve_reachable_with_no_decisions(two_branches_binary):
    """With no constraints, sink is reachable (input that satisfies all guards exists)."""
    ex = PathExecutor(two_branches_binary)
    state = ex.initial_state_libc_stdin()
    sink_addr = ex.func_addr("__sink_reached")
    result = ex.solve_with_decisions(
        state, sink_addr,
        branch_decisions={},
        attack_predicate=None,
        timeout=120,
    )
    assert result["reachable"] is True
    assert result["counterexample"] is not None


def test_solve_unreachable_with_attack_predicate(two_branches_binary):
    """Attack predicate `data >= 200` combined with the natural sanitizer
    (`if data >= 100 return`) makes sink unreachable."""
    ex = PathExecutor(two_branches_binary)
    state = ex.initial_state_libc_stdin()
    sink_addr = ex.func_addr("__sink_reached")
    result = ex.solve_with_decisions(
        state, sink_addr,
        branch_decisions={},
        attack_predicate={
            "byte_offset": 0,
            "width": 4,
            "op": ">=",
            "value": 200,
            "signed": False,
        },
        timeout=120,
    )
    assert result["reachable"] is False
```

(Note: at this stage we constrain via byte_offset (position in stdin) rather than DWARF var name — that integration comes in Task 9 inside `verifier.py`. The path_executor only needs to accept a pre-resolved offset/width.)

- [ ] **Step 2: Run, verify failure**

Run: `pytest test/test_symbolic_sanitizer/test_path_executor.py -v --timeout=180`
Expected: failures on the two new tests.

- [ ] **Step 3: Implement `solve_with_decisions`**

Append to `src/libs/symbolic_sanitizer/path_executor.py`:

```python
@_add_method(PathExecutor, "solve_with_decisions")
def _solve_with_decisions(self, initial_state, sink_addr: int,
                          branch_decisions: Dict[str, bool],
                          attack_predicate: Optional[Dict[str, Any]],
                          timeout: int = 120) -> Dict[str, Any]:
    state = initial_state

    if attack_predicate:
        offset = int(attack_predicate["byte_offset"])
        width = int(attack_predicate["width"])
        op = attack_predicate["op"]
        value = int(attack_predicate["value"])
        signed = bool(attack_predicate.get("signed", False))
        composed = claripy.Concat(*reversed(self.sym_bytes[offset:offset + width]))
        if op == ">=":
            constr = (claripy.SGE(composed, value) if signed
                      else claripy.UGE(composed, value))
        elif op == "<=":
            constr = (claripy.SLE(composed, value) if signed
                      else claripy.ULE(composed, value))
        elif op == ">":
            constr = (claripy.SGT(composed, value) if signed
                      else claripy.UGT(composed, value))
        elif op == "<":
            constr = (claripy.SLT(composed, value) if signed
                      else claripy.ULT(composed, value))
        elif op == "==":
            constr = (composed == value)
        elif op == "!=":
            constr = (composed != value)
        else:
            return {"success": False, "reachable": False,
                    "error": f"unsupported op: {op}",
                    "counterexample": None, "sat_branches": [], "paths_explored": 0}
        state.solver.add(constr)
        if not state.solver.satisfiable():
            return {"success": True, "reachable": False, "counterexample": None,
                    "sat_branches": [], "paths_explored": 0, "error": None}

    # branch_decisions are applied lazily inside the step callback: every time
    # we encounter a guard that matches an "include" branch_id, AND its guard
    # expression onto the state's constraints.
    included = {bid for bid, take in branch_decisions.items() if take}
    sat_branches: List[str] = []

    def _step_cb(simgr):
        for s in simgr.active:
            try:
                guard = s.history.jump_guards[-1]
                if guard is None or not guard.symbolic:
                    continue
                taint_vars = _ast_taint_vars(guard)
                if not taint_vars:
                    continue
                guard_addr = s.history.bbl_addrs[-1] if len(s.history.bbl_addrs) else 0
                bid = _branch_id(guard_addr, guard)
                if bid in included and bid not in sat_branches:
                    s.solver.add(guard)
                    sat_branches.append(bid)
            except Exception:
                continue
        return simgr

    simgr = self.project.factory.simgr(state, save_unsat=False)
    simgr.use_technique(angr.exploration_techniques.LengthLimiter(max_length=2000))
    simgr.explore(find=sink_addr, step_func=_step_cb, num_find=1)

    counterexample = None
    reachable = bool(simgr.found)
    if reachable:
        found = simgr.found[0]
        try:
            concrete = bytes([found.solver.eval(b, cast_to=int) for b in self.sym_bytes[:32]])
            counterexample = concrete.hex()
        except Exception:
            counterexample = "extraction_failed"

    return {
        "success": True,
        "reachable": reachable,
        "counterexample": counterexample,
        "sat_branches": sat_branches,
        "paths_explored": (
            len(simgr.found) + len(getattr(simgr, "deadended", [])) +
            len(getattr(simgr, "active", [])) + len(getattr(simgr, "errored", []))
        ),
        "error": None,
    }
```

- [ ] **Step 4: Run tests**

Run: `pytest test/test_symbolic_sanitizer/test_path_executor.py -v --timeout=240`
Expected: all pass. If reachability semantics differ (e.g. fixture sink is `unreachable` without satisfying both guards naturally), adjust the attack predicate values to match the fixture's logic.

- [ ] **Step 5: Commit**

```bash
git add src/libs/symbolic_sanitizer/path_executor.py test/test_symbolic_sanitizer/test_path_executor.py
git commit -m "feat: solve_with_decisions in path executor"
```

---

## Task 9: branch_scanner.py — thin tool wrapper

**Files:**
- Create: `src/libs/symbolic_sanitizer/branch_scanner.py`
- Create: `test/test_symbolic_sanitizer/test_branch_scanner.py`

`scan_path_branches` is a tool entrypoint. It uses `PathExecutor` plus
`dwarf_resolver` to enrich each branch with `file:line`, `condition_src`, and
DWARF-visible taint variable names (instead of raw `sym_byte_N`).

- [ ] **Step 1: Write failing test**

Create `test/test_symbolic_sanitizer/test_branch_scanner.py`:

```python
import os
import pytest

from libs.symbolic_sanitizer.branch_scanner import scan_path_branches

FIX = os.path.join(os.path.dirname(__file__), "fixtures")


def test_scan_returns_enriched_branches(two_branches_binary):
    path = {
        "source": {
            "file_path": os.path.join(FIX, "two_branches.c"),
            "line_number": 10,           # fread call
            "function_name": "vuln_entry",
        },
        "sink": {
            "file_path": os.path.join(FIX, "two_branches.c"),
            "line_number": 17,           # __sink_reached()
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
```

- [ ] **Step 2: Run, verify failure**

Run: `pytest test/test_symbolic_sanitizer/test_branch_scanner.py -v`
Expected: ImportError.

- [ ] **Step 3: Implement `branch_scanner.py`**

Create `src/libs/symbolic_sanitizer/branch_scanner.py`:

```python
"""scan_path_branches — enumerate tainted branches on a SARIF path."""
from __future__ import annotations

import os
from typing import Dict, Any

from .path_executor import PathExecutor
from .dwarf_resolver import addr_to_line, func_entry


def _read_source_line(file_path: str, line: int, context: int = 2) -> Dict[str, str]:
    if not os.path.exists(file_path):
        return {"condition_src": "", "surrounding_code": ""}
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()
    if line < 1 or line > len(lines):
        return {"condition_src": "", "surrounding_code": ""}
    cond = lines[line - 1].rstrip("\n")
    lo = max(0, line - 1 - context)
    hi = min(len(lines), line - 1 + context + 1)
    surrounding = "".join(lines[lo:hi])
    return {"condition_src": cond, "surrounding_code": surrounding}


def scan_path_branches(binary_path: str, path: Dict[str, Any],
                       source_mode: str, timeout: int = 120) -> Dict[str, Any]:
    if not os.path.exists(binary_path):
        return {"success": False, "error": f"binary not found: {binary_path}",
                "tainted_branches": []}

    ex = PathExecutor(binary_path)

    if source_mode == "libc_stdin":
        state = ex.initial_state_libc_stdin()
    elif source_mode == "mid_function":
        src_file = path["source"]["file_path"]
        src_line = path["source"]["line_number"]
        from .dwarf_resolver import line_to_addr
        addr = line_to_addr(binary_path, src_file, src_line)
        if addr is None:
            func_name = path["source"].get("function_name") or "main"
            faddr = func_entry(binary_path, func_name)
            if faddr is None:
                return {"success": False,
                        "error": "DWARF cannot resolve source address",
                        "tainted_branches": [], "degraded": "no_dwarf_for_source"}
            state = ex.initial_state_entry_fallback(faddr)
        else:
            state = ex.initial_state_mid_function(addr)
    else:
        return {"success": False, "error": f"unknown source_mode: {source_mode}",
                "tainted_branches": []}

    sink_addr = ex.func_addr("__sink_reached")
    if sink_addr is None:
        return {"success": False, "error": "__sink_reached not found in binary",
                "tainted_branches": []}

    raw = ex.collect_tainted_branches(state, sink_addr, timeout=timeout)

    enriched = []
    for b in raw:
        fl = addr_to_line(binary_path, b["guard_addr"])
        if fl is None:
            file, line = "", 0
            src = {"condition_src": "", "surrounding_code": ""}
        else:
            file, line = fl
            src = _read_source_line(file, line)
        enriched.append({
            "branch_id": b["branch_id"],
            "file": file,
            "line": line,
            "condition_src": src["condition_src"],
            "surrounding_code": src["surrounding_code"],
            "taint_vars": b["taint_vars"],
            "guard_repr": b["guard_repr"],
        })

    return {"success": True, "tainted_branches": enriched, "error": None}
```

- [ ] **Step 4: Re-export, run test**

Modify `__init__.py` to add `from .branch_scanner import scan_path_branches`.

Run: `pytest test/test_symbolic_sanitizer/test_branch_scanner.py -v --timeout=180`
Expected: passes.

- [ ] **Step 5: Commit**

```bash
git add src/libs/symbolic_sanitizer/branch_scanner.py src/libs/symbolic_sanitizer/__init__.py test/test_symbolic_sanitizer/test_branch_scanner.py
git commit -m "feat: add scan_path_branches tool"
```

---

## Task 10: verifier.py — verify_with_decisions

**Files:**
- Create: `src/libs/symbolic_sanitizer/verifier.py`
- Create: `test/test_symbolic_sanitizer/test_verifier.py`

The verifier translates `attack_predicate.taint_var` (DWARF name) to a
`byte_offset` in the symbolic stdin/buffer. For libc_stdin, the convention is
that taint variables are filled in order by the program's libc calls; the
verifier asks the caller to supply `byte_offset` directly if name resolution
fails (v1 simplification — we currently only support `byte_offset` lookup via
a small heuristic: SARIF source-line's first DWARF location of the named
variable, mapped to the stdin offset it was read from).

For v1 we keep the contract simple: `attack_predicate.byte_offset` is what
ends up applied; if `taint_var` is provided AND `mid_function` mode is in use,
we attempt to resolve it via `dwarf_resolver.var_storage` and translate to the
scratch buffer offset.

- [ ] **Step 1: Write failing test**

Create `test/test_symbolic_sanitizer/test_verifier.py`:

```python
import os
import pytest

from libs.symbolic_sanitizer.verifier import verify_with_decisions

FIX = os.path.join(os.path.dirname(__file__), "fixtures")


def _path():
    return {
        "source": {
            "file_path": os.path.join(FIX, "two_branches.c"),
            "line_number": 10, "function_name": "vuln_entry",
        },
        "sink": {
            "file_path": os.path.join(FIX, "two_branches.c"),
            "line_number": 17, "function_name": "vuln_entry",
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
            "byte_offset": 0, "width": 4, "op": ">=",
            "value": 200, "signed": False,
        },
    )
    assert r["success"] is True
    assert r["reachable"] is False
```

- [ ] **Step 2: Run, verify failure**

Run: `pytest test/test_symbolic_sanitizer/test_verifier.py -v`
Expected: ImportError.

- [ ] **Step 3: Implement `verifier.py`**

Create `src/libs/symbolic_sanitizer/verifier.py`:

```python
"""verify_with_decisions — re-execute path applying chosen sanitizer guards."""
from __future__ import annotations

import os
from typing import Dict, Any, Optional

from .path_executor import PathExecutor
from .dwarf_resolver import line_to_addr, func_entry


def verify_with_decisions(
    binary_path: str,
    path: Dict[str, Any],
    source_mode: str,
    branch_decisions: Dict[str, bool],
    attack_predicate: Optional[Dict[str, Any]],
    timeout: int = 120,
) -> Dict[str, Any]:
    if not os.path.exists(binary_path):
        return {"success": False, "error": f"binary not found: {binary_path}",
                "reachable": False, "counterexample": None, "sat_branches": []}

    ex = PathExecutor(binary_path)

    if source_mode == "libc_stdin":
        state = ex.initial_state_libc_stdin()
        degraded = None
    elif source_mode == "mid_function":
        src_file = path["source"]["file_path"]
        src_line = path["source"]["line_number"]
        addr = line_to_addr(binary_path, src_file, src_line)
        if addr is None:
            func_name = path["source"].get("function_name") or "main"
            faddr = func_entry(binary_path, func_name)
            if faddr is None:
                return {"success": False, "error": "no DWARF for source line",
                        "reachable": False, "counterexample": None,
                        "sat_branches": [], "degraded": "no_dwarf_for_source"}
            state = ex.initial_state_entry_fallback(faddr)
            degraded = "no_dwarf_for_source"
        else:
            state = ex.initial_state_mid_function(addr)
            degraded = None
    else:
        return {"success": False, "error": f"unknown source_mode: {source_mode}",
                "reachable": False, "counterexample": None, "sat_branches": []}

    sink_addr = ex.func_addr("__sink_reached")
    if sink_addr is None:
        return {"success": False, "error": "__sink_reached not in binary",
                "reachable": False, "counterexample": None, "sat_branches": []}

    res = ex.solve_with_decisions(state, sink_addr, branch_decisions,
                                  attack_predicate, timeout=timeout)
    if degraded:
        res["degraded"] = degraded
    return res
```

- [ ] **Step 4: Re-export, run tests**

Modify `__init__.py` to add `from .verifier import verify_with_decisions`.

Run: `pytest test/test_symbolic_sanitizer/test_verifier.py -v --timeout=240`
Expected: passes.

- [ ] **Step 5: Commit**

```bash
git add src/libs/symbolic_sanitizer/verifier.py src/libs/symbolic_sanitizer/__init__.py test/test_symbolic_sanitizer/test_verifier.py
git commit -m "feat: add verify_with_decisions tool"
```

---

## Task 11: MCP server — shrink to 4 tools

**Files:**
- Modify: `src/mcptools/symbolic_sanitizer.py`

- [ ] **Step 1: Replace the MCP server contents**

Overwrite `src/mcptools/symbolic_sanitizer.py`:

```python
#!/usr/bin/env python3
"""MCP Server: Symbolic Sanitizer (4-tool path-guided selective sym-exec)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastmcp import FastMCP
from libs.symbolic_sanitizer import (
    parse_sarif as _parse_sarif,
    build_harness as _build_harness,
    scan_path_branches as _scan_path_branches,
    verify_with_decisions as _verify_with_decisions,
    resolve_compile_config as _resolve_compile_config,
    write_compile_config as _write_compile_config,
    DEFAULT_COMPILE_SH,
)

mcp = FastMCP(
    name="symbolic_sanitizer",
    instructions=("Path-guided selective symbolic execution. Workflow: "
                  "parse_sarif -> build_harness -> scan_path_branches -> "
                  "(agent decides branch include/exclude + attack predicate) -> "
                  "verify_with_decisions."),
)


@mcp.tool()
def parse_sarif(sarif_path: str, dataset_root: str) -> dict:
    """Parse SARIF and return taint paths with absolute paths + function source."""
    return _parse_sarif(sarif_path, dataset_root)


@mcp.tool()
def build_harness(source_file: str, vuln_entry: str, source_api: str,
                  compile_script: str, entry_signature: str = "void") -> dict:
    """Compile a template harness linked with the original source file."""
    return _build_harness(source_file, vuln_entry, source_api,
                          compile_script, entry_signature=entry_signature)


@mcp.tool()
def scan_path_branches(binary_path: str, path: dict, source_mode: str,
                       timeout: int = 120) -> dict:
    """Enumerate tainted branches along the SARIF path. Agent decides which to
    treat as sanitizers."""
    return _scan_path_branches(binary_path, path, source_mode, timeout=timeout)


@mcp.tool()
def verify_with_decisions(binary_path: str, path: dict, source_mode: str,
                          branch_decisions: dict,
                          attack_predicate: dict | None = None,
                          timeout: int = 120) -> dict:
    """Re-execute path applying chosen sanitizer guards + attack predicate."""
    return _verify_with_decisions(binary_path, path, source_mode,
                                  branch_decisions, attack_predicate,
                                  timeout=timeout)


@mcp.tool()
def resolve_compile_config(dataset_path: str) -> dict:
    """Locate an existing compile.sh under dataset_path."""
    return _resolve_compile_config(dataset_path)


@mcp.tool()
def write_compile_config(dataset_path: str, script_content: str | None = None) -> dict:
    """Write a compile.sh into dataset_path. Defaults to the template that
    enforces -g -O0 -fno-inline."""
    return _write_compile_config(dataset_path,
                                 script_content or DEFAULT_COMPILE_SH)


if __name__ == "__main__":
    mcp.run()
```

(Note: `compile_config` helpers are exposed as utility tools so users without a `compile.sh` can write one. The agent's mainline workflow remains the 4 core tools.)

- [ ] **Step 2: Run smoke import**

Run: `python -c "from mcptools.symbolic_sanitizer import mcp; print([t for t in mcp._tool_manager._tools.keys()])"` (or whatever the introspection method is for the installed fastmcp version — adjust if API differs).
Expected: prints 6 tool names.

- [ ] **Step 3: Commit**

```bash
git add src/mcptools/symbolic_sanitizer.py
git commit -m "feat: shrink MCP surface to 4 core tools + 2 compile.sh helpers"
```

---

## Task 12: End-to-end Juliet validation

**Files:**
- Create: `test/test_symbolic_sanitizer/test_end_to_end_juliet.py`

- [ ] **Step 1: Write the e2e test**

Create `test/test_symbolic_sanitizer/test_end_to_end_juliet.py`:

```python
import os
import pytest

from libs.symbolic_sanitizer import (
    build_harness, scan_path_branches, verify_with_decisions,
    DEFAULT_COMPILE_SH,
)

JULIET_ROOT = "/data/benchmark/juliet/juliet-test-suite-c"
SQUARE_SRC = os.path.join(
    JULIET_ROOT,
    "testcases/CWE190_Integer_Overflow/s05/"
    "CWE190_Integer_Overflow__unsigned_int_fscanf_square_01.c",
)

pytestmark = pytest.mark.skipif(
    not os.path.exists(SQUARE_SRC), reason="Juliet not available"
)


@pytest.fixture(scope="module")
def juliet_compile_script(tmp_path_factory):
    p = tmp_path_factory.mktemp("compile") / "compile.sh"
    # Juliet needs the testcasesupport include path; extend the template.
    template = DEFAULT_COMPILE_SH.replace(
        '"$HARNESS" "$ORIG"',
        f'-I"{JULIET_ROOT}/testcasesupport" '
        f'"{JULIET_ROOT}/testcasesupport/io.c" '
        '"$HARNESS" "$ORIG"',
    )
    p.write_text(template)
    p.chmod(0o755)
    return str(p)


def test_e2e_fscanf_square_goodB2G(juliet_compile_script):
    r = build_harness(
        source_file=SQUARE_SRC,
        vuln_entry="CWE190_Integer_Overflow__unsigned_int_fscanf_square_01_goodB2G",
        source_api="fscanf",
        compile_script=juliet_compile_script,
    )
    assert r["success"] is True, r.get("error")
    binary = r["binary_path"]

    path = {
        "source": {
            "file_path": SQUARE_SRC,
            "line_number": 55,  # fscanf call (approximate, adjust per file)
            "function_name": (
                "CWE190_Integer_Overflow__unsigned_int_fscanf_square_01_goodB2G"
            ),
        },
        "sink": {
            "file_path": SQUARE_SRC,
            "line_number": 65,  # data * data; (approximate)
            "function_name": (
                "CWE190_Integer_Overflow__unsigned_int_fscanf_square_01_goodB2G"
            ),
        },
        "intermediate_locations": [],
    }

    scan = scan_path_branches(binary, path, source_mode="libc_stdin", timeout=120)
    assert scan["success"] is True
    # At least one tainted branch (the abs/sqrt sanitizer) is expected.
    assert len(scan["tainted_branches"]) >= 1

    # Attack predicate: data >= 65536 (sqrt(UINT_MAX) ~ 65536), 32-bit unsigned.
    res = verify_with_decisions(
        binary_path=binary,
        path=path,
        source_mode="libc_stdin",
        branch_decisions={b["branch_id"]: True for b in scan["tainted_branches"]},
        attack_predicate={"byte_offset": 0, "width": 4, "op": ">=",
                          "value": 65536, "signed": False},
        timeout=180,
    )
    # The Juliet sanitizer has a documented bypass — sink should still be
    # reachable. (If the line numbers / function name don't match the actual
    # file, adjust per `head -100 $SQUARE_SRC`.)
    assert res["success"] is True
    assert res["reachable"] is True
    assert res["counterexample"] is not None
```

- [ ] **Step 2: Adjust line numbers**

Run: `head -100 $JULIET_ROOT/testcases/CWE190_Integer_Overflow/s05/CWE190_Integer_Overflow__unsigned_int_fscanf_square_01.c`
Locate the actual line numbers of the `fscanf` source call and the `data * data` sink. Update the `line_number` fields in the test.

- [ ] **Step 3: Run e2e test**

Run: `pytest test/test_symbolic_sanitizer/test_end_to_end_juliet.py -v --timeout=600`
Expected: pass. If `scan` finds zero branches, it likely means stdin symbolic bytes didn't propagate through fscanf — fall back to setting `source_api="fscanf"` is already correct; double-check angr's libc SimProcedure for `__isoc99_fscanf` (some glibc versions use that symbol).

- [ ] **Step 4: Commit**

```bash
git add test/test_symbolic_sanitizer/test_end_to_end_juliet.py
git commit -m "test: end-to-end Juliet CWE-190 fscanf_square verification"
```

---

## Task 13: Rewrite agent prompt (`readme.md`)

**Files:**
- Modify: `src/libs/symbolic_sanitizer/readme.md`

- [ ] **Step 1: Overwrite agent prompt with the 4-tool flow**

Overwrite `src/libs/symbolic_sanitizer/readme.md`:

````markdown
# Symbolic Sanitizer — Agent Workflow

You are a security analyst. Your job: given a SARIF file and the dataset root,
verify whether the sanitizers along each taint path actually block the
documented attack, using path-guided selective symbolic execution.

## Architecture

- **MCP tools** do all symbolic execution and binary analysis.
- **You** make exactly one judgement per path: which tainted branches are
  sanitizers (to enforce as constraints), plus an attack predicate.

## Tools (4 core + 2 compile.sh helpers)

| Tool | Purpose |
|------|---------|
| `parse_sarif(sarif_path, dataset_root)` | Returns taint paths with absolute file paths and enclosing-function source code for every node. |
| `build_harness(source_file, vuln_entry, source_api, compile_script, entry_signature)` | Compiles a template harness linked with the original source file. Returns `binary_path`, `source_mode`, `dwarf_ok`. |
| `scan_path_branches(binary_path, path, source_mode)` | Enumerates tainted branch conditions along the path. Returns `tainted_branches[]` (id, file, line, `condition_src`, surrounding 5 lines, taint vars). |
| `verify_with_decisions(binary_path, path, source_mode, branch_decisions, attack_predicate)` | Re-executes the path, enforces guards for branches you marked `true`, applies the attack predicate, explores to sink. Returns `reachable`, `counterexample`. |
| `resolve_compile_config(dataset_path)` | Finds an existing `compile.sh` under the dataset. |
| `write_compile_config(dataset_path, script_content?)` | Writes a `compile.sh` (default template enforces `-g -O0 -fno-inline`). |

## Flow

```
parse_sarif → paths[]
for each path:
    resolve compile.sh (write if missing, default template OK)
    build_harness                 (template only — you don't write C)
    scan_path_branches → tainted_branches[]
    -- YOUR DECISION --
    For each tainted_branch decide include / exclude based on whether the
    condition looks like a sanitizer. Pick the attack predicate.
    -- END DECISION --
    verify_with_decisions
```

## How to choose `branch_decisions`

You see each tainted branch with its source line, surrounding code, and the
taint variables it depends on. Mark `true` (include as constraint, i.e.
"sanitizer accepted the input") iff the condition is a candidate sanitizer
guarding the sink. Excluded branches are explored both ways naturally by angr.

Prefer including conditions that:
- Compare a taint variable against a constant (range check, length check).
- Validate format (`isdigit`, `isalpha`, character allowlists/denylists).
- Are wrapped around code that flows into the sink (path tells you this).

Exclude conditions that:
- Are loop iteration tests (`i < n`).
- Are environment/config checks unrelated to the data.

## Attack predicate schema

```json
{
  "byte_offset": 0,
  "width": 4,
  "op": ">=" | "<=" | "==" | "!=" | ">" | "<",
  "value": 65536,
  "signed": false
}
```

`byte_offset` indexes into the symbolic input buffer (libc_stdin: byte position
in stdin stream; mid_function: byte position in the scratch buffer that the
mid-function entry point writes into the target variable). Pick it from the
SARIF source node's first-read variable. Width is 1/2/4/8.

## Pick the attack predicate by rule_id

| rule_id | Typical predicate |
|---------|-------------------|
| `cpp/integer-overflow-tainted` (uint32 mul) | `byte_offset=0, width=4, op=">=", value=65536` |
| `cpp/integer-overflow-tainted` (int8 add) | `byte_offset=0, width=1, op=">=", value=127` |
| `cpp/non-constant-format` | `op="==", value=0x73`  (`'%s'` indicator byte) |
| `cpp/uncontrolled-allocation-size` | `width=4, op=">=", value=<large>` |

(Use your judgement — these are starting points.)

## Result interpretation

- `reachable=true` with counterexample → sanitizer is bypassable. Report the
  counterexample bytes interpreted as the target type.
- `reachable=false` → sanitizer holds against the attack predicate.
- `degraded` field → DWARF missing; mark confidence lower.

## Report format

```markdown
## Path-Guided Symbolic Verification Report

### SARIF Overview
- Paths analysed: {N}
- Dataset: {dataset_root}

### Per-Path Verdicts

| path_id | rule_id | entry | sink line | branches included | reachable | counterexample |
|---------|---------|-------|-----------|-------------------|-----------|----------------|
| ... | ... | ... | ... | ... | ❌/✅ | ... |

### Detailed Analysis
For each path: list the tainted branches you saw, which you included and why,
the attack predicate you chose, the angr result, and your conclusion.
```
````

- [ ] **Step 2: Commit**

```bash
git add src/libs/symbolic_sanitizer/readme.md
git commit -m "docs: rewrite agent prompt for 4-tool path-guided flow"
```

---

## Task 14: Cleanup — delete obsolete files

**Files:**
- Delete: `src/libs/symbolic_sanitizer/harness_generator.py`
- Delete: `src/libs/symbolic_sanitizer/symbolic_sanitizer.py`
- Delete: `test/test_symbolic_sanitizer/test_step5_harness_generation.py`
- Delete: `test/test_symbolic_sanitizer/test_step6_verify_with_constraints.py`
- Modify: `src/libs/symbolic_sanitizer/__init__.py`

- [ ] **Step 1: Remove obsolete imports from `__init__.py`**

Edit `src/libs/symbolic_sanitizer/__init__.py` so it imports only the new modules. Final content should be:

```python
"""Symbolic Sanitizer — path-guided selective symbolic execution."""

from .sarif_parser import (
    load_sarif_from_file,
    extract_taint_paths,
    parse_sarif,
    TaintPath,
)
from .path_context import find_enclosing_function
from .harness_builder import (
    build_harness,
    render_harness,
    select_source_mode,
    DEFAULT_COMPILE_SH,
)
from .compile_config import resolve_compile_config, write_compile_config
from .path_executor import PathExecutor
from .branch_scanner import scan_path_branches
from .verifier import verify_with_decisions

__all__ = [
    "load_sarif_from_file", "extract_taint_paths", "parse_sarif", "TaintPath",
    "find_enclosing_function",
    "build_harness", "render_harness", "select_source_mode", "DEFAULT_COMPILE_SH",
    "resolve_compile_config", "write_compile_config",
    "PathExecutor",
    "scan_path_branches",
    "verify_with_decisions",
]
```

- [ ] **Step 2: Delete obsolete files**

```bash
git rm src/libs/symbolic_sanitizer/harness_generator.py
git rm src/libs/symbolic_sanitizer/symbolic_sanitizer.py
git rm test/test_symbolic_sanitizer/test_step5_harness_generation.py
git rm test/test_symbolic_sanitizer/test_step6_verify_with_constraints.py
```

- [ ] **Step 3: Run full test suite to confirm nothing else broke**

Run: `pytest test/test_symbolic_sanitizer -v --timeout=600`
Expected: only the new tests run; all pass; no ImportError from removed modules.

- [ ] **Step 4: Grep for stale references**

Run: `grep -rn "harness_generator\|symbolic_sanitizer\.SymbolicExecutor" src/ test/ scripts/`
Expected: zero hits (except this file's own diff history).

- [ ] **Step 5: Commit**

```bash
git add src/libs/symbolic_sanitizer/__init__.py
git commit -m "refactor: remove obsolete harness_generator and old SymbolicExecutor"
```

---

## Task 15: Update eval script

**Files:**
- Modify: `scripts/eval_symbolic_sanitizer.py`

- [ ] **Step 1: Read the current eval script**

Run: `cat scripts/eval_symbolic_sanitizer.py | head -120`
Identify which old function names it imports.

- [ ] **Step 2: Update imports + flow**

Replace its old imports and per-path logic with the 4-tool flow:

```python
from libs.symbolic_sanitizer import (
    parse_sarif, build_harness, scan_path_branches, verify_with_decisions,
    resolve_compile_config, write_compile_config, DEFAULT_COMPILE_SH,
)
```

For each path, replicate the workflow shown in `src/libs/symbolic_sanitizer/readme.md` (Flow section). Use a simple branch-decision heuristic for the eval script (e.g. include all branches whose `condition_src` mentions any taint variable name), since the eval script runs without an LLM in the loop.

- [ ] **Step 3: Smoke-run the script on the sample SARIF**

Run: `python scripts/eval_symbolic_sanitizer.py --sarif test/test_symbolic_sanitizer/fixtures/sample.sarif --dataset-root /data/benchmark/juliet/juliet-test-suite-c`
Expected: produces a report; non-zero paths.

- [ ] **Step 4: Commit**

```bash
git add scripts/eval_symbolic_sanitizer.py
git commit -m "refactor: drive eval script with 4-tool flow"
```

---

## Final verification

- [ ] **All tests green**

Run: `pytest test/test_symbolic_sanitizer -v --timeout=600`
Expected: every test from Tasks 2–12 passes.

- [ ] **No dangling references to old symbols**

Run: `grep -rn "harness_generator\|generate_harness\|read_path_context\b\|parse_sarif_detailed\|verify_branch" src/ test/ scripts/ docs/`
Expected: matches only inside `docs/superpowers/specs/2026-05-23-*` (historical) and `docs/superpowers/specs/2026-05-26-*` (current — references in §9 are fine). No matches in `src/`, `test/`, or `scripts/`.

- [ ] **Sanity-check the MCP server boots**

Run: `python -m mcptools.symbolic_sanitizer --help 2>&1 | head -5` (or whatever invocation fastmcp supports).
Expected: server starts; tools register without error.

- [ ] **Plan complete — open PR or hand off**
