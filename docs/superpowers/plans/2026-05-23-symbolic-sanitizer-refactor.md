# Symbolic Sanitizer Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor `symbolic_sanitizer` from function-level to branch-level selective symbolic execution, with structured harness generation and dataset-level compile configuration.

**Architecture:** MCP Tools handle deterministic operations (SARIF parsing, source reading, harness generation, compilation, angr verification). Agent handles semantic reasoning (branch analysis, constraint generation, compile.sh authoring for new datasets). The pipeline: parse SARIF → read path context → Agent produces verification plan → loop over targets: generate harness → resolve compile config → compile → verify branch reachability.

**Tech Stack:** Python 3.13, FastMCP, angr/claripy (symbolic execution), pytest

**Spec:** `docs/superpowers/specs/2026-05-23-symbolic-sanitizer-refactor-design.md`

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `src/libs/symbolic_sanitizer/path_context.py` | Create | `read_path_context`, `find_enclosing_function` |
| `src/libs/symbolic_sanitizer/compile_config.py` | Create | `resolve_compile_config`, `write_compile_config` |
| `src/libs/symbolic_sanitizer/harness_generator.py` | Rewrite | `generate_harness` (structured params), `compile_harness` (calls compile.sh) |
| `src/libs/symbolic_sanitizer/symbolic_sanitizer.py` | Rewrite | `SymbolicExecutor.execute_reachability` (sink reachability via angr) |
| `src/libs/symbolic_sanitizer/sarif_parser.py` | Minor edit | Remove `parse_sarif_result`, keep `extract_taint_paths` |
| `src/libs/symbolic_sanitizer/verifier.py` | Delete | Orchestration logic moves to Agent prompt |
| `src/libs/symbolic_sanitizer/__init__.py` | Rewrite | Export new public API |
| `src/mcptools/symbolic_sanitizer.py` | Rewrite | New tool surface: 7 tools |
| `src/libs/symbolic_sanitizer/readme.md` | Rewrite | New 7-step Agent workflow prompt |
| `test/test_symbolic_sanitizer/conftest.py` | Edit | Add fixtures for path_context, compile_config, harness |
| `test/test_symbolic_sanitizer/test_read_path_context.py` | Create | Tests for path_context module |
| `test/test_symbolic_sanitizer/test_compile_config.py` | Create | Tests for compile_config module |
| `test/test_symbolic_sanitizer/test_step5_harness_generation.py` | Rewrite | Tests for new generate_harness + compile_harness |
| `test/test_symbolic_sanitizer/test_step6_verify_with_constraints.py` | Rewrite | Tests for verify_branch |
| `test/test_symbolic_sanitizer/test_step3_function_selector_skill.py` | Delete | Skill no longer exists |
| `test/test_symbolic_sanitizer/test_step4_constraint_generator_skill.py` | Delete | Skill no longer exists |

---

### Task 1: Create `path_context.py` — `find_enclosing_function`

**Files:**
- Create: `src/libs/symbolic_sanitizer/path_context.py`
- Test: `test/test_symbolic_sanitizer/test_read_path_context.py`

- [ ] **Step 1: Write test for `find_enclosing_function`**

Create `test/test_symbolic_sanitizer/test_read_path_context.py`:

```python
"""Tests for path_context module."""
import os
import sys
import pytest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../src'))

from libs.symbolic_sanitizer.path_context import find_enclosing_function


@pytest.fixture
def c_source_file(tmp_path):
    """Create a sample C file with multiple functions."""
    code = """#include <stdio.h>
#include <string.h>

int validate_input(char* input) {
    if (input == NULL) {
        return 0;
    }
    if (strchr(input, ';') != NULL) {
        return 0;
    }
    return 1;
}

void process_data(char* input, char* output) {
    if (validate_input(input)) {
        strcpy(output, input);
    }
}

int main() {
    char buf[64];
    process_data(buf, buf);
    return 0;
}
"""
    f = tmp_path / "sample.c"
    f.write_text(code)
    return str(f)


class TestFindEnclosingFunction:
    def test_finds_function_by_line_inside_body(self, c_source_file):
        result = find_enclosing_function(c_source_file, 6)
        assert result["success"] is True
        assert result["function_name"] == "validate_input"
        assert "strchr" in result["source_code"]

    def test_finds_second_function(self, c_source_file):
        result = find_enclosing_function(c_source_file, 16)
        assert result["success"] is True
        assert result["function_name"] == "process_data"

    def test_finds_main(self, c_source_file):
        result = find_enclosing_function(c_source_file, 22)
        assert result["success"] is True
        assert result["function_name"] == "main"

    def test_line_outside_any_function(self, c_source_file):
        result = find_enclosing_function(c_source_file, 1)
        assert result["success"] is False

    def test_file_not_found(self):
        result = find_enclosing_function("/nonexistent/file.c", 10)
        assert result["success"] is False
        assert "not found" in result["error"].lower() or "不存在" in result["error"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Volumes/Important/E_backup/Creation/PPPPPPP/创新计划2025/Project/Exp/CodeQL-AI && python -m pytest test/test_symbolic_sanitizer/test_read_path_context.py -v`
Expected: FAIL — `ModuleNotFoundError` or `ImportError` (module doesn't exist yet)

- [ ] **Step 3: Implement `find_enclosing_function`**

Create `src/libs/symbolic_sanitizer/path_context.py`:

```python
"""
Path Context — batch source reading for taint path nodes.
"""

import re
from pathlib import Path
from typing import Optional


def find_enclosing_function(file_path: str, line_number: int) -> dict:
    """
    Given a file and line number, find the function definition containing that line.
    Scans upward for a function signature, then matches braces to find the end.

    Returns:
        {"success": True, "function_name": ..., "source_code": ..., "start_line": ..., "end_line": ...}
        or {"success": False, "error": ...}
    """
    path = Path(file_path)
    if not path.exists():
        return {"success": False, "error": f"文件不存在: {file_path}"}

    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception as e:
        return {"success": False, "error": f"读取文件失败: {str(e)}"}

    if line_number < 1 or line_number > len(lines):
        return {"success": False, "error": f"行号超出范围: {line_number} (文件共 {len(lines)} 行)"}

    # C/C++ function definition pattern: return_type func_name(
    func_def_pattern = re.compile(
        r'^[\w\s\*:~]+?\b(\w+)\s*\([^;]*$'
    )

    # Scan upward from target line to find the function definition start
    target_idx = line_number - 1
    func_start = None
    func_name = None

    for i in range(target_idx, -1, -1):
        line = lines[i]
        m = func_def_pattern.match(line)
        if not m:
            continue
        # Confirm it's a definition (has '{' nearby, not just a declaration ending with ';')
        search_text = ''.join(lines[i:min(i + 10, len(lines))])
        if '{' not in search_text:
            continue
        before_brace = search_text.split('{')[0]
        if before_brace.rstrip().endswith(';'):
            continue
        func_start = i
        func_name = m.group(1)
        break

    if func_start is None:
        return {"success": False, "error": f"未找到包含第 {line_number} 行的函数"}

    # Find function end by matching braces
    brace_count = 0
    found_start = False
    func_end = func_start
    for j in range(func_start, len(lines)):
        for char in lines[j]:
            if char == '{':
                found_start = True
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if found_start and brace_count == 0:
                    func_end = j + 1
                    break
        if found_start and brace_count == 0:
            break

    if brace_count != 0:
        return {"success": False, "error": f"函数 {func_name} 的花括号不匹配"}

    # Verify target line is within function range
    if target_idx >= func_end:
        return {"success": False, "error": f"第 {line_number} 行不在函数 {func_name} 内"}

    return {
        "success": True,
        "function_name": func_name,
        "file_path": file_path,
        "start_line": func_start + 1,
        "end_line": func_end,
        "source_code": ''.join(lines[func_start:func_end])
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Volumes/Important/E_backup/Creation/PPPPPPP/创新计划2025/Project/Exp/CodeQL-AI && python -m pytest test/test_symbolic_sanitizer/test_read_path_context.py -v`
Expected: All 5 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/libs/symbolic_sanitizer/path_context.py test/test_symbolic_sanitizer/test_read_path_context.py
git commit -m "feat: add find_enclosing_function for line-to-function lookup"
```

---

### Task 2: Add `read_path_context` to `path_context.py`

**Files:**
- Modify: `src/libs/symbolic_sanitizer/path_context.py`
- Modify: `test/test_symbolic_sanitizer/test_read_path_context.py`

- [ ] **Step 1: Write tests for `read_path_context`**

Append to `test/test_symbolic_sanitizer/test_read_path_context.py`:

```python
from libs.symbolic_sanitizer.path_context import read_path_context


@pytest.fixture
def multi_file_project(tmp_path):
    """Create a small multi-file C project."""
    (tmp_path / "input.c").write_text(
        'char* get_user_input() {\n    char* buf = malloc(64);\n    fgets(buf, 64, stdin);\n    return buf;\n}\n'
    )
    (tmp_path / "validate.c").write_text(
        'int validate_cmd(char* input) {\n    if (strchr(input, \';\') != NULL) return 0;\n    return 1;\n}\n'
    )
    return tmp_path


class TestReadPathContext:
    def test_batch_read_with_function_names(self, multi_file_project):
        locations = [
            {"file_path": str(multi_file_project / "input.c"), "line_number": 2, "function_name": "get_user_input"},
            {"file_path": str(multi_file_project / "validate.c"), "line_number": 2, "function_name": "validate_cmd"},
        ]
        result = read_path_context(locations)
        assert result["success"] is True
        assert len(result["context"]) == 2
        assert result["context"][0]["function_name"] == "get_user_input"
        assert result["context"][1]["function_name"] == "validate_cmd"
        assert len(result["failed"]) == 0

    def test_batch_read_without_function_name(self, multi_file_project):
        locations = [
            {"file_path": str(multi_file_project / "validate.c"), "line_number": 2, "function_name": None},
        ]
        result = read_path_context(locations)
        assert result["success"] is True
        assert len(result["context"]) == 1
        assert result["context"][0]["function_name"] == "validate_cmd"

    def test_deduplication(self, multi_file_project):
        locations = [
            {"file_path": str(multi_file_project / "validate.c"), "line_number": 1, "function_name": "validate_cmd"},
            {"file_path": str(multi_file_project / "validate.c"), "line_number": 2, "function_name": "validate_cmd"},
        ]
        result = read_path_context(locations)
        assert result["success"] is True
        assert len(result["context"]) == 1

    def test_missing_file_collected_in_failed(self, multi_file_project):
        locations = [
            {"file_path": str(multi_file_project / "validate.c"), "line_number": 2, "function_name": "validate_cmd"},
            {"file_path": "/nonexistent/file.c", "line_number": 10, "function_name": "foo"},
        ]
        result = read_path_context(locations)
        assert result["success"] is True
        assert len(result["context"]) == 1
        assert len(result["failed"]) == 1
        assert "nonexistent" in result["failed"][0]["file_path"]

    def test_empty_locations(self):
        result = read_path_context([])
        assert result["success"] is True
        assert len(result["context"]) == 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Volumes/Important/E_backup/Creation/PPPPPPP/创新计划2025/Project/Exp/CodeQL-AI && python -m pytest test/test_symbolic_sanitizer/test_read_path_context.py::TestReadPathContext -v`
Expected: FAIL — `ImportError` (function not defined)

- [ ] **Step 3: Implement `read_path_context`**

Add to `src/libs/symbolic_sanitizer/path_context.py`:

```python
from libs.lib_sanitizer import read_function_implementation


def read_path_context(locations: list) -> dict:
    """
    Batch-read source code for all nodes on a taint path.

    For each location:
    - If function_name is provided, use read_function_implementation
    - If function_name is None, use find_enclosing_function by line_number
    - Deduplicates by (file_path, function_name)
    - Collects failures without aborting
    """
    context = []
    failed = []
    seen = set()

    for loc in locations:
        file_path = loc.get("file_path", "")
        line_number = loc.get("line_number", 0)
        function_name = loc.get("function_name")

        if function_name:
            result = read_function_implementation(function_name, file_path)
        else:
            result = find_enclosing_function(file_path, line_number)

        if not result.get("success"):
            failed.append({
                "file_path": file_path,
                "line_number": line_number,
                "function_name": function_name,
                "reason": result.get("error", "unknown error")
            })
            continue

        fn_name = result.get("function_name", function_name)
        dedup_key = (file_path, fn_name)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        context.append({
            "file_path": file_path,
            "function_name": fn_name,
            "line_number": line_number,
            "source_code": result["source_code"],
            "start_line": result.get("start_line"),
            "end_line": result.get("end_line"),
        })

    return {
        "success": True,
        "context": context,
        "failed": failed,
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Volumes/Important/E_backup/Creation/PPPPPPP/创新计划2025/Project/Exp/CodeQL-AI && python -m pytest test/test_symbolic_sanitizer/test_read_path_context.py -v`
Expected: All 10 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/libs/symbolic_sanitizer/path_context.py test/test_symbolic_sanitizer/test_read_path_context.py
git commit -m "feat: add read_path_context for batch taint path source reading"
```

---

### Task 3: Create `compile_config.py`

**Files:**
- Create: `src/libs/symbolic_sanitizer/compile_config.py`
- Create: `test/test_symbolic_sanitizer/test_compile_config.py`

- [ ] **Step 1: Write tests**

Create `test/test_symbolic_sanitizer/test_compile_config.py`:

```python
"""Tests for compile_config module."""
import os
import sys
import stat
import pytest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../src'))

from libs.symbolic_sanitizer.compile_config import resolve_compile_config, write_compile_config


class TestResolveCompileConfig:
    def test_found_existing_config(self, tmp_path):
        config_dir = tmp_path / ".CodeQL-AI"
        config_dir.mkdir()
        script = config_dir / "compile.sh"
        script.write_text("#!/bin/bash\ngcc $1 -o $2\n")
        script.chmod(script.stat().st_mode | stat.S_IEXEC)

        result = resolve_compile_config(str(tmp_path))
        assert result["found"] is True
        assert result["compile_script"] == str(script)

    def test_not_found_returns_listing(self, tmp_path):
        (tmp_path / "src").mkdir()
        (tmp_path / "include").mkdir()
        (tmp_path / "main.c").touch()

        result = resolve_compile_config(str(tmp_path))
        assert result["found"] is False
        assert str(tmp_path) in result["dataset_path"]
        assert isinstance(result["directory_listing"], list)
        assert "src" in result["directory_listing"]

    def test_nonexistent_dataset_path(self):
        result = resolve_compile_config("/nonexistent/path")
        assert result["found"] is False


class TestWriteCompileConfig:
    def test_creates_directory_and_script(self, tmp_path):
        script_content = "#!/bin/bash\ngcc -O0 $1 -o $2\n"
        result = write_compile_config(str(tmp_path), script_content)
        assert result["success"] is True

        script_path = Path(result["compile_script"])
        assert script_path.exists()
        assert script_path.read_text() == script_content
        assert os.access(str(script_path), os.X_OK)

    def test_overwrites_existing(self, tmp_path):
        config_dir = tmp_path / ".CodeQL-AI"
        config_dir.mkdir()
        (config_dir / "compile.sh").write_text("old content")

        result = write_compile_config(str(tmp_path), "new content")
        assert result["success"] is True
        assert Path(result["compile_script"]).read_text() == "new content"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Volumes/Important/E_backup/Creation/PPPPPPP/创新计划2025/Project/Exp/CodeQL-AI && python -m pytest test/test_symbolic_sanitizer/test_compile_config.py -v`
Expected: FAIL — `ImportError`

- [ ] **Step 3: Implement**

Create `src/libs/symbolic_sanitizer/compile_config.py`:

```python
"""
Compile Config — dataset-level compile.sh discovery and creation.
"""

import os
import stat
from pathlib import Path


def resolve_compile_config(dataset_path: str) -> dict:
    """
    Check if a dataset has an existing compile.sh config.

    Looks for: {dataset_path}/.CodeQL-AI/compile.sh
    If not found, returns the top-level directory listing to help
    the Agent generate an appropriate compile.sh.
    """
    path = Path(dataset_path)
    if not path.exists():
        return {
            "found": False,
            "dataset_path": dataset_path,
            "directory_listing": [],
        }

    script_path = path / ".CodeQL-AI" / "compile.sh"
    if script_path.exists():
        return {
            "found": True,
            "compile_script": str(script_path),
        }

    listing = sorted([
        entry.name for entry in path.iterdir()
        if not entry.name.startswith('.')
    ])

    return {
        "found": False,
        "dataset_path": str(path),
        "directory_listing": listing,
    }


def write_compile_config(dataset_path: str, script_content: str) -> dict:
    """
    Write compile.sh to {dataset_path}/.CodeQL-AI/compile.sh.
    Creates directory if needed, sets executable permission.
    """
    path = Path(dataset_path)
    config_dir = path / ".CodeQL-AI"

    try:
        config_dir.mkdir(parents=True, exist_ok=True)
        script_path = config_dir / "compile.sh"
        script_path.write_text(script_content, encoding='utf-8')
        script_path.chmod(script_path.stat().st_mode | stat.S_IEXEC)

        return {
            "success": True,
            "compile_script": str(script_path),
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Volumes/Important/E_backup/Creation/PPPPPPP/创新计划2025/Project/Exp/CodeQL-AI && python -m pytest test/test_symbolic_sanitizer/test_compile_config.py -v`
Expected: All 5 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/libs/symbolic_sanitizer/compile_config.py test/test_symbolic_sanitizer/test_compile_config.py
git commit -m "feat: add compile_config for dataset-level compile.sh management"
```

---

### Task 4: Rewrite `harness_generator.py`

**Files:**
- Rewrite: `src/libs/symbolic_sanitizer/harness_generator.py`
- Rewrite: `test/test_symbolic_sanitizer/test_step5_harness_generation.py`

- [ ] **Step 1: Write tests for new `generate_harness`**

Rewrite `test/test_symbolic_sanitizer/test_step5_harness_generation.py`:

```python
"""Tests for harness_generator: generate_harness (structured) + compile_harness (compile.sh)."""
import os
import sys
import stat
import pytest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../src'))

from libs.symbolic_sanitizer.harness_generator import generate_harness, compile_harness


class TestGenerateHarness:
    def test_basic_harness_generation(self):
        result = generate_harness(
            target_function="validate_cmd",
            source_file="src/validate.c",
            call_chain=[
                'char* result = sanitize(symbolic_input);',
                'int ok = validate_cmd(result);',
            ],
            sink_expression="system(result)",
            includes=["validate.h"],
        )
        assert result["success"] is True
        code = result["harness_code"]
        assert 'void __sink_reached()' in code
        assert 'char symbolic_input[64]' in code
        assert 'sanitize(symbolic_input)' in code
        assert 'validate_cmd(result)' in code
        assert '__sink_reached()' in code
        assert 'system(result)' in code
        assert '#include "validate.h"' in code

    def test_empty_includes(self):
        result = generate_harness(
            target_function="foo",
            source_file="src/foo.c",
            call_chain=["foo(symbolic_input);"],
            sink_expression="printf(symbolic_input)",
            includes=[],
        )
        assert result["success"] is True
        assert 'foo(symbolic_input)' in result["harness_code"]

    def test_multiple_call_chain_steps(self):
        result = generate_harness(
            target_function="process",
            source_file="src/process.c",
            call_chain=[
                'char* step1 = preprocess(symbolic_input);',
                'char* step2 = transform(step1);',
                'int valid = process(step2);',
            ],
            sink_expression="exec(step2)",
            includes=["process.h", "transform.h"],
        )
        assert result["success"] is True
        code = result["harness_code"]
        assert 'preprocess(symbolic_input)' in code
        assert 'transform(step1)' in code
        assert 'process(step2)' in code
        assert '#include "process.h"' in code
        assert '#include "transform.h"' in code


class TestCompileHarness:
    def test_successful_compilation(self, tmp_path):
        # Create a compile.sh that just uses gcc
        script = tmp_path / "compile.sh"
        script.write_text("#!/bin/bash\ngcc -O0 -g \"$1\" -o \"$2\"\n")
        script.chmod(script.stat().st_mode | stat.S_IEXEC)

        harness_code = """
#include <stdio.h>
void __sink_reached() {}
char symbolic_input[64];
int main() {
    __sink_reached();
    return 0;
}
"""
        result = compile_harness(harness_code, str(script))
        assert result["success"] is True
        assert result["binary_path"] is not None
        assert os.path.exists(result["binary_path"])

    def test_compilation_failure(self, tmp_path):
        script = tmp_path / "compile.sh"
        script.write_text("#!/bin/bash\ngcc -O0 \"$1\" -o \"$2\"\n")
        script.chmod(script.stat().st_mode | stat.S_IEXEC)

        harness_code = "THIS IS NOT VALID C CODE @@@@"
        result = compile_harness(harness_code, str(script))
        assert result["success"] is False
        assert result["error"] is not None

    def test_missing_compile_script(self):
        result = compile_harness("int main(){}", "/nonexistent/compile.sh")
        assert result["success"] is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Volumes/Important/E_backup/Creation/PPPPPPP/创新计划2025/Project/Exp/CodeQL-AI && python -m pytest test/test_symbolic_sanitizer/test_step5_harness_generation.py -v`
Expected: FAIL — old imports don't match new module shape

- [ ] **Step 3: Rewrite `harness_generator.py`**

Rewrite `src/libs/symbolic_sanitizer/harness_generator.py`:

```python
"""
Harness Generator — structured harness generation + compile.sh–based compilation.
"""

import os
import tempfile
import subprocess
import logging
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


def generate_harness(
    target_function: str,
    source_file: str,
    call_chain: list,
    sink_expression: str,
    includes: list = None,
) -> dict:
    """
    Generate C harness code from structured parameters.

    Args:
        target_function: Target sanitizer function name (for metadata)
        source_file: Source file containing the target function (for metadata)
        call_chain: List of C statements forming the call sequence
        sink_expression: C expression for the sink call (placed after __sink_reached)
        includes: List of header files to #include

    Returns:
        {"success": True, "harness_code": "...", "error": None}
    """
    if includes is None:
        includes = []

    include_lines = ['#include <stdio.h>', '#include <stdlib.h>', '#include <string.h>']
    for header in includes:
        include_lines.append(f'#include "{header}"')

    call_chain_lines = '\n    '.join(call_chain)

    harness_code = f"""{chr(10).join(include_lines)}

void __sink_reached() {{}}

char symbolic_input[64];

int main() {{
    {call_chain_lines}
    __sink_reached();
    {sink_expression};
    return 0;
}}
"""
    return {
        "success": True,
        "harness_code": harness_code,
        "error": None,
    }


def compile_harness(harness_code: str, compile_script: str) -> dict:
    """
    Compile harness code using a dataset's compile.sh.

    Args:
        harness_code: C source code for the harness
        compile_script: Path to compile.sh (takes <harness.c> <output_binary>)

    Returns:
        {"success": True, "binary_path": "...", "harness_path": "...", "error": None}
    """
    if not Path(compile_script).exists():
        return {
            "success": False,
            "binary_path": None,
            "harness_path": None,
            "error": f"Compile script not found: {compile_script}",
        }

    temp_dir = tempfile.mkdtemp(prefix="symbolic_harness_")
    harness_path = os.path.join(temp_dir, "harness.c")
    binary_path = os.path.join(temp_dir, "harness_bin")

    try:
        with open(harness_path, 'w') as f:
            f.write(harness_code)

        result = subprocess.run(
            ["bash", compile_script, harness_path, binary_path],
            capture_output=True,
            text=True,
            timeout=60,
        )

        if result.returncode != 0:
            return {
                "success": False,
                "binary_path": None,
                "harness_path": harness_path,
                "error": f"Compilation failed: {result.stderr}",
            }

        return {
            "success": True,
            "binary_path": binary_path,
            "harness_path": harness_path,
            "error": None,
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "binary_path": None,
            "harness_path": harness_path,
            "error": "Compilation timed out (60s)",
        }
    except Exception as e:
        return {
            "success": False,
            "binary_path": None,
            "harness_path": harness_path,
            "error": f"Compilation error: {str(e)}",
        }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Volumes/Important/E_backup/Creation/PPPPPPP/创新计划2025/Project/Exp/CodeQL-AI && python -m pytest test/test_symbolic_sanitizer/test_step5_harness_generation.py -v`
Expected: All 6 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/libs/symbolic_sanitizer/harness_generator.py test/test_symbolic_sanitizer/test_step5_harness_generation.py
git commit -m "feat: rewrite harness_generator with structured params and compile.sh"
```

---

### Task 5: Rewrite `symbolic_sanitizer.py` — sink reachability

**Files:**
- Rewrite: `src/libs/symbolic_sanitizer/symbolic_sanitizer.py`
- Rewrite: `test/test_symbolic_sanitizer/test_step6_verify_with_constraints.py`

- [ ] **Step 1: Write tests for `execute_reachability`**

Rewrite `test/test_symbolic_sanitizer/test_step6_verify_with_constraints.py`:

```python
"""Tests for SymbolicExecutor.execute_reachability (sink reachability via angr)."""
import os
import sys
import pytest
from unittest.mock import MagicMock, patch, PropertyMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../src'))


class TestExecuteReachability:
    """Test execute_reachability with mocked angr."""

    @patch('libs.symbolic_sanitizer.symbolic_sanitizer.angr')
    @patch('libs.symbolic_sanitizer.symbolic_sanitizer.claripy')
    def test_reachable_returns_true(self, mock_claripy, mock_angr):
        from libs.symbolic_sanitizer.symbolic_sanitizer import SymbolicExecutor

        # Setup mocks
        mock_project = MagicMock()
        mock_angr.Project.return_value = mock_project

        mock_symbol = MagicMock()
        mock_symbol.rebased_addr = 0x400000
        mock_sink_symbol = MagicMock()
        mock_sink_symbol.rebased_addr = 0x400100

        def find_symbol_side_effect(name):
            if name == "main":
                return mock_symbol
            if name == "__sink_reached":
                return mock_sink_symbol
            return None
        mock_project.loader.find_symbol.side_effect = find_symbol_side_effect

        mock_state = MagicMock()
        mock_state.solver.satisfiable.return_value = True
        mock_project.factory.call_state.return_value = mock_state

        # simgr.explore finds a path to sink
        mock_simgr = MagicMock()
        found_state = MagicMock()
        found_state.solver.eval.return_value = 0x41
        mock_simgr.found = [found_state]
        mock_project.factory.simgr.return_value = mock_simgr

        mock_claripy.BVS.return_value = MagicMock()

        executor = SymbolicExecutor.__new__(SymbolicExecutor)
        executor.project = mock_project
        executor.binary_path = "/fake/binary"

        result = executor.execute_reachability(
            constraints={"input_constraints": [{"type": "contains_any", "chars": [";"]}]},
            sink_marker="__sink_reached",
            timeout=60,
        )

        assert result["success"] is True
        assert result["reachable"] is True
        assert result["paths_to_sink"] == 1

    @patch('libs.symbolic_sanitizer.symbolic_sanitizer.angr')
    @patch('libs.symbolic_sanitizer.symbolic_sanitizer.claripy')
    def test_not_reachable_returns_false(self, mock_claripy, mock_angr):
        from libs.symbolic_sanitizer.symbolic_sanitizer import SymbolicExecutor

        mock_project = MagicMock()
        mock_angr.Project.return_value = mock_project

        mock_symbol = MagicMock()
        mock_symbol.rebased_addr = 0x400000
        mock_sink_symbol = MagicMock()
        mock_sink_symbol.rebased_addr = 0x400100

        def find_symbol_side_effect(name):
            if name == "main":
                return mock_symbol
            if name == "__sink_reached":
                return mock_sink_symbol
            return None
        mock_project.loader.find_symbol.side_effect = find_symbol_side_effect

        mock_state = MagicMock()
        mock_state.solver.satisfiable.return_value = True
        mock_project.factory.call_state.return_value = mock_state

        # simgr.explore does NOT find any path to sink
        mock_simgr = MagicMock()
        mock_simgr.found = []
        mock_project.factory.simgr.return_value = mock_simgr

        mock_claripy.BVS.return_value = MagicMock()

        executor = SymbolicExecutor.__new__(SymbolicExecutor)
        executor.project = mock_project
        executor.binary_path = "/fake/binary"

        result = executor.execute_reachability(
            constraints={"input_constraints": [{"type": "contains_any", "chars": [";"]}]},
            sink_marker="__sink_reached",
            timeout=60,
        )

        assert result["success"] is True
        assert result["reachable"] is False
        assert result["paths_to_sink"] == 0

    @patch('libs.symbolic_sanitizer.symbolic_sanitizer.angr')
    @patch('libs.symbolic_sanitizer.symbolic_sanitizer.claripy')
    def test_sink_marker_not_found(self, mock_claripy, mock_angr):
        from libs.symbolic_sanitizer.symbolic_sanitizer import SymbolicExecutor

        mock_project = MagicMock()
        mock_angr.Project.return_value = mock_project

        mock_symbol = MagicMock()
        mock_symbol.rebased_addr = 0x400000
        mock_project.loader.find_symbol.side_effect = lambda name: mock_symbol if name == "main" else None

        executor = SymbolicExecutor.__new__(SymbolicExecutor)
        executor.project = mock_project
        executor.binary_path = "/fake/binary"

        result = executor.execute_reachability(
            constraints={"input_constraints": []},
            sink_marker="__sink_reached",
            timeout=60,
        )

        assert result["success"] is False
        assert "__sink_reached" in result["error"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Volumes/Important/E_backup/Creation/PPPPPPP/创新计划2025/Project/Exp/CodeQL-AI && python -m pytest test/test_symbolic_sanitizer/test_step6_verify_with_constraints.py -v`
Expected: FAIL — old code structure doesn't have `execute_reachability`

- [ ] **Step 3: Rewrite `symbolic_sanitizer.py`**

Rewrite `src/libs/symbolic_sanitizer/symbolic_sanitizer.py`:

```python
"""
Symbolic Execution — angr-based sink reachability verification.
"""

import logging
from typing import List, Dict, Any, Optional

import angr
import claripy

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SymbolicExecutor:
    """angr-based symbolic execution for branch-level reachability analysis."""

    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.project = angr.Project(binary_path, auto_load_libs=False)
        logger.info(f"Loaded binary: {binary_path}")

    def execute_reachability(
        self, constraints: dict, sink_marker: str, timeout: int
    ) -> dict:
        """
        Check if an input satisfying input_constraints can reach the sink_marker function.

        Returns:
            {
                "success": bool,
                "reachable": bool,
                "paths_explored": int,
                "paths_to_sink": int,
                "counterexample": str or None,  # hex bytes if reachable
                "error": str or None,
            }
        """
        try:
            main_addr = self._find_function("main")
            if not main_addr:
                return self._error_result("main function not found")

            sink_addr = self._find_function(sink_marker)
            if not sink_addr:
                return self._error_result(f"{sink_marker} function not found in binary")

            sym_bytes = [claripy.BVS(f'byte_{i}', 8) for i in range(64)]
            input_addr = 0x500000

            state = self.project.factory.call_state(main_addr, input_addr)
            for i, b in enumerate(sym_bytes):
                state.memory.store(input_addr + i, b)

            input_constraints = constraints.get("input_constraints", [])
            self.apply_input_constraints(state, sym_bytes, input_constraints)

            if not state.solver.satisfiable():
                return {
                    "success": True,
                    "reachable": False,
                    "paths_explored": 0,
                    "paths_to_sink": 0,
                    "counterexample": None,
                    "error": None,
                }

            simgr = self.project.factory.simgr(state)
            logger.info(f"Exploring reachability to {sink_marker} at 0x{sink_addr:x}")
            simgr.explore(find=sink_addr)

            paths_to_sink = len(simgr.found)
            paths_explored = (
                len(simgr.found)
                + len(getattr(simgr, 'deadended', []))
                + len(getattr(simgr, 'active', []))
                + len(getattr(simgr, 'errored', []))
            )

            counterexample = None
            if simgr.found:
                try:
                    found_state = simgr.found[0]
                    concrete = bytes([
                        found_state.solver.eval(b, cast_to=int) for b in sym_bytes[:32]
                    ])
                    counterexample = concrete.hex()
                except Exception:
                    counterexample = "extraction_failed"

            return {
                "success": True,
                "reachable": paths_to_sink > 0,
                "paths_explored": paths_explored,
                "paths_to_sink": paths_to_sink,
                "counterexample": counterexample,
                "error": None,
            }

        except Exception as e:
            logger.error(f"Reachability analysis failed: {e}")
            return self._error_result(str(e))

    def _find_function(self, name: str) -> Optional[int]:
        """Find function address by symbol name."""
        try:
            symbol = self.project.loader.find_symbol(name)
            if symbol:
                return symbol.rebased_addr
        except Exception:
            pass

        for sym in self.project.loader.symbols:
            if sym.name == name:
                return sym.rebased_addr
        return None

    def apply_input_constraints(
        self, state, sym_bytes: List, input_constraints: List[Dict]
    ) -> None:
        """Apply input constraints to angr state solver."""
        constraint = self._build_input_constraint(sym_bytes, input_constraints)
        state.solver.add(constraint)

    def _build_input_constraint(self, sym_bytes: List, input_constraints: List[Dict]):
        combined = []
        for c in input_constraints:
            ctype = c.get("type")
            if ctype == "contains_any":
                chars = c.get("chars", [])
                if chars:
                    combined.append(self._build_contains_any_constraint(sym_bytes, chars))
            elif ctype == "length_range":
                min_len = c.get("min", 0)
                max_len = c.get("max", len(sym_bytes))
                combined.append(self._build_length_range_constraint(sym_bytes, min_len, max_len))
        if combined:
            return claripy.And(*combined)
        return claripy.true

    def _build_contains_any_constraint(self, sym_bytes: List, chars: List[str]):
        char_vals = [ord(ch[0]) if len(ch) > 0 else ord(' ') for ch in chars]
        byte_matches = []
        for byte in sym_bytes:
            char_matches = [byte == val for val in char_vals]
            byte_matches.append(claripy.Or(*char_matches))
        return claripy.Or(*byte_matches)

    def _build_length_range_constraint(self, sym_bytes: List, min_len: int, max_len: int):
        constraints = []
        if min_len > 0 and min_len <= len(sym_bytes):
            for i in range(min_len):
                if i < len(sym_bytes):
                    constraints.append(sym_bytes[i] != 0)
        if max_len < len(sym_bytes):
            constraints.append(sym_bytes[max_len] == 0)
        if constraints:
            return claripy.And(*constraints)
        return claripy.true

    @staticmethod
    def _error_result(error: str) -> dict:
        return {
            "success": False,
            "reachable": False,
            "paths_explored": 0,
            "paths_to_sink": 0,
            "counterexample": None,
            "error": error,
        }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Volumes/Important/E_backup/Creation/PPPPPPP/创新计划2025/Project/Exp/CodeQL-AI && python -m pytest test/test_symbolic_sanitizer/test_step6_verify_with_constraints.py -v`
Expected: All 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/libs/symbolic_sanitizer/symbolic_sanitizer.py test/test_symbolic_sanitizer/test_step6_verify_with_constraints.py
git commit -m "feat: rewrite SymbolicExecutor with sink reachability via explore(find=sink)"
```

---

### Task 6: Clean up `sarif_parser.py`, delete `verifier.py`, update `__init__.py`

**Files:**
- Modify: `src/libs/symbolic_sanitizer/sarif_parser.py` — remove `parse_sarif_result`
- Delete: `src/libs/symbolic_sanitizer/verifier.py`
- Rewrite: `src/libs/symbolic_sanitizer/__init__.py`
- Delete: `test/test_symbolic_sanitizer/test_step3_function_selector_skill.py`
- Delete: `test/test_symbolic_sanitizer/test_step4_constraint_generator_skill.py`

- [ ] **Step 1: Remove `parse_sarif_result` and `_parse_result` from `sarif_parser.py`**

Delete lines 40-87 from `src/libs/symbolic_sanitizer/sarif_parser.py` (the `parse_sarif_result` function, the `_parse_result` helper, and the `FunctionLocation` dataclass). Keep: `load_sarif_from_file`, `extract_taint_paths`, `TaintPath`, `_parse_location_node`.

The file should become:

```python
"""
SARIF Parser — extract taint paths from CodeQL SARIF results.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass


@dataclass
class TaintPath:
    """
    Represents a complete taint path extracted from SARIF codeFlows.
    """
    path_id: str
    source: Dict
    sink: Dict
    intermediate_locations: List[Dict]
    rule_id: str
    message: str


def load_sarif_from_file(sarif_path: str) -> Dict[str, Any]:
    """Load and parse SARIF file."""
    with open(sarif_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def extract_taint_paths(sarif_data: dict) -> List[TaintPath]:
    """
    Extract complete taint paths from SARIF 2.1.0 codeFlows/threadFlows structure.
    """
    taint_paths = []
    path_counter = 0

    for run in sarif_data.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            message = result.get("message", {}).get("text", "")

            code_flows = result.get("codeFlows", [])
            for code_flow in code_flows:
                thread_flows = code_flow.get("threadFlows", [])
                for thread_flow in thread_flows:
                    locations = thread_flow.get("locations", [])
                    if len(locations) < 2:
                        continue

                    path_nodes = [_parse_location_node(loc) for loc in locations]
                    path_nodes = [node for node in path_nodes if node is not None]

                    if len(path_nodes) < 2:
                        continue

                    path_counter += 1
                    path_id = f"path_{path_counter:04d}"

                    source = path_nodes[0]
                    sink = path_nodes[-1]
                    intermediate = path_nodes[1:-1] if len(path_nodes) > 2 else []

                    taint_path = TaintPath(
                        path_id=path_id,
                        source=source,
                        sink=sink,
                        intermediate_locations=intermediate,
                        rule_id=rule_id,
                        message=message
                    )
                    taint_paths.append(taint_path)

    return taint_paths


def _parse_location_node(location_data: dict) -> Optional[dict]:
    """Parse a single location node from threadFlow locations."""
    physical = location_data.get("physicalLocation", {})
    artifact = physical.get("artifactLocation", {})
    region = physical.get("region", {})
    logical = location_data.get("logicalLocation", {})

    file_path = artifact.get("uri", "")
    line_number = region.get("startLine", 0)

    if not file_path or not line_number:
        return None

    return {
        "file_path": file_path,
        "line_number": line_number,
        "function_name": logical.get("name") or logical.get("fullyQualifiedName"),
        "column": region.get("startColumn")
    }
```

- [ ] **Step 2: Delete `verifier.py`**

```bash
rm src/libs/symbolic_sanitizer/verifier.py
```

- [ ] **Step 3: Delete obsolete test files**

```bash
rm test/test_symbolic_sanitizer/test_step3_function_selector_skill.py
rm test/test_symbolic_sanitizer/test_step4_constraint_generator_skill.py
```

- [ ] **Step 4: Rewrite `__init__.py`**

Rewrite `src/libs/symbolic_sanitizer/__init__.py`:

```python
"""
Symbolic Sanitizer — branch-level selective symbolic execution for SAST false positive reduction.
"""

from .sarif_parser import (
    load_sarif_from_file,
    extract_taint_paths,
    TaintPath,
)
from .path_context import read_path_context, find_enclosing_function
from .harness_generator import generate_harness, compile_harness
from .compile_config import resolve_compile_config, write_compile_config
from .symbolic_sanitizer import SymbolicExecutor

__all__ = [
    'load_sarif_from_file',
    'extract_taint_paths',
    'TaintPath',
    'read_path_context',
    'find_enclosing_function',
    'generate_harness',
    'compile_harness',
    'resolve_compile_config',
    'write_compile_config',
    'SymbolicExecutor',
]
```

- [ ] **Step 5: Run existing SARIF tests to confirm they still pass**

Run: `cd /Volumes/Important/E_backup/Creation/PPPPPPP/创新计划2025/Project/Exp/CodeQL-AI && python -m pytest test/test_symbolic_sanitizer/test_step1_parse_sarif_detailed.py -v`
Expected: PASS (this test uses `extract_taint_paths` which we kept)

Note: Some tests in `test_step1_parse_sarif_detailed.py` may import `parse_sarif_result` or `FunctionLocation` — if so, remove those specific test cases that reference deleted functions. The `extract_taint_paths` tests should remain.

- [ ] **Step 6: Commit**

```bash
git add -A src/libs/symbolic_sanitizer/ test/test_symbolic_sanitizer/
git commit -m "refactor: remove old verifier, sarif_result parser, obsolete tests; update __init__"
```

---

### Task 7: Rewrite MCP Server entry point

**Files:**
- Rewrite: `src/mcptools/symbolic_sanitizer.py`

- [ ] **Step 1: Rewrite the MCP server**

Rewrite `src/mcptools/symbolic_sanitizer.py`:

```python
#!/usr/bin/env python3
"""
MCP Server: Symbolic Sanitizer
Branch-level selective symbolic execution for SAST false positive reduction.

Tools: parse_sarif_detailed, read_path_context, generate_harness,
       resolve_compile_config, write_compile_config, compile_harness, verify_branch
"""

import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from fastmcp import FastMCP
from libs.symbolic_sanitizer import (
    load_sarif_from_file,
    extract_taint_paths,
    read_path_context as _read_path_context,
    generate_harness as _generate_harness,
    compile_harness as _compile_harness,
    resolve_compile_config as _resolve_compile_config,
    write_compile_config as _write_compile_config,
    SymbolicExecutor,
)

mcp = FastMCP(
    name="symbolic_sanitizer",
    instructions="Branch-level selective symbolic execution for verifying sanitizer effectiveness"
)


@mcp.tool()
def parse_sarif_detailed(sarif_path: str) -> dict:
    """Parse SARIF file and extract complete taint paths with source/sink information."""
    if not os.path.exists(sarif_path):
        return {"success": False, "error": f"SARIF file not found: {sarif_path}"}

    try:
        sarif_data = load_sarif_from_file(sarif_path)
    except json.JSONDecodeError as e:
        return {"success": False, "error": f"Failed to parse SARIF JSON: {str(e)}"}
    except Exception as e:
        return {"success": False, "error": f"Failed to load SARIF file: {str(e)}"}

    try:
        taint_paths = extract_taint_paths(sarif_data)
    except Exception as e:
        return {"success": False, "error": f"Failed to extract taint paths: {str(e)}"}

    if not taint_paths:
        return {"success": True, "count": 0, "paths": []}

    formatted_paths = []
    for path in taint_paths:
        formatted_paths.append({
            "path_id": path.path_id,
            "source": {
                "file_path": path.source.get("file_path", ""),
                "line_number": path.source.get("line_number", 0),
                "function_name": path.source.get("function_name"),
                "column": path.source.get("column")
            },
            "sink": {
                "file_path": path.sink.get("file_path", ""),
                "line_number": path.sink.get("line_number", 0),
                "function_name": path.sink.get("function_name"),
                "column": path.sink.get("column")
            },
            "intermediate_locations": [
                {
                    "file_path": loc.get("file_path", ""),
                    "line_number": loc.get("line_number", 0),
                    "function_name": loc.get("function_name"),
                    "column": loc.get("column")
                }
                for loc in path.intermediate_locations
            ],
            "rule_id": path.rule_id,
            "message": path.message
        })

    return {"success": True, "count": len(formatted_paths), "paths": formatted_paths}


@mcp.tool()
def read_path_context(locations: list) -> dict:
    """Batch-read source code for all nodes on a taint path."""
    return _read_path_context(locations)


@mcp.tool()
def generate_harness(
    target_function: str,
    source_file: str,
    call_chain: list,
    sink_expression: str,
    includes: list = [],
) -> dict:
    """Generate C harness code from structured parameters."""
    return _generate_harness(
        target_function=target_function,
        source_file=source_file,
        call_chain=call_chain,
        sink_expression=sink_expression,
        includes=includes,
    )


@mcp.tool()
def resolve_compile_config(dataset_path: str) -> dict:
    """Check if dataset has compile.sh config at {dataset}/.CodeQL-AI/compile.sh."""
    return _resolve_compile_config(dataset_path)


@mcp.tool()
def write_compile_config(dataset_path: str, script_content: str) -> dict:
    """Write compile.sh to {dataset}/.CodeQL-AI/compile.sh."""
    return _write_compile_config(dataset_path, script_content)


@mcp.tool()
def compile_harness(harness_code: str, compile_script: str) -> dict:
    """Compile harness code using dataset's compile.sh."""
    return _compile_harness(harness_code, compile_script)


@mcp.tool()
def verify_branch(
    binary_path: str,
    constraints: dict,
    sink_marker: str = "__sink_reached",
    timeout: int = 120,
) -> dict:
    """Verify if attack input can reach sink marker via angr symbolic execution."""
    if not os.path.exists(binary_path):
        return {
            "success": False,
            "reachable": False,
            "paths_explored": 0,
            "paths_to_sink": 0,
            "counterexample": None,
            "error": f"Binary file not found: {binary_path}",
        }

    try:
        executor = SymbolicExecutor(binary_path)
        return executor.execute_reachability(constraints, sink_marker, timeout)
    except Exception as e:
        return {
            "success": False,
            "reachable": False,
            "paths_explored": 0,
            "paths_to_sink": 0,
            "counterexample": None,
            "error": f"Symbolic execution failed: {str(e)}",
        }


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--stdio":
        mcp.run()
    else:
        mcp.run(transport="http", host="127.0.0.1", port=8000)
```

- [ ] **Step 2: Verify the server can be imported**

Run: `cd /Volumes/Important/E_backup/Creation/PPPPPPP/创新计划2025/Project/Exp/CodeQL-AI && python -c "import sys; sys.modules['fastmcp'] = type(sys)('fastmcp'); sys.modules['fastmcp'].FastMCP = lambda **kw: type('M', (), {'tool': lambda self, **k: lambda f: f, 'run': lambda self, **k: None})(); sys.modules['angr'] = type(sys)('angr'); sys.modules['claripy'] = type(sys)('claripy'); exec(open('src/mcptools/symbolic_sanitizer.py').read()); print('OK: 7 tools registered')"`
Expected: `OK: 7 tools registered`

- [ ] **Step 3: Commit**

```bash
git add src/mcptools/symbolic_sanitizer.py
git commit -m "feat: rewrite MCP server with 7-tool surface for branch-level verification"
```

---

### Task 8: Rewrite Agent workflow prompt (readme.md)

**Files:**
- Rewrite: `src/libs/symbolic_sanitizer/readme.md`

- [ ] **Step 1: Write the new readme.md**

Rewrite `src/libs/symbolic_sanitizer/readme.md`:

````markdown
# Symbolic Sanitizer — Agent 工作流

你是一个安全分析专家，使用 MCP Tools 和自身推理能力来验证 SAST 告警中的净化函数是否有效。

## 系统架构

- **MCP Tools**: 确定性操作（SARIF 解析、源码读取、harness 生成、编译、符号执行）
- **Agent (你)**: 语义推理（分支分析、约束生成、验证计划制定、compile.sh 编写）

## 可用 MCP Tools

| 工具名 | 用途 | 输入 | 输出 |
|--------|------|------|------|
| `parse_sarif_detailed` | 解析 SARIF，提取完整污点路径 | `sarif_path` | paths 列表 |
| `read_path_context` | 批量读取路径上所有函数源码 | `locations` 列表 | 函数源码列表 |
| `generate_harness` | 结构化参数生成 C harness | `target_function`, `source_file`, `call_chain`, `sink_expression`, `includes` | harness_code |
| `resolve_compile_config` | 检查数据集是否有 compile.sh | `dataset_path` | found + 路径或目录列表 |
| `write_compile_config` | 写入 compile.sh | `dataset_path`, `script_content` | compile_script 路径 |
| `compile_harness` | 用 compile.sh 编译 harness | `harness_code`, `compile_script` | binary_path |
| `verify_branch` | angr 验证 sink 可达性 | `binary_path`, `constraints`, `sink_marker` | reachable + counterexample |

## 分析流程（7 步）

```
Step 1: parse_sarif_detailed          → MCP Tool
Step 2: read_path_context             → MCP Tool
Step 3: 分支分析 + 验证计划            → 你自己推理
              ┌─────── 对每个 verification_target 循环 ───────┐
Step 4:       │ generate_harness        → MCP Tool             │
Step 5:       │ resolve/write compile   → MCP Tool + 你(首次)  │
Step 6:       │ compile_harness         → MCP Tool             │
Step 7:       │ verify_branch           → MCP Tool             │
              └────────────────────────────────────────────────┘
```

### Step 1: 解析 SARIF

调用 `parse_sarif_detailed`，获取所有污点路径。

### Step 2: 读取路径上下文

将所有路径的 source、sink、intermediate_locations 合并为一个 locations 列表，调用 `read_path_context` 获取每个节点的函数源码。

### Step 3: 分支分析 + 生成验证计划（你自己做）

阅读 Step 2 返回的全部源码，**一次性**分析所有污点路径，输出结构化的验证计划：

```json
{
  "dataset_path": "/path/to/dataset",
  "compile_info": {
    "source_files": ["src/validate.c"],
    "include_files": ["validate.h"],
    "include_dirs": ["src/", "include/"]
  },
  "verification_targets": [
    {
      "id": "vt_001",
      "path_id": "path_0001",
      "rule_id": "cpp/command-line-injection",
      "target_branch": {
        "file": "src/validate.c",
        "line": 25,
        "condition": "if(strchr(input, ';') != NULL)"
      },
      "sanitization_type": "判定型",
      "target_function": "validate_cmd",
      "source_file": "src/validate.c",
      "call_chain": ["char* result = sanitize(symbolic_input);", "int ok = validate_cmd(result);"],
      "sink_expression": "system(result)",
      "includes": ["validate.h"],
      "input_constraints": [{"type": "contains_any", "chars": [";", "|", "&"]}],
      "confidence": "medium",
      "reasoning": "..."
    }
  ]
}
```

分析要点：
1. 识别路径上所有与净化相关的分支条件
2. 判断净化类型：判定型（branch guard）或过滤型（字符替换/删除）
3. 根据 rule_id 生成 input_constraints
4. 收集涉及的 source_files、include_files、include_dirs（用于 compile.sh）
5. 为每个 target 构造 call_chain 和 sink_expression

### Step 4-7: 逐条验证（循环）

对 verification_targets 中的每个 target：

**Step 4**: 调用 `generate_harness`，传入 target 的 `target_function`, `source_file`, `call_chain`, `sink_expression`, `includes`。

**Step 5**: 调用 `resolve_compile_config(dataset_path)`。
- 如果 `found=true`，记住 `compile_script` 路径。
- 如果 `found=false`（仅首次），根据 `compile_info` 和 `directory_listing` 编写 compile.sh，调用 `write_compile_config` 写入。后续 target 复用同一个 compile_script。

compile.sh 约定：`bash compile.sh <harness.c> <output_binary>`

**Step 6**: 调用 `compile_harness(harness_code, compile_script)`。

**Step 7**: 调用 `verify_branch(binary_path, {"input_constraints": target.input_constraints}, "__sink_reached")`。

### 结果判定

- `reachable = true` → 净化无效，攻击输入可绕过净化到达 sink。counterexample 是一个具体的绕过输入。
- `reachable = false` → 净化有效，满足攻击约束的输入无法到达 sink。

## 输出报告格式

```markdown
## 分支级符号执行验证报告

### SARIF 概览
- 污点路径数: {count}
- 数据集: {dataset_path}

### 验证结果

| ID | 路径 | 规则 | 目标函数 | 关键分支 | 结果 | 置信度 |
|----|------|------|----------|----------|------|--------|
| vt_001 | path_0001 | cpp/cmd-injection | validate_cmd | L25: if(strchr...) | ✅ 已净化 | medium |
| vt_002 | path_0002 | cpp/buffer-overflow | process_data | L42: if(strlen...) | ❌ 可绕过 | high |

### 详细分析
（对每个 target 给出分析过程和结论）

### 绕过样例
（对 reachable=true 的 target，展示 counterexample）
```
````

- [ ] **Step 2: Commit**

```bash
git add src/libs/symbolic_sanitizer/readme.md
git commit -m "docs: rewrite Agent workflow prompt for 7-step branch-level pipeline"
```

---

### Task 9: Update conftest.py and run full test suite

**Files:**
- Modify: `test/test_symbolic_sanitizer/conftest.py`

- [ ] **Step 1: Clean up conftest.py**

Remove fixtures that reference deleted concepts (`mock_taint_analysis_result`, `mock_taint_analysis_no_functions`, `mock_taint_analysis_failure` — these belong to `function_level_sanitizer`'s test suite, not symbolic_sanitizer). Keep SARIF-related fixtures (`sample_sarif_data`, `sample_sarif_no_codeflows`, `sample_sarif_empty_results`, `sample_sarif_no_runs`, `invalid_sarif_data`, `temp_sarif_file`). Keep `sample_taint_json` fixtures (still useful for integration).

Remove lines 301-342 (the three `mock_taint_analysis_*` fixtures).

- [ ] **Step 2: Run the full test suite**

Run: `cd /Volumes/Important/E_backup/Creation/PPPPPPP/创新计划2025/Project/Exp/CodeQL-AI && python -m pytest test/test_symbolic_sanitizer/ -v --ignore=test/test_symbolic_sanitizer/test_step2_find_potential_functions.py`
Expected: All tests PASS. (Step 2 tests belong to function_level_sanitizer and may require CodeQL — skip them here.)

- [ ] **Step 3: Commit**

```bash
git add test/test_symbolic_sanitizer/conftest.py
git commit -m "chore: clean up conftest, remove obsolete fixtures"
```

---

### Task 10: Final integration check

- [ ] **Step 1: Verify all source files exist and are importable**

```bash
cd /Volumes/Important/E_backup/Creation/PPPPPPP/创新计划2025/Project/Exp/CodeQL-AI
python -c "
import sys, os
sys.path.insert(0, 'src')
# Mock heavy deps
sys.modules['angr'] = type(sys)('angr')
sys.modules['claripy'] = type(sys)('claripy')
from libs.symbolic_sanitizer import (
    load_sarif_from_file, extract_taint_paths, TaintPath,
    read_path_context, find_enclosing_function,
    generate_harness, compile_harness,
    resolve_compile_config, write_compile_config,
    SymbolicExecutor,
)
print('All imports OK')
print(f'Exported symbols: {len([x for x in dir() if not x.startswith(\"_\")])}')
"
```
Expected: `All imports OK`

- [ ] **Step 2: Verify deleted files are gone**

```bash
test ! -f src/libs/symbolic_sanitizer/verifier.py && echo "verifier.py deleted OK"
test ! -f test/test_symbolic_sanitizer/test_step3_function_selector_skill.py && echo "step3 test deleted OK"
test ! -f test/test_symbolic_sanitizer/test_step4_constraint_generator_skill.py && echo "step4 test deleted OK"
```

- [ ] **Step 3: Verify file structure matches spec**

```bash
find src/libs/symbolic_sanitizer -name "*.py" | sort
```
Expected:
```
src/libs/symbolic_sanitizer/__init__.py
src/libs/symbolic_sanitizer/compile_config.py
src/libs/symbolic_sanitizer/harness_generator.py
src/libs/symbolic_sanitizer/path_context.py
src/libs/symbolic_sanitizer/sarif_parser.py
src/libs/symbolic_sanitizer/symbolic_sanitizer.py
```

- [ ] **Step 4: Run full test suite one final time**

```bash
cd /Volumes/Important/E_backup/Creation/PPPPPPP/创新计划2025/Project/Exp/CodeQL-AI && python -m pytest test/test_symbolic_sanitizer/ -v --ignore=test/test_symbolic_sanitizer/test_step2_find_potential_functions.py
```
Expected: All tests PASS

- [ ] **Step 5: Commit any remaining changes**

```bash
git status
# If anything unstaged:
git add -A && git commit -m "chore: final cleanup for symbolic_sanitizer refactor"
```
