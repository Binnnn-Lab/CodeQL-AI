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
