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
