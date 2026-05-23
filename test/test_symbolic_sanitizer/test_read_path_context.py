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
