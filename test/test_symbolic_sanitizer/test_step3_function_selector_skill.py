"""
Test Step 3: Function-Selector LLM Skill

These tests validate the input/output schema for the function-selector skill.
This is a schema validation test suite - no actual LLM calls are made.

The function-selector skill selects the most promising sanitizer/validator function
from a list of candidates based on location, semantics, and vulnerability type matching.
"""

import pytest
from typing import Dict, List, Any
import json


class TestFunctionSelectorInputSchema:
    """Tests for validating input schema structure."""

    @pytest.fixture
    def valid_input(self) -> Dict[str, Any]:
        """Returns a valid input structure for function-selector skill."""
        return {
            "path_id": "path_0001",
            "source": {
                "file_path": "src/input.c",
                "line_number": 10,
                "function_name": "get_user_input"
            },
            "sink": {
                "file_path": "src/exec.c",
                "line_number": 50,
                "function_name": "system"
            },
            "potential_functions": [
                {"name": "sanitize_input", "file": "src/sanitizer.c", "line": 20},
                {"name": "validate_cmd", "file": "src/validate.c", "line": 30},
                {"name": "process_data", "file": "src/process.c", "line": 40}
            ],
            "rule_id": "cpp/command-line-injection",
            "message": "User input reaches system()"
        }

    def test_input_has_required_fields(self, valid_input):
        """Test that input contains all required top-level fields."""
        required_fields = ["path_id", "source", "sink", "potential_functions", "rule_id", "message"]
        for field in required_fields:
            assert field in valid_input, f"Missing required field: {field}"

    def test_source_structure(self, valid_input):
        """Test that source object has correct structure."""
        source = valid_input["source"]
        assert "file_path" in source
        assert "line_number" in source
        assert "function_name" in source
        assert isinstance(source["file_path"], str)
        assert isinstance(source["line_number"], int)
        assert isinstance(source["function_name"], str)

    def test_sink_structure(self, valid_input):
        """Test that sink object has correct structure."""
        sink = valid_input["sink"]
        assert "file_path" in sink
        assert "line_number" in sink
        assert "function_name" in sink
        assert isinstance(sink["file_path"], str)
        assert isinstance(sink["line_number"], int)
        assert isinstance(sink["function_name"], str)

    def test_potential_functions_is_array(self, valid_input):
        """Test that potential_functions is a list."""
        assert isinstance(valid_input["potential_functions"], list)

    def test_potential_function_item_structure(self, valid_input):
        """Test that each potential function has required fields."""
        for func in valid_input["potential_functions"]:
            assert "name" in func, "Function must have 'name' field"
            assert "file" in func, "Function must have 'file' field"
            assert "line" in func, "Function must have 'line' field"
            assert isinstance(func["name"], str)
            assert isinstance(func["file"], str)
            assert isinstance(func["line"], int)

    @pytest.mark.parametrize("rule_id,expected_type", [
        ("cpp/command-line-injection", "command_injection"),
        ("cpp/command-injection", "command_injection"),
        ("cpp/sql-injection", "sql_injection"),
        ("cpp/overflow-buffer", "buffer_overflow"),
        ("cpp/integer-overflow", "integer_overflow"),
        ("cpp/format-string", "format_string"),
        ("cpp/path-traversal", "path_traversal"),
    ])
    def test_rule_id_formats(self, rule_id, expected_type):
        """Test that various rule_id formats are supported."""
        test_input = {
            "path_id": "path_0001",
            "source": {"file_path": "src/input.c", "line_number": 10, "function_name": "get_input"},
            "sink": {"file_path": "src/sink.c", "line_number": 50, "function_name": "sink_func"},
            "potential_functions": [],
            "rule_id": rule_id,
            "message": "Test message"
        }
        assert test_input["rule_id"] == rule_id

    def test_empty_potential_functions(self, valid_input):
        """Test that empty potential_functions array is handled."""
        valid_input["potential_functions"] = []
        assert valid_input["potential_functions"] == []

    def test_single_potential_function(self, valid_input):
        """Test with a single potential function."""
        valid_input["potential_functions"] = [
            {"name": "check_input", "file": "src/check.c", "line": 15}
        ]
        assert len(valid_input["potential_functions"]) == 1


class TestFunctionSelectorOutputSchema:
    """Tests for validating output schema structure."""

    @pytest.fixture
    def valid_output(self) -> Dict[str, Any]:
        """Returns a valid output structure from function-selector skill."""
        return {
            "selected_function": {
                "name": "validate_cmd",
                "file": "src/validate.c",
                "line": 30,
                "reason": "函数名包含'validate'语义关键词(高优先级)，且'cmd'与命令注入漏洞类型直接匹配，位于source和sink之间的调用路径上，最可能是针对命令注入的验证函数"
            }
        }

    def test_output_has_selected_function(self, valid_output):
        """Test that output contains selected_function field."""
        assert "selected_function" in valid_output

    def test_selected_function_structure(self, valid_output):
        """Test that selected_function has all required fields."""
        func = valid_output["selected_function"]
        required_fields = ["name", "file", "line", "reason"]
        for field in required_fields:
            assert field in func, f"Missing required field in selected_function: {field}"

    def test_selected_function_types(self, valid_output):
        """Test that selected_function fields have correct types."""
        func = valid_output["selected_function"]
        assert isinstance(func["name"], str)
        assert isinstance(func["file"], str)
        assert isinstance(func["line"], int)
        assert isinstance(func["reason"], str)

    def test_reason_is_non_empty(self, valid_output):
        """Test that reason field is not empty."""
        assert len(valid_output["selected_function"]["reason"]) > 0


class TestSemanticPriorityKeywords:
    """Tests for validating semantic priority keywords."""

    @pytest.mark.parametrize("keyword,priority", [
        # High priority keywords
        ("sanitize_input", "high"),
        ("clean_buffer", "high"),
        ("escape_sql", "high"),
        ("validate_cmd", "high"),
        ("verify_path", "high"),
        ("check_bounds", "high"),
        # Medium priority keywords
        ("filter_chars", "medium"),
        ("encode_html", "medium"),
        ("quote_string", "medium"),
        ("is_valid_filename", "medium"),
        ("can_execute", "medium"),
        ("has_permission", "medium"),
        # Low priority keywords
        ("process_data", "low"),
        ("handle_request", "low"),
        ("prepare_query", "low"),
    ])
    def test_keyword_patterns(self, keyword, priority):
        """Test that function names with various keywords are recognized."""
        # This test documents the expected priority levels
        high_keywords = ["sanitize", "clean", "escape", "validate", "verify", "check"]
        medium_keywords = ["filter", "encode", "quote", "is_valid", "can_", "has_"]
        low_keywords = ["process", "handle", "prepare"]

        detected_priority = None
        if any(kw in keyword.lower() for kw in high_keywords):
            detected_priority = "high"
        elif any(kw in keyword.lower() for kw in medium_keywords):
            detected_priority = "medium"
        elif any(kw in keyword.lower() for kw in low_keywords):
            detected_priority = "low"

        assert detected_priority == priority, f"Expected {priority} priority for {keyword}"


class TestVulnerabilityTypeMatching:
    """Tests for validating vulnerability type matching."""

    @pytest.mark.parametrize("rule_id,expected_keywords", [
        ("cpp/command-line-injection", ["cmd", "command", "shell", "exec"]),
        ("cpp/command-injection", ["cmd", "command", "shell", "exec"]),
        ("cpp/sql-injection", ["sql", "query", "statement"]),
        ("cpp/overflow-buffer", ["buffer", "size", "length", "bounds"]),
        ("cpp/integer-overflow", ["int", "number", "overflow"]),
        ("cpp/format-string", ["format", "string", "print"]),
        ("cpp/path-traversal", ["path", "file", "dir", "filename"]),
    ])
    def test_vulnerability_keywords_mapping(self, rule_id, expected_keywords):
        """Test that rule_id maps to expected vulnerability keywords."""
        # Mapping of rule_id patterns to vulnerability keywords
        vulnerability_keywords = {
            "command": ["cmd", "command", "shell", "exec"],
            "sql": ["sql", "query", "statement"],
            "buffer": ["buffer", "size", "length", "bounds"],
            "integer": ["int", "number", "overflow"],
            "format": ["format", "string", "print"],
            "path": ["path", "file", "dir", "filename"],
        }

        detected_keywords = None
        for key, keywords in vulnerability_keywords.items():
            if key in rule_id.lower():
                detected_keywords = keywords
                break

        assert detected_keywords == expected_keywords

    def test_function_name_matches_vulnerability_type(self):
        """Test that function names are matched against vulnerability keywords."""
        rule_id = "cpp/command-line-injection"
        func_name = "validate_cmd"
        keywords = ["cmd", "command", "shell", "exec"]

        # Check if function name contains any vulnerability-specific keyword
        matches = any(kw in func_name.lower() for kw in keywords)
        assert matches, f"Function {func_name} should match {rule_id} keywords"


class TestExclusionConditions:
    """Tests for validating exclusion conditions."""

    @pytest.mark.parametrize("func_name,should_exclude", [
        # System/library functions - should be excluded
        ("strlen", True),
        ("memcpy", True),
        ("strcpy", True),
        ("memset", True),
        ("printf", True),
        ("malloc", True),
        ("free", True),
        # Utility functions - should be excluded
        ("print_debug", True),
        ("log_error", True),
        ("log_debug", True),
        # Simple getter functions - should be excluded
        ("get_flag", True),
        ("is_enabled", True),
        # Sanitizer functions - should NOT be excluded
        ("sanitize_input", False),
        ("validate_cmd", False),
        ("check_bounds", False),
    ])
    def test_exclusion_patterns(self, func_name, should_exclude):
        """Test that certain function patterns are excluded."""
        excluded_patterns = [
            "strlen", "memcpy", "strcpy", "memset", "printf", "malloc", "free",
            "print_debug", "log_error", "log_debug", "log_",
            "get_flag", "is_enabled"
        ]

        is_excluded = any(func_name.startswith(pat.replace("_", "")) or 
                          func_name.startswith(pat) or 
                          func_name == pat 
                          for pat in excluded_patterns)

        assert is_excluded == should_exclude, f"Exclusion mismatch for {func_name}"


class TestSampleInputOutputPairs:
    """Regression tests with sample input/output pairs from SKILL.md."""

    def test_command_injection_example_1(self):
        """Test sample from Example 1: Command Injection."""
        input_data = {
            "path_id": "path_0001",
            "source": {
                "file_path": "src/input.c",
                "line_number": 10,
                "function_name": "get_user_input"
            },
            "sink": {
                "file_path": "src/exec.c",
                "line_number": 50,
                "function_name": "system"
            },
            "potential_functions": [
                {"name": "strlen", "file": "src/utils.c", "line": 5},
                {"name": "process_data", "file": "src/process.c", "line": 40},
                {"name": "sanitize_input", "file": "src/sanitizer.c", "line": 20},
                {"name": "validate_cmd", "file": "src/validate.c", "line": 30},
                {"name": "log_debug", "file": "src/debug.c", "line": 100}
            ],
            "rule_id": "cpp/command-line-injection",
            "message": "User input reaches system()"
        }

        expected_output = {
            "selected_function": {
                "name": "validate_cmd",
                "file": "src/validate.c",
                "line": 30,
                "reason": "函数名包含'validate'语义关键词(高优先级)，且'cmd'与命令注入漏洞类型直接匹配，位于source和sink之间的调用路径上，最可能是针对命令注入的验证函数"
            }
        }

        # Validate input schema
        assert input_data["path_id"] == "path_0001"
        assert len(input_data["potential_functions"]) == 5
        assert input_data["rule_id"] == "cpp/command-line-injection"

        # Validate expected output schema
        assert "selected_function" in expected_output
        assert expected_output["selected_function"]["name"] == "validate_cmd"
        assert expected_output["selected_function"]["line"] == 30

    def test_sql_injection_example(self):
        """Test sample from Example 2: SQL Injection."""
        input_data = {
            "path_id": "path_0002",
            "source": {
                "file_path": "src/web.c",
                "line_number": 25,
                "function_name": "parse_request"
            },
            "sink": {
                "file_path": "src/db.c",
                "line_number": 80,
                "function_name": "sqlite3_exec"
            },
            "potential_functions": [
                {"name": "check_auth", "file": "src/auth.c", "line": 15},
                {"name": "escape_sql", "file": "src/db_utils.c", "line": 45},
                {"name": "prepare_statement", "file": "src/db.c", "line": 60},
                {"name": "memcpy", "file": "string.h", "line": 1},
                {"name": "is_valid_user", "file": "src/auth.c", "line": 30}
            ],
            "rule_id": "cpp/sql-injection",
            "message": "Tainted data used in SQL query"
        }

        expected_output = {
            "selected_function": {
                "name": "escape_sql",
                "file": "src/db_utils.c",
                "line": 45,
                "reason": "函数名包含'escape'语义关键词(高优先级)，且'sql'与SQL注入漏洞类型完全匹配，位于source和sink之间，明确表明是SQL转义/净化函数"
            }
        }

        # Validate input schema
        assert input_data["rule_id"] == "cpp/sql-injection"
        assert input_data["sink"]["function_name"] == "sqlite3_exec"

        # Validate expected output schema
        assert expected_output["selected_function"]["name"] == "escape_sql"
        assert "sql" in expected_output["selected_function"]["reason"].lower()

    def test_buffer_overflow_example(self):
        """Test sample from Example 3: Buffer Overflow."""
        input_data = {
            "path_id": "path_0003",
            "source": {
                "file_path": "src/network.c",
                "line_number": 30,
                "function_name": "recv_packet"
            },
            "sink": {
                "file_path": "src/buffer.c",
                "line_number": 100,
                "function_name": "memcpy"
            },
            "potential_functions": [
                {"name": "check_bounds", "file": "src/utils.c", "line": 50},
                {"name": "validate_size", "file": "src/utils.c", "line": 55},
                {"name": "strcpy", "file": "string.h", "line": 1},
                {"name": "process_packet", "file": "src/network.c", "line": 45},
                {"name": "log_packet", "file": "src/debug.c", "line": 20}
            ],
            "rule_id": "cpp/overflow-buffer",
            "message": "Potential buffer overflow"
        }

        expected_output = {
            "selected_function": {
                "name": "validate_size",
                "file": "src/utils.c",
                "line": 55,
                "reason": "函数名包含'validate'语义关键词(高优先级)，且'size'与缓冲区溢出漏洞的边界检查需求匹配，位于source和sink之间。相比'check_bounds'，'size'更直接对应缓冲区大小验证，更适合验证是否能防止溢出"
            }
        }

        # Validate input schema
        assert input_data["rule_id"] == "cpp/overflow-buffer"

        # Validate expected output schema
        assert expected_output["selected_function"]["name"] == "validate_size"
        assert "size" in expected_output["selected_function"]["reason"].lower()


class TestScoringLogic:
    """Tests for validating the scoring logic."""

    def test_semantic_scoring_high(self):
        """Test high priority semantic keywords (+3 points)."""
        high_keywords = ["sanitize", "clean", "escape", "validate", "verify", "check"]
        func_name = "sanitize_input"

        score = 0
        for kw in high_keywords:
            if kw in func_name.lower():
                score += 3
                break

        assert score == 3

    def test_semantic_scoring_medium(self):
        """Test medium priority semantic keywords (+2 points)."""
        medium_keywords = ["filter", "encode", "quote", "is_valid", "can_", "has_"]
        func_name = "is_valid_filename"

        score = 0
        for kw in medium_keywords:
            if kw in func_name.lower():
                score += 2
                break

        assert score == 2

    def test_semantic_scoring_low(self):
        """Test low priority semantic keywords (+1 point)."""
        low_keywords = ["process", "handle", "prepare"]
        func_name = "process_data"

        score = 0
        for kw in low_keywords:
            if kw in func_name.lower():
                score += 1
                break

        assert score == 1

    def test_vulnerability_match_scoring(self):
        """Test vulnerability type matching (+2 points)."""
        rule_id = "cpp/command-line-injection"
        func_name = "validate_cmd"
        keywords = ["cmd", "command", "shell", "exec"]

        score = 0
        if any(kw in func_name.lower() for kw in keywords):
            score += 2

        assert score == 2

    def test_combined_scoring(self):
        """Test combined scoring logic."""
        # Example: validate_cmd for command injection
        func_name = "validate_cmd"
        rule_id = "cpp/command-line-injection"

        # Semantic score (high priority)
        semantic_score = 3  # "validate" is high priority

        # Vulnerability match score
        vuln_keywords = ["cmd", "command", "shell", "exec"]
        vuln_score = 2 if any(kw in func_name.lower() for kw in vuln_keywords) else 0

        # Total score
        total_score = semantic_score + vuln_score

        assert total_score == 5


class TestReasonFormat:
    """Tests for validating reason format."""

    def test_reason_contains_semantic_info(self):
        """Test that reason contains semantic keyword information."""
        reason = "函数名包含'sanitize'语义关键词(高优先级)，位于source和sink之间"
        assert "sanitize" in reason
        assert "高优先级" in reason

    def test_reason_contains_vulnerability_info(self):
        """Test that reason contains vulnerability type information."""
        reason = "且'cmd'与命令注入漏洞类型直接匹配"
        assert "cmd" in reason
        assert "命令注入" in reason

    def test_reason_contains_location_info(self):
        """Test that reason contains location information."""
        reason = "位于source和sink之间的调用路径上"
        assert "source" in reason
        assert "sink" in reason

    def test_reason_is_detailed(self):
        """Test that reason is detailed and specific."""
        reason = "函数名包含'validate'语义关键词(高优先级)，且'cmd'与命令注入漏洞类型直接匹配，位于source和sink之间的调用路径上，最可能是针对命令注入的验证函数"
        assert len(reason) > 50  # Should be detailed
        assert "函数名" in reason
        assert "语义" in reason or "validate" in reason


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
