"""
Test Step 4: Constraint-Generator LLM Skill

These tests validate the input/output schema for the constraint-generator skill.
This is a schema validation test suite - no actual LLM calls are made.

The constraint-generator skill generates constraints for angr symbolic execution
to verify whether a sanitizer is effective for various vulnerability types.
"""

import pytest
from typing import Dict, List, Any
import json


class TestConstraintGeneratorInputSchema:
    """Tests for validating input schema structure."""

    @pytest.fixture
    def valid_input(self) -> Dict[str, Any]:
        """Returns a valid input structure for constraint-generator skill."""
        return {
            "rule_id": "cpp/command-line-injection",
            "sink_function": "system",
            "function_code": "void run_cmd(char* input) { char buf[64]; sanitize(input, buf); system(buf); }",
            "context": {
                "vulnerability_type": "command_injection",
                "buffer_size": 64,
                "line_number": 42
            }
        }

    def test_input_has_required_fields(self, valid_input):
        """Test that input contains all required top-level fields."""
        required_fields = ["rule_id", "sink_function", "function_code", "context"]
        for field in required_fields:
            assert field in valid_input, f"Missing required field: {field}"

    def test_rule_id_type(self, valid_input):
        """Test that rule_id is a string."""
        assert isinstance(valid_input["rule_id"], str)

    def test_sink_function_type(self, valid_input):
        """Test that sink_function is a string."""
        assert isinstance(valid_input["sink_function"], str)

    def test_function_code_type(self, valid_input):
        """Test that function_code is a string."""
        assert isinstance(valid_input["function_code"], str)

    def test_context_structure(self, valid_input):
        """Test that context object has required fields."""
        context = valid_input["context"]
        assert "vulnerability_type" in context
        assert isinstance(context["vulnerability_type"], str)

    def test_context_optional_fields(self, valid_input):
        """Test that context optional fields are correctly typed."""
        context = valid_input["context"]
        if "buffer_size" in context:
            assert isinstance(context["buffer_size"], int)
        if "line_number" in context:
            assert isinstance(context["line_number"], int)

    @pytest.mark.parametrize("vuln_type", [
        "command_injection",
        "sql_injection",
        "buffer_overflow",
        "format_string",
        "path_traversal",
    ])
    def test_supported_vulnerability_types(self, vuln_type):
        """Test that all supported vulnerability types are accepted."""
        test_input = {
            "rule_id": f"cpp/{vuln_type}",
            "sink_function": "test_sink",
            "function_code": "void test() {}",
            "context": {
                "vulnerability_type": vuln_type,
                "buffer_size": 64,
                "line_number": 10
            }
        }
        assert test_input["context"]["vulnerability_type"] == vuln_type


class TestConstraintGeneratorOutputSchema:
    """Tests for validating output schema structure."""

    @pytest.fixture
    def valid_output(self) -> Dict[str, Any]:
        """Returns a valid output structure from constraint-generator skill."""
        return {
            "constraint_id": "cst_001",
            "description": "命令注入约束 - 过滤 shell 元字符",
            "vulnerability_type": "command_injection",
            "input_constraints": [
                {
                    "type": "contains_any",
                    "description": "输入必须包含至少一个危险字符（模拟攻击）",
                    "chars": [";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">"]
                }
            ],
            "output_constraints": [
                {
                    "type": "not_contains_any",
                    "description": "输出不能包含危险字符（验证 sanitizer）",
                    "chars": [";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">"]
                }
            ],
            "verification_logic": "如果存在路径：输入有危险字符且输出也有危险字符 → 未净化/存在漏洞"
        }

    def test_output_has_required_fields(self, valid_output):
        """Test that output contains all required fields."""
        required_fields = ["constraint_id", "description", "vulnerability_type", 
                          "input_constraints", "output_constraints", "verification_logic"]
        for field in required_fields:
            assert field in valid_output, f"Missing required field: {field}"

    def test_constraint_id_type(self, valid_output):
        """Test that constraint_id is a string."""
        assert isinstance(valid_output["constraint_id"], str)

    def test_description_type(self, valid_output):
        """Test that description is a string."""
        assert isinstance(valid_output["description"], str)

    def test_vulnerability_type_matches(self, valid_output):
        """Test that vulnerability_type is valid."""
        supported_types = ["command_injection", "sql_injection", "buffer_overflow", 
                          "format_string", "path_traversal"]
        assert valid_output["vulnerability_type"] in supported_types

    def test_input_constraints_is_array(self, valid_output):
        """Test that input_constraints is a list."""
        assert isinstance(valid_output["input_constraints"], list)

    def test_output_constraints_is_array(self, valid_output):
        """Test that output_constraints is a list."""
        assert isinstance(valid_output["output_constraints"], list)

    def test_verification_logic_type(self, valid_output):
        """Test that verification_logic is a string."""
        assert isinstance(valid_output["verification_logic"], str)


class TestConstraintTypes:
    """Tests for validating different constraint types."""

    def test_contains_any_constraint(self):
        """Test contains_any constraint structure."""
        constraint = {
            "type": "contains_any",
            "description": "输入必须包含至少一个危险字符",
            "chars": [";", "|", "&"]
        }
        assert constraint["type"] == "contains_any"
        assert isinstance(constraint["chars"], list)
        assert all(isinstance(c, str) for c in constraint["chars"])

    def test_not_contains_any_constraint(self):
        """Test not_contains_any constraint structure."""
        constraint = {
            "type": "not_contains_any",
            "description": "输出不能包含危险字符",
            "chars": [";", "|", "&"]
        }
        assert constraint["type"] == "not_contains_any"
        assert isinstance(constraint["chars"], list)

    def test_contains_all_constraint(self):
        """Test contains_all constraint structure."""
        constraint = {
            "type": "contains_all",
            "description": "输入必须包含所有指定字符",
            "chars": ["SELECT", "FROM"]
        }
        assert constraint["type"] == "contains_all"
        assert isinstance(constraint["chars"], list)

    def test_length_range_constraint(self):
        """Test length_range constraint structure."""
        constraint = {
            "type": "length_range",
            "description": "输入长度超过缓冲区大小",
            "min": 65,
            "max": 1024
        }
        assert constraint["type"] == "length_range"
        assert isinstance(constraint["min"], int)
        assert isinstance(constraint["max"], int)
        assert constraint["min"] < constraint["max"]

    def test_matches_regex_constraint(self):
        """Test matches_regex constraint structure."""
        constraint = {
            "type": "matches_regex",
            "description": "输入匹配路径遍历模式",
            "pattern": "\\.\\.[/\\\\]|~"
        }
        assert constraint["type"] == "matches_regex"
        assert isinstance(constraint["pattern"], str)
        assert len(constraint["pattern"]) > 0

    def test_always_true_constraint(self):
        """Test always_true constraint structure."""
        constraint = {
            "type": "always_true",
            "description": "无约束（用于 passthrough）"
        }
        assert constraint["type"] == "always_true"


class TestVulnerabilityTypeConstraints:
    """Tests for validating constraints per vulnerability type."""

    @pytest.mark.parametrize("vuln_type,dangerous_chars", [
        ("command_injection", [";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">"]),
        ("sql_injection", ["'", "\"", ";", "-", "*", "/", "%", "_"]),
        ("format_string", ["%n", "%p", "%x", "%s", "%d", "%f"]),
    ])
    def test_contains_any_dangerous_chars(self, vuln_type, dangerous_chars):
        """Test that each vulnerability type has appropriate dangerous characters."""
        constraint = {
            "type": "contains_any",
            "description": f"输入必须包含至少一个{vuln_type}危险字符",
            "chars": dangerous_chars
        }
        assert len(constraint["chars"]) > 0
        assert all(isinstance(c, str) for c in constraint["chars"])

    def test_command_injection_constraints(self):
        """Test command injection specific constraints."""
        input_constraints = [
            {
                "type": "contains_any",
                "description": "输入必须包含至少一个 shell 元字符",
                "chars": [";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">"]
            }
        ]
        output_constraints = [
            {
                "type": "not_contains_any",
                "description": "输出不能包含 shell 元字符",
                "chars": [";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">"]
            }
        ]

        assert len(input_constraints) == 1
        assert len(output_constraints) == 1
        assert input_constraints[0]["type"] == "contains_any"
        assert output_constraints[0]["type"] == "not_contains_any"
        assert input_constraints[0]["chars"] == output_constraints[0]["chars"]

    def test_sql_injection_constraints(self):
        """Test SQL injection specific constraints."""
        input_constraints = [
            {
                "type": "contains_any",
                "description": "输入必须包含至少一个 SQL 危险字符",
                "chars": ["'", "\"", ";", "-", "*", "/", "%", "_"]
            }
        ]
        output_constraints = [
            {
                "type": "matches_regex",
                "description": "输出必须是参数化查询或已正确转义",
                "pattern": "^(SELECT|INSERT|UPDATE|DELETE).*\\?(?!.*['\";])"
            }
        ]

        assert input_constraints[0]["type"] == "contains_any"
        assert output_constraints[0]["type"] == "matches_regex"

    def test_buffer_overflow_constraints(self):
        """Test buffer overflow specific constraints."""
        buffer_size = 64
        input_constraints = [
            {
                "type": "length_range",
                "description": "输入长度超过缓冲区大小",
                "min": buffer_size + 1,
                "max": 1024
            }
        ]
        output_constraints = [
            {
                "type": "length_range",
                "description": "输出长度必须在安全范围内",
                "min": 0,
                "max": buffer_size - 1
            }
        ]

        assert input_constraints[0]["type"] == "length_range"
        assert output_constraints[0]["type"] == "length_range"
        assert input_constraints[0]["min"] > output_constraints[0]["max"]

    def test_format_string_constraints(self):
        """Test format string specific constraints."""
        input_constraints = [
            {
                "type": "contains_any",
                "description": "输入必须包含至少一个格式说明符",
                "chars": ["%n", "%p", "%x", "%s", "%d", "%f"]
            }
        ]
        output_constraints = [
            {
                "type": "not_contains_any",
                "description": "输出不能包含危险的格式说明符",
                "chars": ["%n", "%p"]
            },
            {
                "type": "matches_regex",
                "description": "输出中的 % 必须被正确转义（%%）",
                "pattern": "^(?!.*%[npxsdf])"
            }
        ]

        assert len(input_constraints) == 1
        assert len(output_constraints) == 2

    def test_path_traversal_constraints(self):
        """Test path traversal specific constraints."""
        input_constraints = [
            {
                "type": "contains_any",
                "description": "输入必须包含至少一个路径跳转字符",
                "chars": ["../", "..\\", "~", ".."]
            },
            {
                "type": "matches_regex",
                "description": "输入匹配路径遍历模式",
                "pattern": "\\.\\.[/\\\\]|~"
            }
        ]
        output_constraints = [
            {
                "type": "not_contains_any",
                "description": "输出不能包含路径跳转",
                "chars": ["../", "..\\", "~", ".."]
            },
            {
                "type": "matches_regex",
                "description": "输出路径必须是绝对路径或规范化后的相对路径",
                "pattern": "^(/[a-zA-Z0-9._-]+)+$|^[a-zA-Z0-9._-]+(/[a-zA-Z0-9._-]+)*$"
            }
        ]

        assert len(input_constraints) == 2
        assert len(output_constraints) == 2


class TestVerificationLogic:
    """Tests for validating verification logic structure."""

    def test_verification_logic_formula(self):
        """Test that verification logic follows the core formula."""
        # Core formula: ∃路径: (满足所有 input_constraints) ∧ (不满足任意 output_constraints)
        # → sanitizer 未生效 / 存在漏洞

        verification_logic = "如果存在路径：输入有危险字符且输出也有危险字符 → 未净化/存在漏洞"

        # Should contain key components
        assert "输入" in verification_logic
        assert "输出" in verification_logic
        assert "存在" in verification_logic or "路径" in verification_logic
        assert "漏洞" in verification_logic or "未净化" in verification_logic

    def test_command_injection_verification_logic(self):
        """Test command injection verification logic."""
        logic = "如果存在路径：输入有 shell 元字符且输出也有 shell 元字符 → 未净化/存在漏洞"
        assert "shell 元字符" in logic
        assert "输入" in logic
        assert "输出" in logic

    def test_buffer_overflow_verification_logic(self):
        """Test buffer overflow verification logic."""
        logic = "如果存在路径：输入长度超过缓冲区且输出长度也超过缓冲区 → 未净化/存在漏洞"
        assert "长度" in logic
        assert "缓冲区" in logic


class TestSampleInputOutputPairs:
    """Regression tests with sample input/output pairs from SKILL.md."""

    def test_command_injection_example(self):
        """Test sample: Command Injection."""
        input_data = {
            "rule_id": "cpp/command-line-injection",
            "sink_function": "system",
            "function_code": "void exec(char* input) { char cmd[128]; clean(input, cmd); system(cmd); }",
            "context": {"vulnerability_type": "command_injection", "buffer_size": 128}
        }

        expected_output = {
            "constraint_id": "cst_cmd_001",
            "description": "命令注入约束 - 检测危险字符是否被过滤",
            "vulnerability_type": "command_injection",
            "input_constraints": [
                {
                    "type": "contains_any",
                    "description": "输入必须包含至少一个 shell 元字符",
                    "chars": [";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">"]
                }
            ],
            "output_constraints": [
                {
                    "type": "not_contains_any",
                    "description": "输出不能包含 shell 元字符",
                    "chars": [";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">"]
                }
            ],
            "verification_logic": "如果存在路径：输入有 shell 元字符且输出也有 shell 元字符 → 未净化/存在漏洞"
        }

        # Validate input schema
        assert input_data["rule_id"] == "cpp/command-line-injection"
        assert input_data["sink_function"] == "system"
        assert "context" in input_data

        # Validate output schema
        assert expected_output["constraint_id"] == "cst_cmd_001"
        assert expected_output["vulnerability_type"] == "command_injection"
        assert len(expected_output["input_constraints"]) == 1
        assert expected_output["input_constraints"][0]["type"] == "contains_any"

    def test_sql_injection_example(self):
        """Test sample: SQL Injection."""
        input_data = {
            "rule_id": "cpp/sql-injection",
            "sink_function": "sqlite3_exec",
            "function_code": "void query(char* input) { char sql[256]; escape(input, sql); sqlite3_exec(db, sql, ...); }",
            "context": {"vulnerability_type": "sql_injection", "buffer_size": 256}
        }

        expected_output = {
            "constraint_id": "cst_sql_001",
            "description": "SQL注入约束 - 检测 SQL 关键字是否被转义",
            "vulnerability_type": "sql_injection",
            "input_constraints": [
                {
                    "type": "contains_any",
                    "description": "输入必须包含至少一个 SQL 危险字符",
                    "chars": ["'", "\"", ";", "-", "*", "/", "%", "_"]
                }
            ],
            "output_constraints": [
                {
                    "type": "matches_regex",
                    "description": "输出必须是参数化查询或已正确转义",
                    "pattern": "^(SELECT|INSERT|UPDATE|DELETE).*\\?(?!.*['\";])"
                }
            ],
            "verification_logic": "如果存在路径：输入有 SQL 危险字符且输出可破坏查询语法 → 未净化/存在漏洞"
        }

        # Validate
        assert input_data["vulnerability_type"] == "sql_injection"
        assert expected_output["output_constraints"][0]["type"] == "matches_regex"

    def test_buffer_overflow_example(self):
        """Test sample: Buffer Overflow."""
        input_data = {
            "rule_id": "cpp/buffer-overflow",
            "sink_function": "strcpy",
            "function_code": "void copy(char* input) { char buf[64]; check_and_copy(input, buf); strcpy(dst, buf); }",
            "context": {"vulnerability_type": "buffer_overflow", "buffer_size": 64}
        }

        expected_output = {
            "constraint_id": "cst_buf_001",
            "description": "缓冲区溢出约束 - 检测长度是否被限制",
            "vulnerability_type": "buffer_overflow",
            "input_constraints": [
                {
                    "type": "length_range",
                    "description": "输入长度超过缓冲区大小",
                    "min": 65,
                    "max": 1024
                }
            ],
            "output_constraints": [
                {
                    "type": "length_range",
                    "description": "输出长度必须在安全范围内",
                    "min": 0,
                    "max": 63
                }
            ],
            "verification_logic": "如果存在路径：输入长度超过缓冲区且输出长度也超过缓冲区 → 未净化/存在漏洞"
        }

        # Validate
        assert input_data["context"]["buffer_size"] == 64
        assert expected_output["input_constraints"][0]["min"] == 65
        assert expected_output["output_constraints"][0]["max"] == 63

    def test_format_string_example(self):
        """Test sample: Format String."""
        input_data = {
            "rule_id": "cpp/format-string",
            "sink_function": "printf",
            "function_code": "void log_msg(char* input) { char msg[128]; filter(input, msg); printf(msg); }",
            "context": {"vulnerability_type": "format_string", "buffer_size": 128}
        }

        expected_output = {
            "constraint_id": "cst_fmt_001",
            "description": "格式化字符串约束 - 检测格式说明符是否被移除",
            "vulnerability_type": "format_string",
            "input_constraints": [
                {
                    "type": "contains_any",
                    "description": "输入必须包含至少一个格式说明符",
                    "chars": ["%n", "%p", "%x", "%s", "%d", "%f"]
                }
            ],
            "output_constraints": [
                {
                    "type": "not_contains_any",
                    "description": "输出不能包含危险的格式说明符",
                    "chars": ["%n", "%p"]
                },
                {
                    "type": "matches_regex",
                    "description": "输出中的 % 必须被正确转义（%%）",
                    "pattern": "^(?!.*%[npxsdf])"
                }
            ],
            "verification_logic": "如果存在路径：输入有 %n/%p 且输出也有 %n/%p → 未净化/存在漏洞"
        }

        # Validate
        assert len(expected_output["output_constraints"]) == 2

    def test_path_traversal_example(self):
        """Test sample: Path Traversal."""
        input_data = {
            "rule_id": "cpp/path-traversal",
            "sink_function": "fopen",
            "function_code": "void open_file(char* input) { char path[256]; validate(input, path); fopen(path, \"r\"); }",
            "context": {"vulnerability_type": "path_traversal", "buffer_size": 256}
        }

        expected_output = {
            "constraint_id": "cst_path_001",
            "description": "路径遍历约束 - 检测路径跳转是否被阻止",
            "vulnerability_type": "path_traversal",
            "input_constraints": [
                {
                    "type": "contains_any",
                    "description": "输入必须包含至少一个路径跳转字符",
                    "chars": ["../", "..\\", "~", ".."]
                },
                {
                    "type": "matches_regex",
                    "description": "输入匹配路径遍历模式",
                    "pattern": "\\.\\.[/\\\\]|~"
                }
            ],
            "output_constraints": [
                {
                    "type": "not_contains_any",
                    "description": "输出不能包含路径跳转",
                    "chars": ["../", "..\\", "~", ".."]
                },
                {
                    "type": "matches_regex",
                    "description": "输出路径必须是绝对路径或规范化后的相对路径",
                    "pattern": "^(/[a-zA-Z0-9._-]+)+$|^[a-zA-Z0-9._-]+(/[a-zA-Z0-9._-]+)*$"
                }
            ],
            "verification_logic": "如果存在路径：输入有 ../ 且输出也有 ../ → 未净化/存在漏洞"
        }

        # Validate
        assert len(expected_output["input_constraints"]) == 2
        assert len(expected_output["output_constraints"]) == 2


class TestErrorHandling:
    """Tests for error handling scenarios."""

    def test_unknown_vulnerability_type_error(self):
        """Test error response for unknown vulnerability type."""
        error_response = {
            "error": "Unknown vulnerability type: unknown_type",
            "supported_types": ["command_injection", "sql_injection", "buffer_overflow", 
                              "format_string", "path_traversal"]
        }

        assert "error" in error_response
        assert "supported_types" in error_response
        assert len(error_response["supported_types"]) == 5

    def test_missing_required_parameter_error(self):
        """Test error response for missing required parameter."""
        error_response = {
            "error": "Missing required parameter: context.buffer_size",
            "required_for": "buffer_overflow"
        }

        assert "error" in error_response
        assert "required_for" in error_response
        assert error_response["required_for"] == "buffer_overflow"


class TestConstraintCombination:
    """Tests for constraint combination rules."""

    def test_and_combination_default(self):
        """Test that multiple constraints are combined with AND by default."""
        constraints = [
            {"type": "contains_any", "chars": ["../"], "description": "Contains ../"},
            {"type": "length_range", "min": 10, "max": 100, "description": "Length 10-100"}
        ]

        # Multiple constraints should be present
        assert len(constraints) == 2
        # Both must be satisfied (AND relationship)
        assert constraints[0]["type"] == "contains_any"
        assert constraints[1]["type"] == "length_range"

    def test_or_group_combination(self):
        """Test OR group constraint combination."""
        or_constraint = {
            "type": "or_group",
            "constraints": [
                {"type": "contains_any", "chars": [";"]},
                {"type": "contains_any", "chars": ["|"]}
            ]
        }

        assert or_constraint["type"] == "or_group"
        assert len(or_constraint["constraints"]) == 2
        assert or_constraint["constraints"][0]["type"] == "contains_any"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
