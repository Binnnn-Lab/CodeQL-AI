"""
Test cases for Step 2: find_potential_functions MCP tool.

This module tests the find_potential_functions function from
src/mcptools/function_level_sanitizer.py which runs CodeQL analysis
to find functions on taint data flow paths.

Note: These tests mock the run_taint_analysis function since they should
not require an actual CodeQL database or installation.
"""
import os
import sys
import json
import pytest
import asyncio
from pathlib import Path
from unittest.mock import patch, AsyncMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../src'))

from mcptools.function_level_sanitizer import find_potential_functions


class TestFindPotentialFunctionsSuccess:
    """Tests for successful function finding scenarios."""
    
    @pytest.mark.asyncio
    async def test_find_potential_functions_with_valid_taint_json(self):
        """
        Test successful execution with valid taint_json structure.
        
        Expected: Returns success=True with list of potential functions.
        """
        taint_json = {
            "source": {
                "source_file_path": "src/input.c",
                "source_start_line": 20,
                "source_target_name": "get_user_input"
            },
            "sink": {
                "sink_file_path": "src/vuln.c",
                "sink_start_line": 50,
                "sink_target_name": "memcpy"
            }
        }
        
        mock_result = {
            "success": True,
            "potential_sanitizer_functions": ["validate_input", "check_bounds"],
            "sarif_path": "/tmp/result.sarif",
            "tmp_ql_path": "/tmp/query.ql",
            "command": "codeql database analyze",
            "message": "CodeQL 污点分析完成"
        }
        
        with patch('mcptools.function_level_sanitizer.run_taint_analysis', 
                   new_callable=AsyncMock, return_value=mock_result):
            result = await find_potential_functions(taint_json, "/path/to/db")
        
        assert result["success"] is True
        assert "potential_sanitizer_functions" in result
        assert isinstance(result["potential_sanitizer_functions"], list)
    
    @pytest.mark.asyncio
    async def test_taint_json_format_preserved(self):
        """
        Test that taint_json format is preserved when passed to run_taint_analysis.
        
        Expected: The mock receives the exact taint_json structure.
        """
        taint_json = {
            "source": {
                "source_file_path": "src/main.c",
                "source_start_line": 10,
                "source_target_name": "fgets"
            },
            "sink": {
                "sink_file_path": "src/buffer.c",
                "sink_start_line": 75,
                "sink_target_name": "strcpy"
            }
        }
        
        mock_run_taint = AsyncMock(return_value={
            "success": True,
            "potential_sanitizer_functions": []
        })
        
        with patch('mcptools.function_level_sanitizer.run_taint_analysis', 
                   mock_run_taint):
            await find_potential_functions(taint_json, "/path/to/db")
        
        mock_run_taint.assert_called_once()
        call_args = mock_run_taint.call_args
        assert call_args[0][0] == taint_json
        assert call_args[0][1] == "/path/to/db"
    
    @pytest.mark.asyncio
    async def test_returns_list_of_functions(self):
        """
        Test that result contains a list of function names.
        
        Expected: potential_sanitizer_functions is a list of strings.
        """
        taint_json = {"source": {}, "sink": {}}
        
        mock_result = {
            "success": True,
            "potential_sanitizer_functions": [
                "sanitize_input",
                "validate_buffer",
                "check_permission",
                "filter_data"
            ]
        }
        
        with patch('mcptools.function_level_sanitizer.run_taint_analysis',
                   new_callable=AsyncMock, return_value=mock_result):
            result = await find_potential_functions(taint_json, "/db")
        
        assert isinstance(result["potential_sanitizer_functions"], list)
        assert len(result["potential_sanitizer_functions"]) == 4
        for func_name in result["potential_sanitizer_functions"]:
            assert isinstance(func_name, str)
            assert len(func_name) > 0
    
    @pytest.mark.asyncio
    async def test_no_duplicate_functions(self):
        """
        Test that duplicate function names are not returned.
        
        Expected: Each function name appears only once.
        """
        taint_json = {"source": {}, "sink": {}}
        
        mock_result = {
            "success": True,
            "potential_sanitizer_functions": [
                "validate_input",
                "check_bounds",
                "validate_input"  # Duplicate
            ]
        }
        
        with patch('mcptools.function_level_sanitizer.run_taint_analysis',
                   new_callable=AsyncMock, return_value=mock_result):
            result = await find_potential_functions(taint_json, "/db")
        
        funcs = result["potential_sanitizer_functions"]
        assert len(funcs) == len(set(funcs))
    
    @pytest.mark.asyncio
    async def test_empty_functions_list(self):
        """
        Test handling when no potential functions are found.
        
        Expected: Returns success=True with empty list.
        """
        taint_json = {"source": {}, "sink": {}}
        
        mock_result = {
            "success": True,
            "potential_sanitizer_functions": [],
            "message": "No functions found"
        }
        
        with patch('mcptools.function_level_sanitizer.run_taint_analysis',
                   new_callable=AsyncMock, return_value=mock_result):
            result = await find_potential_functions(taint_json, "/db")
        
        assert result["success"] is True
        assert result["potential_sanitizer_functions"] == []


class TestFindPotentialFunctionsErrorHandling:
    """Tests for error handling scenarios."""
    
    @pytest.mark.asyncio
    async def test_database_not_found_error(self):
        """
        Test handling when CodeQL database does not exist.
        
        Expected: Returns success=False with appropriate error.
        """
        taint_json = {"source": {}, "sink": {}}
        
        mock_result = {
            "success": False,
            "error": "CodeQL 数据库不存在: /invalid/db"
        }
        
        with patch('mcptools.function_level_sanitizer.run_taint_analysis',
                   new_callable=AsyncMock, return_value=mock_result):
            result = await find_potential_functions(taint_json, "/invalid/db")
        
        assert result["success"] is False
        assert "error" in result
        assert "数据库不存在" in result["error"] or "not found" in result["error"].lower()
    
    @pytest.mark.asyncio
    async def test_ql_template_not_found_error(self):
        """
        Test handling when QL template file is missing.
        
        Expected: Returns success=False with error about missing template.
        """
        taint_json = {"source": {}, "sink": {}}
        
        mock_result = {
            "success": False,
            "error": "QL 模板文件不存在"
        }
        
        with patch('mcptools.function_level_sanitizer.run_taint_analysis',
                   new_callable=AsyncMock, return_value=mock_result):
            result = await find_potential_functions(taint_json, "/db")
        
        assert result["success"] is False
        assert "error" in result
    
    @pytest.mark.asyncio
    async def test_codeql_analysis_failure(self):
        """
        Test handling when CodeQL analysis command fails.
        
        Expected: Returns success=False with command output.
        """
        taint_json = {"source": {}, "sink": {}}
        
        mock_result = {
            "success": False,
            "error": "CodeQL 分析失败",
            "command": "codeql database analyze --rerun /db /query.ql",
            "stderr": "Compilation failed"
        }
        
        with patch('mcptools.function_level_sanitizer.run_taint_analysis',
                   new_callable=AsyncMock, return_value=mock_result):
            result = await find_potential_functions(taint_json, "/db")
        
        assert result["success"] is False
        assert "error" in result
    
    @pytest.mark.asyncio
    async def test_sarif_parsing_failure(self):
        """
        Test handling when SARIF output parsing fails.
        
        Expected: Returns success=False with parsing error.
        """
        taint_json = {"source": {}, "sink": {}}
        
        mock_result = {
            "success": False,
            "error": "解析 SARIF 文件失败: Invalid JSON"
        }
        
        with patch('mcptools.function_level_sanitizer.run_taint_analysis',
                   new_callable=AsyncMock, return_value=mock_result):
            result = await find_potential_functions(taint_json, "/db")
        
        assert result["success"] is False
        assert "解析" in result["error"] or "parse" in result["error"].lower()


class TestFindPotentialFunctionsInputValidation:
    """Tests for input validation."""
    
    @pytest.mark.asyncio
    async def test_missing_source_in_taint_json(self):
        """
        Test handling of taint_json without source field.
        
        Expected: Should still call run_taint_analysis (validation is in lib).
        """
        taint_json = {
            "sink": {
                "sink_file_path": "src/vuln.c",
                "sink_start_line": 50,
                "sink_target_name": "memcpy"
            }
        }
        
        mock_run_taint = AsyncMock(return_value={
            "success": False,
            "error": "Missing source"
        })
        
        with patch('mcptools.function_level_sanitizer.run_taint_analysis',
                   mock_run_taint):
            result = await find_potential_functions(taint_json, "/db")
        
        mock_run_taint.assert_called_once()
        assert result["success"] is False
    
    @pytest.mark.asyncio
    async def test_missing_sink_in_taint_json(self):
        """
        Test handling of taint_json without sink field.
        
        Expected: Should still call run_taint_analysis.
        """
        taint_json = {
            "source": {
                "source_file_path": "src/input.c",
                "source_start_line": 20,
                "source_target_name": "get_user_input"
            }
        }
        
        mock_run_taint = AsyncMock(return_value={
            "success": False,
            "error": "Missing sink"
        })
        
        with patch('mcptools.function_level_sanitizer.run_taint_analysis',
                   mock_run_taint):
            result = await find_potential_functions(taint_json, "/db")
        
        mock_run_taint.assert_called_once()
        assert result["success"] is False
    
    @pytest.mark.asyncio
    async def test_empty_taint_json(self):
        """
        Test handling of empty taint_json.
        
        Expected: Should call run_taint_analysis with empty dict.
        """
        taint_json = {}
        
        mock_run_taint = AsyncMock(return_value={
            "success": False,
            "error": "Invalid taint configuration"
        })
        
        with patch('mcptools.function_level_sanitizer.run_taint_analysis',
                   mock_run_taint):
            result = await find_potential_functions(taint_json, "/db")
        
        mock_run_taint.assert_called_once_with(taint_json, "/db")


class TestFindPotentialFunctionsOutputFormat:
    """Tests for verifying output format."""
    
    @pytest.mark.asyncio
    async def test_success_output_structure(self):
        """
        Test that successful output has expected structure.
        
        Expected: Contains success, potential_sanitizer_functions, and optional fields.
        """
        taint_json = {"source": {}, "sink": {}}
        
        mock_result = {
            "success": True,
            "potential_sanitizer_functions": ["func1", "func2"],
            "sarif_path": "/tmp/result.sarif",
            "tmp_ql_path": "/tmp/query.ql",
            "command": "codeql analyze",
            "message": "Success"
        }
        
        with patch('mcptools.function_level_sanitizer.run_taint_analysis',
                   new_callable=AsyncMock, return_value=mock_result):
            result = await find_potential_functions(taint_json, "/db")
        
        assert isinstance(result, dict)
        assert "success" in result
        assert isinstance(result["success"], bool)
        assert "potential_sanitizer_functions" in result
        assert isinstance(result["potential_sanitizer_functions"], list)
    
    @pytest.mark.asyncio
    async def test_error_output_structure(self):
        """
        Test that error output has expected structure.
        
        Expected: Contains success=False and error field.
        """
        taint_json = {"source": {}, "sink": {}}
        
        mock_result = {
            "success": False,
            "error": "Analysis failed",
            "command": "codeql analyze"
        }
        
        with patch('mcptools.function_level_sanitizer.run_taint_analysis',
                   new_callable=AsyncMock, return_value=mock_result):
            result = await find_potential_functions(taint_json, "/db")
        
        assert isinstance(result, dict)
        assert result["success"] is False
        assert "error" in result
        assert isinstance(result["error"], str)
    
    @pytest.mark.asyncio
    async def test_function_names_are_valid_identifiers(self):
        """
        Test that returned function names are valid C/C++ identifiers.
        
        Expected: Function names follow identifier pattern.
        """
        taint_json = {"source": {}, "sink": {}}
        
        import re
        valid_identifier_pattern = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*$')
        
        mock_result = {
            "success": True,
            "potential_sanitizer_functions": [
                "validate_input",
                "checkBounds",
                "_sanitize_data",
                "Func123"
            ]
        }
        
        with patch('mcptools.function_level_sanitizer.run_taint_analysis',
                   new_callable=AsyncMock, return_value=mock_result):
            result = await find_potential_functions(taint_json, "/db")
        
        for func_name in result["potential_sanitizer_functions"]:
            assert valid_identifier_pattern.match(func_name), \
                f"{func_name} is not a valid identifier"


class TestFindPotentialFunctionsAsyncBehavior:
    """Tests for async function behavior."""
    
    @pytest.mark.asyncio
    async def test_function_is_async(self):
        """
        Test that find_potential_functions is an async function.
        
        Expected: Function can be awaited.
        """
        import inspect
        assert inspect.iscoroutinefunction(find_potential_functions)
    
    @pytest.mark.asyncio
    async def test_awaits_run_taint_analysis(self):
        """
        Test that the function properly awaits run_taint_analysis.
        
        Expected: run_taint_analysis is called with await.
        """
        taint_json = {"source": {}, "sink": {}}
        
        mock_run_taint = AsyncMock(return_value={
            "success": True,
            "potential_sanitizer_functions": []
        })
        
        with patch('mcptools.function_level_sanitizer.run_taint_analysis',
                   mock_run_taint):
            await find_potential_functions(taint_json, "/db")
        
        assert mock_run_taint.awaited
    
    @pytest.mark.asyncio
    async def test_propagates_result_directly(self):
        """
        Test that the function returns the result from run_taint_analysis.
        
        Expected: Result is passed through without modification.
        """
        taint_json = {"source": {}, "sink": {}}
        
        expected_result = {
            "success": True,
            "potential_sanitizer_functions": ["func1"],
            "custom_field": "custom_value"
        }
        
        with patch('mcptools.function_level_sanitizer.run_taint_analysis',
                   new_callable=AsyncMock, return_value=expected_result):
            result = await find_potential_functions(taint_json, "/db")
        
        assert result == expected_result
        assert result["custom_field"] == "custom_value"
