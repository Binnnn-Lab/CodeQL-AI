#!/usr/bin/env python3
"""
MCP Server: Symbolic Sanitizer Pipeline
包含所有符号执行验证相关的工具：parse_sarif, generate_harness, compile_harness, verify_sanitization
"""

import sys
import os
import json

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from fastmcp import FastMCP
from libs.symbolic_sanitizer import (
    parse_sarif_result,
    load_sarif_from_file,
    extract_taint_paths,
    generate_harness as _generate_harness,
    compile_harness as _compile_harness,
    verify_sanitization as _verify_sanitization,
)
from libs.symbolic_sanitizer.symbolic_sanitizer import SymbolicExecutor

mcp = FastMCP(
    name="symbolic_sanitizer",
    instructions="CodeQL Symbolic Sanitizer - Verify function sanitization using angr"
)

@mcp.tool()
def parse_sarif(sarif_path: str) -> dict:
    """Parse SARIF file and extract function locations."""
    try:
        sarif_data = load_sarif_from_file(sarif_path)
        locations = parse_sarif_result(sarif_data)
        return {
            "success": True,
            "count": len(locations),
            "locations": [
                {
                    "file_path": loc.file_path,
                    "line_number": loc.line_number,
                    "rule_id": loc.rule_id,
                    "message": loc.message
                }
                for loc in locations
            ]
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

@mcp.tool()
def parse_sarif_detailed(sarif_path: str) -> dict:
    """Parse SARIF file and extract complete taint paths with source/sink information."""
    if not os.path.exists(sarif_path):
        return {
            "success": False,
            "error": f"SARIF file not found: {sarif_path}"
        }

    try:
        sarif_data = load_sarif_from_file(sarif_path)
    except json.JSONDecodeError as e:
        return {
            "success": False,
            "error": f"Failed to parse SARIF JSON: {str(e)}"
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to load SARIF file: {str(e)}"
        }

    try:
        taint_paths = extract_taint_paths(sarif_data)
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to extract taint paths: {str(e)}"
        }

    if not taint_paths:
        return {
            "success": True,
            "count": 0,
            "paths": []
        }

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

    return {
        "success": True,
        "count": len(formatted_paths),
        "paths": formatted_paths
    }

@mcp.tool()
def generate_harness(function_name: str, source_file: str) -> dict:
    """Generate C++ harness for symbolic execution."""
    result = _generate_harness(function_name, source_file)
    return {
        "success": result.success,
        "harness_code": result.harness_code,
        "error": result.error
    }

@mcp.tool()
def compile_harness(harness_code: str, source_file: str) -> dict:
    """Compile harness with original source file."""
    result = _compile_harness(harness_code, source_file)
    return {
        "success": result.success,
        "binary_path": result.binary_path,
        "harness_path": result.harness_path,
        "error": result.error
    }

@mcp.tool()
def verify_sanitization(binary_path: str, timeout: int = 60) -> dict:
    """Run symbolic execution to verify sanitization."""
    result = _verify_sanitization(binary_path, timeout)
    return result.to_dict()

@mcp.tool()
def verify_with_constraints(binary_path: str, constraints: dict, timeout: int = 60) -> dict:
    """
    Verify sanitization with input/output constraints using symbolic execution.

    Args:
        binary_path: Path to the compiled binary to analyze
        constraints: Dictionary with input_constraints and output_constraints
                     Format: {"input_constraints": [...], "output_constraints": [...]}
        timeout: Execution timeout in seconds (default: 60)

    Returns:
        Dictionary with verification results including:
        - success: Whether the execution completed successfully
        - sanitized: Whether all paths are properly sanitized
        - paths_analyzed: Total number of execution paths analyzed
        - paths_safe: Number of paths that are properly sanitized
        - paths_harmful: Number of paths that bypass sanitization
        - details: Detailed analysis results per path
    """
    if not os.path.exists(binary_path):
        return {
            "success": False,
            "sanitized": False,
            "paths_analyzed": 0,
            "paths_safe": 0,
            "paths_harmful": 0,
            "details": {},
            "error": f"Binary file not found: {binary_path}"
        }

    try:
        executor = SymbolicExecutor(binary_path)
        result = executor.execute_with_constraints(constraints, timeout)
        return result.to_dict()

    except FileNotFoundError as e:
        return {
            "success": False,
            "sanitized": False,
            "paths_analyzed": 0,
            "paths_safe": 0,
            "paths_harmful": 0,
            "details": {},
            "error": f"Binary file not found: {str(e)}"
        }
    except Exception as e:
        return {
            "success": False,
            "sanitized": False,
            "paths_analyzed": 0,
            "paths_safe": 0,
            "paths_harmful": 0,
            "details": {},
            "error": f"Symbolic execution failed: {str(e)}"
        }

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--stdio":
        mcp.run()
    else:
        mcp.run(transport="http", host="127.0.0.1", port=8000)
