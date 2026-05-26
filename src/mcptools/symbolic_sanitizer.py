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
def compile_harness(harness_code: str, compile_script: str, target_file: str) -> dict:
    """Compile harness code using dataset's compile.sh.

    `target_file` is the source file holding the target function (from SARIF);
    its extension decides whether the harness is compiled as C or C++.
    """
    return _compile_harness(harness_code, compile_script, target_file)


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
