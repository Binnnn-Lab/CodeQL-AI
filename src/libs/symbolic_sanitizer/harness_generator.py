"""
Harness Generator — structured harness generation + compile.sh-based compilation.
"""

import os
import tempfile
import subprocess
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def generate_harness(
    target_function: str,
    source_file: str,
    call_chain: list,
    sink_expression: str,
    includes: list = None,
) -> dict:
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
