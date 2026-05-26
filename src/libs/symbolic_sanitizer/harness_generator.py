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
    """Generate a C harness with the layout:

        char symbolic_input[64];       // angr writes symbolic bytes here
        void __sink_reached();         // angr's reachability target

        int main() {
            {call_chain}               // sanitizer guard goes here (early-return on reject)
            __sink_reached();          // reached only if sanitizer accepts the input
            {sink_expression};         // the actual sink operation (kept for taint clarity)
            return 0;
        }

    The agent is responsible for putting the sanitizer logic in ``call_chain`` such
    that the function returns BEFORE reaching ``__sink_reached`` when the
    sanitizer rejects the input. The verifier then asks angr: "can attack
    constraints still reach __sink_reached?"
    """
    if includes is None:
        includes = []

    include_lines = ['#include <stdio.h>', '#include <stdlib.h>', '#include <string.h>']
    for header in includes:
        if header.startswith('<') and header.endswith('>'):
            include_lines.append(f'#include {header}')
        else:
            include_lines.append(f'#include "{header}"')

    call_chain_lines = '\n    '.join(call_chain)
    sink_line = f"{sink_expression};" if sink_expression and not sink_expression.rstrip().endswith(';') else (sink_expression or '')

    harness_code = f"""{chr(10).join(include_lines)}

#ifdef __cplusplus
extern "C" {{
#endif
void __sink_reached(void) {{}}
char symbolic_input[64];
#ifdef __cplusplus
}}
#endif

int main(void) {{
    {call_chain_lines}
    __sink_reached();
    {sink_line}
    return 0;
}}
"""
    return {
        "success": True,
        "harness_code": harness_code,
        "error": None,
    }


_CPP_EXTS = {'.cpp', '.cc', '.cxx', '.c++', '.C', '.hpp', '.hh', '.hxx'}


def _infer_lang(target_file: str) -> str:
    """Infer 'c' vs 'cpp' from the target source file extension."""
    return 'cpp' if Path(target_file).suffix in _CPP_EXTS else 'c'


def compile_harness(harness_code: str, compile_script: str, target_file: str) -> dict:
    """Compile a harness via the dataset's compile.sh.

    `target_file` is the source file containing the target function (e.g. from
    SARIF). Its extension decides C vs C++: the harness is written with the
    matching extension and the language token is passed to compile.sh as $3.
    """
    if not Path(compile_script).exists():
        return {
            "success": False,
            "binary_path": None,
            "harness_path": None,
            "error": f"Compile script not found: {compile_script}",
        }

    lang = _infer_lang(target_file)
    harness_ext = '.cpp' if lang == 'cpp' else '.c'

    temp_dir = tempfile.mkdtemp(prefix="symbolic_harness_")
    harness_path = os.path.join(temp_dir, f"harness{harness_ext}")
    binary_path = os.path.join(temp_dir, "harness_bin")

    try:
        with open(harness_path, 'w') as f:
            f.write(harness_code)

        result = subprocess.run(
            ["bash", compile_script, harness_path, binary_path, lang],
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
