"""
Path Context — batch source reading for taint path nodes.
"""

import re
from pathlib import Path



_KEYWORDS = frozenset({
    'if', 'else', 'for', 'while', 'do', 'switch', 'case', 'return',
    'break', 'continue', 'goto', 'sizeof', 'typedef', 'extern',
    'static', 'inline', 'const', 'volatile', 'register',
})
_FUNC_DEF_PATTERN = re.compile(r'^[\w\s\*:~]+?\b(\w+)\s*\([^;]*$')


def find_enclosing_function(file_path: str, line_number: int) -> dict:
    path = Path(file_path)
    if not path.exists():
        return {"success": False, "error": f"文件不存在: {file_path}"}

    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception as e:
        return {"success": False, "error": f"读取文件失败: {str(e)}"}

    if line_number < 1 or line_number > len(lines):
        return {"success": False, "error": f"行号超出范围: {line_number} (文件共 {len(lines)} 行)"}

    # Scan upward from target line to find the function definition start
    target_idx = line_number - 1
    func_start = None
    func_name = None

    for i in range(target_idx, -1, -1):
        line = lines[i]
        m = _FUNC_DEF_PATTERN.match(line)
        if not m:
            continue
        if m.group(1) in _KEYWORDS:
            continue
        # Confirm it's a definition (has '{' nearby, not just a declaration ending with ';')
        search_text = ''.join(lines[i:min(i + 10, len(lines))])
        if '{' not in search_text:
            continue
        before_brace = search_text.split('{')[0]
        if before_brace.rstrip().endswith(';'):
            continue
        func_start = i
        func_name = m.group(1)
        break

    if func_start is None:
        return {"success": False, "error": f"未找到包含第 {line_number} 行的函数"}

    # Find function end by matching braces
    brace_count = 0
    found_start = False
    func_end = func_start
    for j in range(func_start, len(lines)):
        for char in lines[j]:
            if char == '{':
                found_start = True
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if found_start and brace_count == 0:
                    func_end = j + 1
                    break
        if found_start and brace_count == 0:
            break

    if brace_count != 0:
        return {"success": False, "error": f"函数 {func_name} 的花括号不匹配"}

    # Verify target line is within function range
    if target_idx >= func_end:
        return {"success": False, "error": f"第 {line_number} 行不在函数 {func_name} 内"}

    return {
        "success": True,
        "function_name": func_name,
        "file_path": file_path,
        "start_line": func_start + 1,
        "end_line": func_end,
        "source_code": ''.join(lines[func_start:func_end])
    }
