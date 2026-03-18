import asyncio
import re
from typing import List
import shlex
from pathlib import Path


async def run_step(cmd: List[str], cwd: str, step_name: str, timeout: int = 120) -> dict:
    """执行单个编译步骤"""
    cmd_str = shlex.join(cmd)
    try:
        process = await asyncio.create_subprocess_shell(
            cmd_str,
            cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            return {"success": False, "step": step_name, "command": cmd_str, "error": f"{step_name} 执行超时"}
            
        return {
            "success": process.returncode == 0,
            "step": step_name,
            "command": cmd_str,
            # "stdout": stdout.decode(),
            "stderr": stderr.decode()
        }
    except Exception as e:
        return {"success": False, "step": step_name, "command": cmd_str, "error": f"执行错误: {str(e)}"}



async def run_taint_analysis(
    taint_json: dict,
    database_path: str,
    cwd: str = "."
) -> dict:
    """
    使用 CodeQL 执行污点分析
    
    Args:
        taint_json: 污点配置，包含 source 和 sink 信息
            {
                "source": {
                    "source_file_path": "src/vuln.c",
                    "source_start_line": 20,
                    "source_target_name": "data_B"
                },
                "sink": {
                    "sink_file_path": "src/sink.c",
                    "sink_start_line": 50,
                    "sink_target_name": "memcpy"
                }
            }
        database_path: CodeQL 数据库路径
        cwd: 工作目录
    
    Returns:
        包含执行结果的字典
    """
    # 获取 QL 模板路径
    template_path = Path(__file__).parent / "codeql-queries" / "find_potential_functions.ql"
    
    if not template_path.exists():
        return {"success": False, "error": f"QL 模板文件不存在: {template_path}"}
    
    if not Path(database_path).exists():
        return {"success": False, "error": f"CodeQL 数据库不存在: {database_path}"}
    
    # 读取 QL 模板
    try:
        with open(template_path, 'r', encoding='utf-8') as f:
            ql_content = f.read()
    except Exception as e:
        return {"success": False, "error": f"读取 QL 模板失败: {str(e)}"}
    
    # 提取 source 和 sink 配置
    source = taint_json.get("source", {})
    sink = taint_json.get("sink", {})
    
    # 替换占位符
    replacements = {
        "&source_file_path&": source.get("source_file_path", ""),
        "&source_start_line&": str(source.get("source_start_line", 0)),
        "&source_target_name&": source.get("source_target_name", ""),
        "&sink_file_path&": sink.get("sink_file_path", ""),
        "&sink_start_line&": str(sink.get("sink_start_line", 0)),
        "&sink_target_name&": sink.get("sink_target_name", ""),
    }
    
    for placeholder, value in replacements.items():
        ql_content = ql_content.replace(placeholder, value)
    
    # 生成唯一的临时文件名
    import time
    timestamp = int(time.time() * 1000)
    tmp_ql_path = Path(__file__).parent / "codeql-queries" / "tmp.ql"
    tmp_sarif_path = Path(f"/tmp/find_potential_functions_{timestamp}.sarif")
    
    # 写入修改后的 QL 文件
    try:
        with open(tmp_ql_path, 'w', encoding='utf-8') as f:
            f.write(ql_content)
    except Exception as e:
        return {"success": False, "error": f"写入临时 QL 文件失败: {str(e)}"}
    
    # 执行 CodeQL 分析
    cmd = [
        "codeql", "database", "analyze", "--rerun",
        str(database_path),
        str(tmp_ql_path),
        "--format=sarif-latest",
        f"--output={tmp_sarif_path}"
    ]
    
    result = await run_step(cmd, cwd=cwd, step_name="codeql-analyze", timeout=3000)
    
    if not result["success"]:
        return {
            "success": False,
            "error": result.get("error", result.get("stderr", "CodeQL 分析失败")),
            "command": result.get("command"),
            "tmp_ql_path": str(tmp_ql_path)
        }
    
    if not tmp_sarif_path.exists():
        return {
            "success": False,
            "error": f"分析完成但未生成 SARIF 文件: {tmp_sarif_path}",
            "command": result.get("command")
        }
    
    # 打开 SARIF 文件读取内容， ["runs"]["results"] 列表中 ["message"]["text"]
    potential_functions = []
    try:
        import json
        with open(tmp_sarif_path, 'r', encoding='utf-8') as f:
            sarif_data = json.load(f)
            
        runs = sarif_data.get("runs", [])
        if runs:
            results = runs[0].get("results", [])
            for res in results:
                text = res.get("message", {}).get("text", "")
                # 提取： “function: xxx”
                match = re.findall(r"function:\s*(\w+)", text)
                if match:
                    for func_name in match:
                        if func_name not in potential_functions:
                            potential_functions.append(func_name)
    except Exception as e:
        return {
            "success": False,
            "error": f"解析 SARIF 文件失败: {str(e)}",
            "command": result.get("command")
        }
    
    return {
        "success": True,
        "potential_sanitizer_functions": potential_functions,
        "sarif_path": str(tmp_sarif_path),
        "tmp_ql_path": str(tmp_ql_path),
        "command": result.get("command"),
        "message": f"CodeQL 污点分析完成，结果保存至: {tmp_sarif_path}"
    }

def read_function_implementation(function_name: str, file_path: str) -> dict:
    """从 C/C++ 源文件中提取指定函数的定义源代码"""
    file_path = Path(file_path)
    
    if not file_path.exists():
        return {"success": False, "error": f"文件不存在: {file_path}"}
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception as e:
        return {"success": False, "error": f"读取文件失败: {str(e)}"}
    
    # 查找函数定义行
    func_pattern = re.compile(r'\b' + re.escape(function_name) + r'\s*\(')
    
    for i, line in enumerate(lines):
        match = func_pattern.search(line)
        if not match:
            continue
            
        # 简单的启发式检查：如果匹配位置前有赋值或控制流关键字，可能是函数调用而非定义
        pre_match = line[:match.start()]
        if '=' in pre_match or re.search(r'\b(if|while|for|switch|return|case)\b', pre_match):
            continue
        
        # 向后查找 { 确认是函数定义
        search_text = ''.join(lines[i:min(i + 10, len(lines))])
        if '{' not in search_text or search_text.split('{')[0].rstrip().endswith(';'):
            continue
        
        # 找到函数体结束位置
        brace_count = 0
        end_line = i
        found_start = False
        for j in range(i, len(lines)):
            for char in lines[j]:
                if char == '{':
                    found_start = True
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if found_start and brace_count == 0:
                        end_line = j + 1
                        break
            if found_start and brace_count == 0:
                break
        
        if brace_count != 0:
            continue
        
        return {
            "success": True,
            "function_name": function_name,
            "file_path": str(file_path),
            "start_line": i + 1,
            "end_line": end_line,
            "source_code": ''.join(lines[i:end_line])
        }
    
    return {"success": True, "error": f"可能为lib库标准函数: {function_name}"}

def patch_ql(
    patched_ql_path: str,
    new_content: str
) -> dict:
    """
    将新内容写入指定的 QL 文件
    
    Args:
        patched_ql_path: 目标 QL 文件路径
        new_content: 要写入的新内容
    
    Returns:
        包含执行结果的字典
    """
    file_path = Path(patched_ql_path)
    
    try:
        # 确保父目录存在
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # 写入新内容
        file_path.write_text(new_content, encoding='utf-8')
        
        return {
            "success": True,
            "patched_ql_path": str(file_path),
            "message": f"QL 文件已成功写入: {file_path}"
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"写入 QL 文件失败: {str(e)}",
            "patched_ql_path": str(file_path)
        }
