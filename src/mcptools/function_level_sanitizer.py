import sys
import os

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from fastmcp import FastMCP
from libs.lib_sanitizer import (
    patch_ql,
    read_function_implementation,
    run_taint_analysis,
)

# 初始化 MCP Server
mcp = FastMCP(
    name="Sanitizer Tools",
    instructions="CodeQL Sanitizer 辅助工具"
)

@mcp.tool(
    name="find_potential_functions",
    description="运行codeql, 查找所有处于数据流路径上污点流入的函数",
    task=True
)
async def find_potential_functions(taint_json: dict, database_path: str) -> dict:
    """使用 CodeQL 执行污点分析"""
    return await run_taint_analysis(taint_json, database_path)



@mcp.tool(
    name="read_function_implementation",
    description="从 C/C++ 源文件中提取指定函数的定义源代码"
)
def read_function_implementation_tool(function_name: str, file_path: str) -> dict:
    """从 C/C++ 源文件中提取指定函数的定义源代码"""
    return read_function_implementation(function_name, file_path)

@mcp.tool(
    name="patch_ql",
    description=(
        "将优化后的 QL 查询写入指定路径，并自动维护 original→patched 映射表。\n"
        "参数说明：\n"
        "- patched_ql_path (必填): patched QL 的输出绝对路径，必须位于 scripts/.CODEQL-AI/patched-ql/ 目录下\n"
        "- new_content (必填): 完整的优化后 QL 文件内容\n"
        "- original_ql_path (必填): 被修补的原始 QL 文件的绝对路径，用于自动更新 scripts/.CODEQL-AI/ql_mappings.json 映射表"
    ),
)
def patch_ql_tool(patched_ql_path: str, new_content: str, original_ql_path: str = "") -> dict:
    """将优化后的 QL 查询写入 patched-ql 目录，并更新映射表"""
    return patch_ql(patched_ql_path, new_content, original_ql_path or None)

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--stdio":
        mcp.run()
    else:
        mcp.run(transport="http", host="127.0.0.1", port=8001)

