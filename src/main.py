from fastmcp import FastMCP
from libs.lib_sanitizer import (
    patch_ql,
    read_function_implementation,
    run_taint_analysis,
)
from libs.lib_ql_optimizer import (
    inspect_ql_query,
    inspect_source_code,
    write_ql_query,
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
    description="将新内容写入指定的 QL 文件"
)
def patch_ql_tool(patched_ql_path: str, new_content: str) -> dict:
    """将新内容写入指定的 QL 文件"""
    return patch_ql(patched_ql_path, new_content)

"""
读取ql查询文件，分析查询内容，读取误报的代码，识别潜在的优化机会，并将优化后的查询写入新的ql文件中
以CWE-190为例。
"""
mcp2 = FastMCP(
    name="Sanitizer Tools 2",
    instructions="CodeQL Sanitizer 辅助工具 2"
)


@mcp2.tool(
    name="inspect_ql_query",
    description="查看 QL 查询文件的内容，输入为ql文件的路径"
)
def inspect_ql_query_tool(ql_query: str) -> dict:
    """分析 QL 查询，识别潜在的性能问题和优化机会"""
    return inspect_ql_query(ql_query)

@mcp2.tool(
    name="inspect_source_code",
    description="查看被误报的源代码文件的内容，输入为源代码文件的路径"
)
def inspect_source_code_tool(source_code_path: str) -> dict:
    """分析源代码，识别潜在的性能问题和优化机会"""
    return inspect_source_code(source_code_path)

@mcp2.tool(
    name="write_ql_query",
    description="将优化后的 QL 查询写入指定文件，输入为ql文件的文件名（仅文件名，不含路径，example：query.ql）和新的ql查询内容（完整的ql查询内容）"
)
def write_ql_query_tool(ql_name: str, ql_content: str) -> dict:
    """将优化后的 QL 查询写入指定文件"""
    return write_ql_query(ql_name, ql_content)


if __name__ == "__main__":
    # 以 Streamable HTTP 模式运行，端口 8000
    # mcp.run(transport="http", host="127.0.0.1", port=8000)

    # 以标准输入输出模式运行，适用于与其他工具的集成
    mcp2.run(transport="stdio")
