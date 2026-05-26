from fastmcp import FastMCP
from libs.lib_ql_optimizer import (
    inspect_ql_query,
    inspect_source_code,
    write_ql_query,
)

mcp = FastMCP(
    name="QL Optimizer Tools",
    instructions="CodeQL QL 查询优化辅助工具 — 读取QL文件、误报源代码，写入优化后的查询"
)


@mcp.tool(
    name="inspect_ql_query",
    description="查看 QL 查询文件的内容，输入为ql文件的路径"
)
def inspect_ql_query_tool(ql_query: str) -> dict:
    """分析 QL 查询，识别潜在的性能问题和优化机会"""
    return inspect_ql_query(ql_query)


@mcp.tool(
    name="inspect_source_code",
    description="查看被误报的源代码文件的内容，输入为源代码文件的路径"
)
def inspect_source_code_tool(source_code_path: str) -> dict:
    """分析源代码，识别潜在的性能问题和优化机会"""
    return inspect_source_code(source_code_path)


@mcp.tool(
    name="write_ql_query",
    description="将优化后的 QL 查询写入指定文件，输入为ql文件的文件名（仅文件名，不含路径，example：query.ql）和新的ql查询内容（完整的ql查询内容）"
)
def write_ql_query_tool(ql_name: str, ql_content: str) -> dict:
    """将优化后的 QL 查询写入指定文件"""
    return write_ql_query(ql_name, ql_content)


if __name__ == "__main__":
    mcp.run(transport="stdio")
