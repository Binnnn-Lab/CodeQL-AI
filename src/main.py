from typing import Optional

from fastmcp import FastMCP
from libs.lib_sanitizer import (
    patch_ql,
    read_function_implementation,
    run_taint_analysis,
)
from libs.lib_knowledge import (
    load_applicable_experiences,
    save_experience_pattern,
    update_experience_validation,
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


@mcp.tool(
    name="save_experience_pattern",
    description="保存 LLM 从误报分析中总结出的 repo/global 级 sanitizer 经验"
)
def save_experience_pattern_tool(pattern: dict, knowledge_base_path: Optional[str] = None) -> dict:
    """保存结构化经验，默认写入项目 knowledge 目录"""
    return save_experience_pattern(pattern, knowledge_base_path)


@mcp.tool(
    name="load_applicable_experiences",
    description="根据 repo、语言、CWE/query 等条件读取可复用的经验"
)
def load_applicable_experiences_tool(
    repo_id: Optional[str] = None,
    language: Optional[str] = None,
    cwe: Optional[str] = None,
    query_id: Optional[str] = None,
    experience_type: Optional[str] = None,
    function_name: Optional[str] = None,
    min_confidence: str = "low",
    include_global: bool = True,
    include_rejected: bool = False,
    knowledge_base_path: Optional[str] = None,
) -> dict:
    """读取适用于当前 database 分析的经验列表"""
    return load_applicable_experiences(
        repo_id=repo_id,
        language=language,
        cwe=cwe,
        query_id=query_id,
        experience_type=experience_type,
        function_name=function_name,
        min_confidence=min_confidence,
        include_global=include_global,
        include_rejected=include_rejected,
        knowledge_base_path=knowledge_base_path,
    )


@mcp.tool(
    name="update_experience_validation",
    description="更新经验的置信度、状态和验证计数"
)
def update_experience_validation_tool(
    experience_id: str,
    repo_id: Optional[str] = None,
    scope: str = "repo",
    status: Optional[str] = None,
    confidence: Optional[str] = None,
    validation_result: Optional[str] = None,
    note: Optional[str] = None,
    knowledge_base_path: Optional[str] = None,
) -> dict:
    """在人工或回归验证后更新经验状态"""
    return update_experience_validation(
        experience_id=experience_id,
        repo_id=repo_id,
        scope=scope,
        status=status,
        confidence=confidence,
        validation_result=validation_result,
        note=note,
        knowledge_base_path=knowledge_base_path,
    )

if __name__ == "__main__":
    # 以 Streamable HTTP 模式运行，端口 8000
    mcp.run(transport="http", host="127.0.0.1", port=8000)
