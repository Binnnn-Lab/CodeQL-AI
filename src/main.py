from typing import Optional

from fastmcp import FastMCP
from libs.lib_sanitizer import (
    patch_ql,
    read_function_implementation,
    run_taint_analysis,
)
from libs.lib_false_positive import analyze_fp_report, read_source_context, save_fp_experience
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

@mcp.tool(
    name="analyze_fp_report",
    description="解析 SARIF 误报报告，返回关系表：每条告警的 ruleId、对应 QL 路径、源码文件位置、message、codeFlows，不读取 QL 和源码内容",
)
def analyze_fp_report_tool(
    sarif_path: str,
    rule_id_map_path: Optional[str] = None,
    source_root: Optional[str] = None,
) -> dict:
    return analyze_fp_report(
        sarif_path=sarif_path,
        rule_id_map_path=rule_id_map_path,
        source_root=source_root,
    )


@mcp.tool(
    name="read_source_context",
    description="读取指定文件的源码片段，返回目标行前后 context_lines 行上下文",
)
def read_source_context_tool(
    file_path: str,
    start_line: int,
    end_line: Optional[int] = None,
    context_lines: int = 5,
    source_root: Optional[str] = None,
) -> dict:
    return read_source_context(
        file_path=file_path,
        start_line=start_line,
        end_line=end_line,
        context_lines=context_lines,
        source_root=source_root,
    )


@mcp.tool(
    name="save_fp_experience",
    description="保存 LLM 分析出的误报模式知识到 knowledge 数据库，支持状态转移模式",
)
def save_fp_experience_tool(
    repo_id: str,
    language: str,
    pattern_summary: str,
    root_cause: str,
    cwe: Optional[str] = None,
    query_id: Optional[str] = None,
    fp_type: Optional[str] = None,
    initial_states: Optional[list] = None,
    states: Optional[list] = None,
    transitions: Optional[list] = None,
    ql_file: Optional[str] = None,
    ql_snippet: Optional[str] = None,
    sarif_refs: Optional[list] = None,
    scope: str = "repo",
    confidence: str = "low",
    knowledge_base_path: Optional[str] = None,
) -> dict:
    return save_fp_experience(
        repo_id=repo_id,
        language=language,
        pattern_summary=pattern_summary,
        root_cause=root_cause,
        cwe=cwe,
        query_id=query_id,
        fp_type=fp_type,
        initial_states=initial_states,
        states=states,
        transitions=transitions,
        ql_file=ql_file,
        ql_snippet=ql_snippet,
        sarif_refs=sarif_refs,
        scope=scope,
        confidence=confidence,
        knowledge_base_path=knowledge_base_path,
    )


if __name__ == "__main__":
    # 以 Streamable HTTP 模式运行，端口 8000
    mcp.run(transport="http", host="127.0.0.1", port=8000)
