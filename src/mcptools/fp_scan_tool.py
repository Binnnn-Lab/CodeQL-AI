import sys
import os
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastmcp import FastMCP
from libs.lib_fp_experience import analyze_fp_report, read_source_context, save_fp_experience

mcp = FastMCP(
    name="FP Scanner Tools",
    instructions="扫描 SARIF 误报报告并将分析结果保存为经验的辅助工具",
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
    if len(sys.argv) > 1 and sys.argv[1] == "--stdio":
        mcp.run()
    else:
        mcp.run(transport="http", host="127.0.0.1", port=8002)
