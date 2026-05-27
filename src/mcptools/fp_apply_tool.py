import sys
import os
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastmcp import FastMCP
from libs.lib_knowledge import load_applicable_experiences, save_experience_pattern, update_experience_validation
from libs.lib_fp_experience import match_experience_to_ql

mcp = FastMCP(
    name="FP Apply Tools",
    instructions="提取误报经验并匹配到目标 QL 查询以辅助修补的辅助工具",
)


@mcp.tool(
    name="load_applicable_experiences",
    description="根据 repo、语言、CWE/query 等条件读取可复用的经验",
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
    name="match_experience_to_ql",
    description="将一条已保存的误报经验与目标 QL 文件做匹配，判断该经验是否适用于此 QL 查询",
)
def match_experience_to_ql_tool(
    experience: dict,
    ql_file_path: str,
) -> dict:
    return match_experience_to_ql(
        experience=experience,
        ql_file_path=ql_file_path,
    )


@mcp.tool(
    name="extract_and_match",
    description="批量加载适用经验并逐一匹配目标 QL 文件，返回排序后的匹配结果和最佳修补建议",
)
def extract_and_match_tool(
    ql_file_path: str,
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
    try:
        loaded = load_applicable_experiences(
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

        experiences: List[Dict[str, Any]] = []
        if isinstance(loaded, dict):
            experiences = loaded.get("experiences") or loaded.get("results") or []
        if isinstance(loaded, list):
            experiences = loaded

        if not experiences:
            return {
                "success": True,
                "ql_file": ql_file_path,
                "total_experiences": 0,
                "matches": [],
                "best_match": None,
                "suggestion": "未找到适用的经验",
            }

        matches: List[Dict[str, Any]] = []
        for exp in experiences:
            match_result = match_experience_to_ql(exp, ql_file_path)
            if match_result.get("success"):
                matches.append({
                    "experience_id": exp.get("id"),
                    "pattern_summary": exp.get("pattern_summary", ""),
                    "root_cause": exp.get("root_cause", ""),
                    "fp_type": exp.get("fp_type", ""),
                    "scope": exp.get("scope", ""),
                    "confidence": exp.get("confidence", ""),
                    "matched": match_result.get("matched"),
                    "score": match_result.get("score"),
                    "matched_details": match_result.get("matched_details", []),
                    "matched_transitions": match_result.get("matched_transitions", []),
                    "unmatched_transitions": match_result.get("unmatched_transitions", []),
                    "suggestion": match_result.get("suggestion", ""),
                    "experience": exp,
                })
            else:
                matches.append({
                    "experience_id": exp.get("id"),
                    "pattern_summary": exp.get("pattern_summary", ""),
                    "matched": False,
                    "score": 0,
                    "error": match_result.get("error", "匹配失败"),
                    "experience": exp,
                })

        matches.sort(key=lambda m: m.get("score", 0), reverse=True)
        best = matches[0] if matches else None
        applicable = [m for m in matches if m.get("matched")]

        return {
            "success": True,
            "ql_file": ql_file_path,
            "total_experiences": len(experiences),
            "matched_count": len(applicable),
            "matches": matches,
            "best_match": best,
            "suggestion": (
                f"找到 {len(applicable)} 条适用经验，最佳匹配 score={best['score']:.2f}"
                if best and best.get("matched")
                else "未找到高置信度匹配，建议人工审查"
            ),
        }
    except Exception as exc:
        return {"success": False, "error": str(exc)}


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--stdio":
        mcp.run()
    else:
        mcp.run(transport="http", host="127.0.0.1", port=8003)
