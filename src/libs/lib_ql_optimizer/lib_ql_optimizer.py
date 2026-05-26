"""
提供针对 QL 查询的结构分析和优化建议的工具函数，主要用于修复 CWE-190 中的关于乘法检查的误报问题。核心功能包括：
1. 读取并分析 QL 文件的基础结构，统计导入语句、谓词定义、是否包含 where 和 select 子句等信息。
2. 基于分析结果给出针对性优化建议，如增加排除条件、补充 Sanitizer 相关逻辑、优先在 where 子句中增加限制条件等。
"""
import re
from pathlib import Path


CONFIG_QL_OUTPUT_DIR = str(Path(__file__).parent) + "/optimized_codeql_queries/"
CONFIG_QL_OUPUT_SUFFIX = "_optimized.ql"


def _read_text(file_path: str) -> str:
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"文件不存在: {path}")
    return path.read_text(encoding="utf-8")


def _write_text(target_path: str, content: str) -> str:
    path = Path(target_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return str(path)


def inspect_ql_query(ql_path: str) -> dict:
    """读取并分析 QL 文件的基础结构。"""
    try:
        content = _read_text(ql_path)
    except Exception as exc:
        return {"success": False, "error": str(exc), "ql_path": ql_path}

    import_count = len(re.findall(r"^\s*import\s+", content, flags=re.MULTILINE))
    predicate_count = len(re.findall(r"^\s*(?:predicate|private predicate|class)\s+", content, flags=re.MULTILINE))
    has_where = bool(re.search(r"^\s*where\b", content, flags=re.MULTILINE))
    has_select = bool(re.search(r"^\s*select\b", content, flags=re.MULTILINE))

    return {
        "success": True,
        "ql_path": str(Path(ql_path)),
        "ql_name": Path(ql_path).name,
        "summary": {
            "import_count": import_count,
            "predicate_or_class_count": predicate_count,
            "has_where_clause": has_where,
            "has_select_clause": has_select,
            "line_count": len(content.splitlines()),
        },
        "content": content,
    }


def inspect_source_code(source_code_path: str) -> dict:
    """读取并分析源代码文件的基础结构。"""
    try:
        content = _read_text(source_code_path)
    except Exception as exc:
        return {"success": False, "error": str(exc), "source_code_path": source_code_path}

    function_count = len(re.findall(r"^\s*(?:def|function|method)\s+\w+\s*\(", content, flags=re.MULTILINE))
    class_count = len(re.findall(r"^\s*class\s+\w+\s*[:\(]", content, flags=re.MULTILINE))
    has_main = bool(re.search(r"^\s*if\s+__name__\s*==\s*['\"]__main__['\"]\s*:", content, flags=re.MULTILINE))

    return {
        "success": True,
        "source_code_path": str(Path(source_code_path)),
        "summary": {
            "function_count": function_count,
            "class_count": class_count,
            "has_main_block": has_main,
            "line_count": len(content.splitlines()),
        },
        "content": content,
    }


def write_ql_query(ql_name: str, content: str) -> dict:
    """将优化后的 QL 查询内容写回文件。"""
    try:
        target_path = _write_text(CONFIG_QL_OUTPUT_DIR + ql_name.replace(".ql", CONFIG_QL_OUPUT_SUFFIX), content)
        return {"success": True, "ql_path": target_path, "ql_name": ql_name,  "message": "QL 查询已成功写入文件。"}
    except Exception as exc:
        return {"success": False, "error": str(exc), "ql_path": ql_name}
