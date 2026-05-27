import re
from pathlib import Path
from typing import Any, Dict, List, Optional

RE_FUNCTION_CALL = re.compile(r"\b(\w+)\s*\(")


def _extract_function_calls(code: str) -> List[str]:
    matches = re.findall(RE_FUNCTION_CALL, code)
    keywords = {"if", "for", "while", "switch", "return", "sizeof", "typeof", "catch"}
    return [m for m in matches if m not in keywords]


def _read_ql_file(ql_file_path: str) -> Optional[str]:
    path = Path(ql_file_path).expanduser()
    if not path.exists():
        return None
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _match_transitions_in_ql(
    transitions: Optional[List[Dict[str, Any]]],
    ql_content: str,
) -> Dict[str, Any]:
    if not transitions:
        return {"matched_transitions": [], "unmatched_transitions": [], "details": []}

    matched_transitions: List[str] = []
    unmatched_transitions: List[str] = []
    details: List[Dict[str, Any]] = []

    for tr in transitions:
        target = (tr.get("target") or "").strip()
        if not target:
            continue
        if target in ql_content:
            matched_transitions.append(target)
            details.append({"transition_target": target, "found_in_ql": True, "status": "found"})
        else:
            unmatched_transitions.append(target)
            details.append({"transition_target": target, "found_in_ql": False, "status": "not_found"})

    return {
        "matched_transitions": matched_transitions,
        "unmatched_transitions": unmatched_transitions,
        "details": details,
    }


def match_experience_to_ql(
    experience: Dict[str, Any],
    ql_file_path: str,
) -> Dict[str, Any]:
    """Match a saved false-positive experience against a target QL file.

    Reads the QL file and compares it with the experience metadata to
    determine whether the experience is applicable to this QL query.

    Matching factors (each contributes to ``score``):
    - ``experience.ql_file`` matches ``ql_file_path`` → same query, strongest signal (0.6)
    - ``experience.ql_snippet`` found in the QL content → same predicate pattern (0.3)
    - ``experience.transitions[].target`` found in the QL → function already tracked (0.1)

    Parameters
    ----------
    experience : dict
        A saved experience record from the knowledge base.
    ql_file_path : str
        Absolute path to the QL file being checked.

    Returns
    -------
    dict with keys ``matched``, ``score``, ``matched_details``, and ``suggestion``.
    """
    try:
        ql_content = _read_ql_file(ql_file_path)
        if ql_content is None:
            return {"success": False, "error": f"QL file not found: {ql_file_path}"}

        score = 0.0
        matched_details: List[str] = []

        exp_ql_file = (experience.get("ql_file") or "").strip()
        if exp_ql_file and Path(exp_ql_file).resolve() == Path(ql_file_path).resolve():
            score += 0.6
            matched_details.append("同一 QL 查询文件")

        ql_snippet = (experience.get("ql_snippet") or "").strip()
        if ql_snippet and ql_snippet in ql_content:
            score += 0.3
            matched_details.append("QL 代码片段匹配")

        transitions = experience.get("transitions")
        if transitions:
            trans_report = _match_transitions_in_ql(transitions, ql_content)
            matched_count = len(trans_report["matched_transitions"])
            total_count = matched_count + len(trans_report["unmatched_transitions"])
            if total_count > 0:
                transition_score = (matched_count / total_count) * 0.1
                score += transition_score
                if matched_count > 0:
                    matched_details.append(f"transition targets 命中 {matched_count}/{total_count}: {', '.join(trans_report['matched_transitions'])}")
        else:
            trans_report = {"matched_transitions": [], "unmatched_transitions": [], "details": []}

        matched = score >= 0.5
        fp_type = experience.get("fp_type", "")
        fp_suggestions = {
            "missing_internal_call_sanitizer": f"该 QL 缺少对 {', '.join(trans_report['unmatched_transitions']) if trans_report['unmatched_transitions'] else '特定函数'} 的 sanitizer 识别",
            "missing_guard_barrier": f"该 QL 缺少对 {', '.join(trans_report['unmatched_transitions']) if trans_report['unmatched_transitions'] else '特定条件'} 的 guard barrier",
            "overly_broad_source": "该 QL 的 source 定义可能过于宽泛",
            "overly_broad_sink": "该 QL 的 sink 定义可能过于宽泛",
            "wrong_pattern_match": "该 QL 的模式匹配可能触发了无害代码",
            "type_mismatch_in_condition": "该 QL 的类型约束可能没有被正确建模",
        }

        if matched:
            suggestion = f"经验适用（score={score:.2f}）。{fp_suggestions.get(fp_type, '可参考经验的 pattern_summary 和 root_cause')}"
        elif score > 0:
            suggestion = f"部分匹配（score={score:.2f}）。匹配项: {'; '.join(matched_details)}。请人工确认"
        else:
            suggestion = "该经验与目标 QL 文件无匹配，可能不适用"

        return {
            "success": True,
            "experience_id": experience.get("id"),
            "ql_file": ql_file_path,
            "matched": matched,
            "score": score,
            "matched_details": matched_details,
            "matched_transitions": trans_report["matched_transitions"],
            "unmatched_transitions": trans_report["unmatched_transitions"],
            "transition_details": trans_report["details"],
            "suggestion": suggestion,
        }
    except Exception as exc:
        return {"success": False, "error": str(exc)}
