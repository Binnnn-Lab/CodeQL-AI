import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from libs.config import DEFAULT_RULE_MAP

DEFAULT_SOURCE_ROOT = "/data/benchmark/juliet/juliet-test-suite-c"


def _load_rule_id_map(map_path: Optional[str]) -> Dict[str, str]:
    path = Path(map_path).expanduser() if map_path else DEFAULT_RULE_MAP
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    return {}


def _resolve_ql_path(rule_id: Optional[str], rule_map: Dict[str, str]) -> Optional[str]:
    if not rule_id:
        return None
    return rule_map.get(str(rule_id).strip())


def _parse_sarif(sarif_path: str) -> Dict[str, Any]:
    path = Path(sarif_path).expanduser()
    if not path.exists():
        raise FileNotFoundError(f"SARIF file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        sarif = json.load(f)

    runs = sarif.get("runs", [])
    if not runs:
        raise ValueError("SARIF has no runs")

    run = runs[0]
    tool = run.get("tool", {})

    rules_by_index: Dict[int, Dict[str, Any]] = {}
    for rule in tool.get("driver", {}).get("rules", []):
        idx = rule.get("index") if rule.get("index") is not None else rule.get("id")
        if idx is not None:
            rules_by_index[idx] = {
                "id": rule.get("id", ""),
                "name": rule.get("name", ""),
                "shortDescription": rule.get("shortDescription", {}).get("text", ""),
                "fullDescription": rule.get("fullDescription", {}).get("text", ""),
            }
    for extension in tool.get("extensions", []):
        for rule in extension.get("rules", []):
            idx = rule.get("index") if rule.get("index") is not None else rule.get("id")
            if idx is not None:
                rules_by_index[idx] = {
                    "id": rule.get("id", ""),
                    "name": rule.get("name", ""),
                    "shortDescription": rule.get("shortDescription", {}).get("text", ""),
                    "fullDescription": rule.get("fullDescription", {}).get("text", ""),
                }

    results: List[Dict[str, Any]] = []
    for res in run.get("results", []):
        rule_id = res.get("ruleId")
        rule_index = res.get("ruleIndex")
        rule_meta = rules_by_index.get(rule_index) if rule_index is not None else None

        locations = []
        for loc in res.get("locations", []):
            pl = loc.get("physicalLocation", {})
            al = pl.get("artifactLocation", {})
            region = pl.get("region", {})
            uri = al.get("uri", "")
            if al.get("uriBaseId"):
                uri_base = al["uriBaseId"]
                if "%SRCROOT%" in uri_base:
                    uri = str(Path(uri_base.replace("%SRCROOT%", "").strip("/")) / uri.lstrip("/"))
            locations.append({
                "file": uri,
                "start_line": region.get("startLine"),
                "end_line": region.get("endLine"),
                "start_column": region.get("startColumn"),
                "end_column": region.get("endColumn"),
                "snippet": region.get("snippet", {}).get("text", ""),
                "message": loc.get("message", {}).get("text", ""),
            })

        related_locations = []
        for rl in res.get("relatedLocations", []):
            pl = rl.get("physicalLocation", {})
            al = pl.get("artifactLocation", {})
            region = pl.get("region", {})
            related_locations.append({
                "file": al.get("uri", ""),
                "start_line": region.get("startLine"),
                "end_line": region.get("endLine"),
                "message": rl.get("message", {}).get("text", ""),
            })

        code_flows = []
        for cf in res.get("codeFlows", []):
            for tf in cf.get("threadFlows", []):
                flow_locations = []
                for tfl in tf.get("locations", []):
                    loc_obj = tfl.get("location", {})
                    pl = loc_obj.get("physicalLocation", {})
                    al = pl.get("artifactLocation", {})
                    region = pl.get("region", {})
                    flow_locations.append({
                        "file": al.get("uri", ""),
                        "start_line": region.get("startLine"),
                        "end_line": region.get("endLine"),
                        "message": loc_obj.get("message", {}).get("text", ""),
                    })
                code_flows.append({"locations": flow_locations})

        results.append({
            "rule_id": rule_id,
            "rule_index": rule_index,
            "rule_name": rule_meta.get("name") if rule_meta else None,
            "rule_short_description": rule_meta.get("shortDescription") if rule_meta else None,
            "message": res.get("message", {}).get("text", ""),
            "locations": locations,
            "related_locations": related_locations,
            "code_flows": code_flows,
        })

    return {
        "sarif_path": str(path),
        "tool_name": tool.get("driver", {}).get("name", ""),
        "result_count": len(results),
        "results": results,
        "rules_by_index": rules_by_index,
    }


def read_source_context(
    file_path: str,
    start_line: int,
    end_line: Optional[int] = None,
    context_lines: int = 5,
    source_root: Optional[str] = None,
) -> Dict[str, Any]:
    path = Path(file_path).expanduser()
    if not path.is_absolute() and source_root:
        path = Path(source_root).expanduser() / path
    if not path.exists():
        return {
            "file": str(path),
            "exists": False,
            "start_line": start_line,
            "end_line": end_line,
            "code_snippet": "",
            "context_before": "",
            "context_after": "",
        }

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        all_lines = f.readlines()

    total = len(all_lines)
    if start_line < 1 or start_line > total:
        return {
            "file": str(path),
            "exists": True,
            "start_line": start_line,
            "end_line": end_line,
            "total_lines": total,
            "code_snippet": "",
            "context_before": "",
            "context_after": "",
        }

    actual_end = min(end_line or start_line, total)
    actual_start = max(1, start_line)
    snippet_start = max(1, actual_start - context_lines)
    snippet_end = min(total, actual_end + 1)

    code_lines = all_lines[actual_start - 1 : actual_end]
    before_lines = all_lines[snippet_start - 1 : actual_start - 1]
    after_lines = all_lines[actual_end : snippet_end]

    return {
        "file": str(path),
        "exists": True,
        "start_line": actual_start,
        "end_line": actual_end,
        "total_lines": total,
        "code_snippet": "".join(code_lines).rstrip(),
        "context_before": "".join(before_lines).rstrip(),
        "context_after": "".join(after_lines).rstrip(),
    }


def _resolve_result_paths(result: Dict[str, Any], source_root: str) -> None:
    root = Path(source_root)
    for loc in result.get("locations", []):
        f = loc.get("file", "")
        if f and not Path(f).is_absolute():
            loc["file"] = str(root / f)
    for rl in result.get("related_locations", []):
        f = rl.get("file", "")
        if f and not Path(f).is_absolute():
            rl["file"] = str(root / f)
    for cf in result.get("code_flows", []):
        for fl in cf.get("locations", []):
            f = fl.get("file", "")
            if f and not Path(f).is_absolute():
                fl["file"] = str(root / f)


def analyze_fp_report(
    sarif_path: str,
    rule_id_map_path: Optional[str] = None,
    source_root: Optional[str] = None,
) -> Dict[str, Any]:
    try:
        sarif_data = _parse_sarif(sarif_path)
        rule_map = _load_rule_id_map(rule_id_map_path)

        rule_to_ql: Dict[str, Optional[str]] = {}
        for res in sarif_data["results"]:
            rid = res.get("rule_id")
            if rid and rid not in rule_to_ql:
                rule_to_ql[rid] = _resolve_ql_path(rid, rule_map)

        resolved_root = str(Path(source_root).expanduser()) if source_root else None

        enriched_results = []
        for res in sarif_data["results"]:
            rid = res.get("rule_id")
            res["ql_path"] = rule_to_ql.get(rid)
            if resolved_root:
                _resolve_result_paths(res, resolved_root)
            enriched_results.append(res)

        return {
            "success": True,
            "sarif_path": sarif_data["sarif_path"],
            "source_root": resolved_root,
            "tool_name": sarif_data["tool_name"],
            "rule_id_map_used": str(rule_id_map_path or DEFAULT_RULE_MAP),
            "rule_to_ql": rule_to_ql,
            "result_count": len(enriched_results),
            "results": enriched_results,
        }
    except Exception as exc:
        return {"success": False, "error": str(exc)}


def save_fp_experience(
    repo_id: str,
    language: str,
    pattern_summary: str,
    root_cause: str,
    cwe: Optional[str] = None,
    query_id: Optional[str] = None,
    fp_type: Optional[str] = None,
    initial_states: Optional[List[str]] = None,
    states: Optional[List[Dict[str, str]]] = None,
    transitions: Optional[List[Dict[str, Any]]] = None,
    ql_file: Optional[str] = None,
    ql_snippet: Optional[str] = None,
    sarif_refs: Optional[List[Dict[str, Any]]] = None,
    scope: str = "repo",
    confidence: str = "low",
    knowledge_base_path: Optional[str] = None,
) -> Dict[str, Any]:
    try:
        from libs.lib_knowledge import save_experience_pattern

        experience: Dict[str, Any] = {
            "scope": scope,
            "repo_id": repo_id,
            "language": language,
            "type": "false_positive",
            "pattern_summary": pattern_summary,
            "root_cause": root_cause,
            "confidence": confidence,
        }
        if cwe:
            experience["cwe"] = cwe
        if query_id:
            experience["query_id"] = query_id
        if fp_type:
            experience["fp_type"] = fp_type
        if initial_states:
            experience["initial_states"] = initial_states
        if states:
            experience["states"] = states
        if transitions:
            experience["transitions"] = transitions
        if ql_file:
            experience["ql_file"] = ql_file
        if ql_snippet:
            experience["ql_snippet"] = ql_snippet
        if sarif_refs:
            experience["sarif_refs"] = sarif_refs

        return save_experience_pattern(experience, knowledge_base_path=knowledge_base_path)
    except Exception as exc:
        return {"success": False, "error": str(exc)}
