"""
SARIF Parser — extract taint paths from CodeQL SARIF results.
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass


@dataclass
class TaintPath:
    """Represents a complete taint path extracted from SARIF codeFlows."""
    path_id: str
    source: Dict
    sink: Dict
    intermediate_locations: List[Dict]
    rule_id: str
    message: str


def load_sarif_from_file(sarif_path: str) -> Dict[str, Any]:
    """Load and parse SARIF file."""
    with open(sarif_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def extract_taint_paths(sarif_data: dict) -> List[TaintPath]:
    """Extract complete taint paths from SARIF 2.1.0 codeFlows/threadFlows structure."""
    taint_paths = []
    path_counter = 0

    for run in sarif_data.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            message = result.get("message", {}).get("text", "")

            code_flows = result.get("codeFlows", [])

            if not code_flows:
                primary_locs = result.get("locations", [])
                related = result.get("relatedLocations", [])
                if primary_locs and related:
                    sink_node = _parse_location_node(primary_locs[0])
                    source_node = _parse_location_node(related[0])
                    if sink_node and source_node:
                        path_counter += 1
                        taint_paths.append(TaintPath(
                            path_id=f"path_{path_counter:04d}",
                            source=source_node,
                            sink=sink_node,
                            intermediate_locations=[],
                            rule_id=rule_id,
                            message=message,
                        ))
                continue

            for code_flow in code_flows:
                thread_flows = code_flow.get("threadFlows", [])
                for thread_flow in thread_flows:
                    locations = thread_flow.get("locations", [])
                    if len(locations) < 2:
                        continue

                    path_nodes = [_parse_location_node(loc) for loc in locations]
                    path_nodes = [node for node in path_nodes if node is not None]

                    if len(path_nodes) < 2:
                        continue

                    path_counter += 1
                    path_id = f"path_{path_counter:04d}"

                    source = path_nodes[0]
                    sink = path_nodes[-1]
                    intermediate = path_nodes[1:-1] if len(path_nodes) > 2 else []

                    taint_path = TaintPath(
                        path_id=path_id,
                        source=source,
                        sink=sink,
                        intermediate_locations=intermediate,
                        rule_id=rule_id,
                        message=message
                    )
                    taint_paths.append(taint_path)

    return taint_paths


def parse_sarif(sarif_path: str, dataset_root: str,
                output_dir: str | None = None) -> dict:
    """Parse SARIF, join paths to absolute, attach enclosing-function source for
    every (file, function) appearing on any path.

    Saves each path as a separate JSON file under ``output_dir`` (defaults to
    ``{sarif_path}_paths/``) and returns a lightweight summary so the agent
    can pick paths without loading all of them into context at once.
    """
    from .path_context import find_enclosing_function

    if not os.path.exists(sarif_path):
        return {"success": False, "error": f"SARIF file not found: {sarif_path}"}

    try:
        sarif_data = load_sarif_from_file(sarif_path)
    except Exception as e:
        return {"success": False, "error": f"Failed to load SARIF: {e}"}

    try:
        taint_paths = extract_taint_paths(sarif_data)
    except Exception as e:
        return {"success": False, "error": f"Failed to extract taint paths: {e}"}

    if output_dir is None:
        output_dir = os.path.splitext(sarif_path)[0] + "_paths"
    os.makedirs(output_dir, exist_ok=True)

    def _absify(node: dict) -> dict:
        rel = node.get("file_path", "")
        if rel and not os.path.isabs(rel):
            node = dict(node)
            node["file_path"] = os.path.normpath(os.path.join(dataset_root, rel))
        return node

    index = []
    for tp in taint_paths:
        source = _absify(tp.source)
        sink = _absify(tp.sink)
        intermediates = [_absify(loc) for loc in tp.intermediate_locations]

        sources_by_key: dict = {}
        for node in [source, sink, *intermediates]:
            file_path = node.get("file_path", "")
            line = node.get("line_number", 0)
            if not file_path or not line:
                continue
            res = find_enclosing_function(file_path, line)
            if not res.get("success"):
                continue
            key = (file_path, res.get("function_name") or "")
            sources_by_key.setdefault(key, {
                "file_path": file_path,
                "function_name": res.get("function_name"),
                "function_source": res.get("source_code"),
                "start_line": res.get("start_line"),
                "end_line": res.get("end_line"),
            })

        path_obj = {
            "path_id": tp.path_id,
            "rule_id": tp.rule_id,
            "message": tp.message,
            "source": source,
            "sink": sink,
            "intermediate_locations": intermediates,
            "function_sources": list(sources_by_key.values()),
        }

        # Save individual path file
        path_file = os.path.join(output_dir, f"{tp.path_id}.json")
        with open(path_file, "w", encoding="utf-8") as f:
            json.dump(path_obj, f, ensure_ascii=False, indent=2)

        index.append({
            "path_id": tp.path_id,
            "path_file": path_file,
            "rule_id": tp.rule_id,
            "source_file": source.get("file_path", ""),
            "source_line": source.get("line_number", 0),
            "source_function": source.get("function_name"),
            "sink_file": sink.get("file_path", ""),
            "sink_line": sink.get("line_number", 0),
            "sink_function": sink.get("function_name"),
        })

    # Save index for external consumers
    index_file = os.path.join(output_dir, "_index.json")
    with open(index_file, "w", encoding="utf-8") as f:
        json.dump({"count": len(index), "paths": index}, f, ensure_ascii=False, indent=2)

    return {
        "success": True,
        "count": len(index),
        "paths_dir": output_dir,
        "index_file": index_file,
    }


def _parse_location_node(location_data: dict) -> Optional[dict]:
    """Parse a single location node from threadFlow locations.

    SARIF threadFlow location entries wrap the actual location under a `location` key:
        { "location": { "physicalLocation": {...}, "logicalLocations": [...], "message": {...} } }
    Fall back to treating the entry itself as the location for tolerance.
    """
    inner = location_data.get("location", location_data)
    physical = inner.get("physicalLocation", {})
    artifact = physical.get("artifactLocation", {})
    region = physical.get("region", {})
    logical_list = inner.get("logicalLocations", [])
    logical = logical_list[0] if logical_list else inner.get("logicalLocation", {})
    message = inner.get("message", {}).get("text") if isinstance(inner.get("message"), dict) else None

    file_path = artifact.get("uri", "")
    line_number = region.get("startLine", 0)

    if not file_path or not line_number:
        return None

    return {
        "file_path": file_path,
        "line_number": line_number,
        "function_name": logical.get("name") or logical.get("fullyQualifiedName"),
        "column": region.get("startColumn"),
        "message": message,
    }
