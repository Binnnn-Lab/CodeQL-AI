"""
SARIF Parser — extract taint paths from CodeQL SARIF results.
"""

import json
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
