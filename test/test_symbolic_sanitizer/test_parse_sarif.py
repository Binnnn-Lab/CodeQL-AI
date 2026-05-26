import json
import os
import pytest

from libs.symbolic_sanitizer.sarif_parser import parse_sarif

FIX = os.path.join(os.path.dirname(__file__), "fixtures")


def test_parse_sarif_joins_absolute_paths(tmp_path):
    sarif = {
        "runs": [{
            "results": [{
                "ruleId": "test/rule",
                "message": {"text": "x"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "src/foo.c"},
                        "region": {"startLine": 1, "startColumn": 1},
                    }
                }],
                "relatedLocations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "src/bar.c"},
                        "region": {"startLine": 1, "startColumn": 1},
                    }
                }],
            }]
        }]
    }
    p = tmp_path / "x.sarif"
    p.write_text(json.dumps(sarif))
    result = parse_sarif(str(p), dataset_root="/tmp/ds")
    assert result["success"] is True
    assert len(result["paths"]) == 1
    path = result["paths"][0]
    assert path["source"]["file_path"] == "/tmp/ds/src/bar.c"
    assert path["sink"]["file_path"] == "/tmp/ds/src/foo.c"
    assert "function_sources" in path  # may be empty (files don't exist), key present


def test_parse_sarif_missing_file_returns_error(tmp_path):
    result = parse_sarif(str(tmp_path / "nope.sarif"), dataset_root="/tmp/ds")
    assert result["success"] is False
