"""
Test cases for Step 1: parse_sarif_detailed MCP tool.

This module tests the parse_sarif_detailed function from
src/mcptools/symbolic_sanitizer.py which extracts complete taint paths
from SARIF files with codeFlows/threadFlows structure.
"""
import os
import sys
import json
import pytest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../src'))

from mcptools.symbolic_sanitizer import parse_sarif_detailed


class TestParseSarifDetailedSuccess:
    """Tests for successful parsing scenarios."""
    
    def test_parse_sarif_detailed_with_valid_sarif(self, tmp_path):
        """
        Test successful parsing of valid SARIF file with codeFlows.
        
        Expected: Returns success=True with properly formatted taint paths.
        """
        sarif_data = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "CodeQL"}},
                "results": [{
                    "ruleId": "cpp/tainted-data-flow",
                    "message": {"text": "Tainted data flow detected"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "src/vuln.c"},
                            "region": {"startLine": 50}
                        }
                    }],
                    "codeFlows": [{
                        "threadFlows": [{
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/input.c"},
                                        "region": {"startLine": 20, "startColumn": 15}
                                    },
                                    "logicalLocation": {"name": "get_user_input"}
                                },
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/processing.c"},
                                        "region": {"startLine": 35, "startColumn": 8}
                                    },
                                    "logicalLocation": {"name": "process_data"}
                                },
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/vuln.c"},
                                        "region": {"startLine": 50, "startColumn": 10}
                                    },
                                    "logicalLocation": {"name": "vulnerable_function"}
                                }
                            ]
                        }]
                    }]
                }]
            }]
        }
        
        sarif_path = tmp_path / "test.sarif"
        with open(sarif_path, 'w') as f:
            json.dump(sarif_data, f)
        
        result = parse_sarif_detailed(str(sarif_path))
        
        assert result["success"] is True
        assert result["count"] == 1
        assert len(result["paths"]) == 1
        
        path = result["paths"][0]
        assert path["path_id"] == "path_0001"
        assert path["rule_id"] == "cpp/tainted-data-flow"
        assert path["message"] == "Tainted data flow detected"
    
    def test_extract_source_sink_intermediate_locations(self, tmp_path):
        """
        Test extraction of source, sink, and intermediate locations.
        
        Expected: Source is first location, sink is last, intermediates are in between.
        """
        sarif_data = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "CodeQL"}},
                "results": [{
                    "ruleId": "cpp/buffer-overflow",
                    "message": {"text": "Buffer overflow detected"},
                    "locations": [],
                    "codeFlows": [{
                        "threadFlows": [{
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/main.c"},
                                        "region": {"startLine": 10}
                                    },
                                    "logicalLocation": {"name": "main"}
                                },
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/validate.c"},
                                        "region": {"startLine": 25}
                                    },
                                    "logicalLocation": {"name": "validate_input"}
                                },
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/copy.c"},
                                        "region": {"startLine": 40}
                                    },
                                    "logicalLocation": {"name": "copy_data"}
                                },
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/buffer.c"},
                                        "region": {"startLine": 75}
                                    },
                                    "logicalLocation": {"name": "unsafe_copy"}
                                }
                            ]
                        }]
                    }]
                }]
            }]
        }
        
        sarif_path = tmp_path / "test.sarif"
        with open(sarif_path, 'w') as f:
            json.dump(sarif_data, f)
        
        result = parse_sarif_detailed(str(sarif_path))
        
        assert result["success"] is True
        path = result["paths"][0]
        
        # Check source (first location)
        assert path["source"]["file_path"] == "src/main.c"
        assert path["source"]["line_number"] == 10
        assert path["source"]["function_name"] == "main"
        
        # Check sink (last location)
        assert path["sink"]["file_path"] == "src/buffer.c"
        assert path["sink"]["line_number"] == 75
        assert path["sink"]["function_name"] == "unsafe_copy"
        
        # Check intermediate locations (middle locations)
        assert len(path["intermediate_locations"]) == 2
        assert path["intermediate_locations"][0]["file_path"] == "src/validate.c"
        assert path["intermediate_locations"][0]["function_name"] == "validate_input"
        assert path["intermediate_locations"][1]["file_path"] == "src/copy.c"
        assert path["intermediate_locations"][1]["function_name"] == "copy_data"
    
    def test_multiple_thread_flows(self, tmp_path):
        """
        Test parsing SARIF with multiple threadFlows.
        
        Expected: Each threadFlow generates a separate taint path.
        """
        sarif_data = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "CodeQL"}},
                "results": [{
                    "ruleId": "cpp/tainted-data-flow",
                    "message": {"text": "Multiple paths"},
                    "codeFlows": [{
                        "threadFlows": [
                            {
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "src/input1.c"},
                                            "region": {"startLine": 10}
                                        }
                                    },
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "src/sink.c"},
                                            "region": {"startLine": 50}
                                        }
                                    }
                                ]
                            },
                            {
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "src/input2.c"},
                                            "region": {"startLine": 20}
                                        }
                                    },
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "src/sink.c"},
                                            "region": {"startLine": 50}
                                        }
                                    }
                                ]
                            }
                        ]
                    }]
                }]
            }]
        }
        
        sarif_path = tmp_path / "test.sarif"
        with open(sarif_path, 'w') as f:
            json.dump(sarif_data, f)
        
        result = parse_sarif_detailed(str(sarif_path))
        
        assert result["success"] is True
        assert result["count"] == 2
        assert len(result["paths"]) == 2
        assert result["paths"][0]["path_id"] == "path_0001"
        assert result["paths"][1]["path_id"] == "path_0002"
    
    def test_multiple_results(self, tmp_path):
        """
        Test parsing SARIF with multiple results.
        
        Expected: Taint paths from all results are extracted.
        """
        sarif_data = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "CodeQL"}},
                "results": [
                    {
                        "ruleId": "cpp/issue-1",
                        "message": {"text": "Issue 1"},
                        "codeFlows": [{
                            "threadFlows": [{
                                "locations": [
                                    {"physicalLocation": {"artifactLocation": {"uri": "a.c"}, "region": {"startLine": 1}}},
                                    {"physicalLocation": {"artifactLocation": {"uri": "b.c"}, "region": {"startLine": 2}}}
                                ]
                            }]
                        }]
                    },
                    {
                        "ruleId": "cpp/issue-2",
                        "message": {"text": "Issue 2"},
                        "codeFlows": [{
                            "threadFlows": [{
                                "locations": [
                                    {"physicalLocation": {"artifactLocation": {"uri": "c.c"}, "region": {"startLine": 3}}},
                                    {"physicalLocation": {"artifactLocation": {"uri": "d.c"}, "region": {"startLine": 4}}}
                                ]
                            }]
                        }]
                    }
                ]
            }]
        }
        
        sarif_path = tmp_path / "test.sarif"
        with open(sarif_path, 'w') as f:
            json.dump(sarif_data, f)
        
        result = parse_sarif_detailed(str(sarif_path))
        
        assert result["success"] is True
        assert result["count"] == 2
        assert result["paths"][0]["rule_id"] == "cpp/issue-1"
        assert result["paths"][1]["rule_id"] == "cpp/issue-2"
    
    def test_parse_sample_sarif_file(self):
        """
        Test parsing the sample.sarif fixture file.
        
        Expected: Successfully parses the realistic SARIF structure.
        """
        fixture_path = Path(__file__).parent / "fixtures" / "sample.sarif"
        
        if not fixture_path.exists():
            pytest.skip("sample.sarif fixture not found")
        
        result = parse_sarif_detailed(str(fixture_path))
        
        assert result["success"] is True
        assert result["count"] >= 3
        
        # Check first path structure
        first_path = result["paths"][0]
        assert "path_id" in first_path
        assert "source" in first_path
        assert "sink" in first_path
        assert "intermediate_locations" in first_path
        assert "rule_id" in first_path
        assert "message" in first_path
        
        # Verify source/sink have expected fields
        assert "file_path" in first_path["source"]
        assert "line_number" in first_path["source"]
        assert "file_path" in first_path["sink"]
        assert "line_number" in first_path["sink"]


class TestParseSarifDetailedErrorHandling:
    """Tests for error handling scenarios."""
    
    def test_missing_file_returns_error(self):
        """
        Test handling of non-existent SARIF file.
        
        Expected: Returns success=False with appropriate error message.
        """
        result = parse_sarif_detailed("/nonexistent/path/to/file.sarif")
        
        assert result["success"] is False
        assert "error" in result
        assert "not found" in result["error"].lower()
    
    def test_invalid_json_returns_error(self, tmp_path):
        """
        Test handling of invalid JSON in SARIF file.
        
        Expected: Returns success=False with JSON decode error message.
        """
        sarif_path = tmp_path / "invalid.sarif"
        with open(sarif_path, 'w') as f:
            f.write('{"version": "2.1.0", "runs": [}')
        
        result = parse_sarif_detailed(str(sarif_path))
        
        assert result["success"] is False
        assert "error" in result
        assert "json" in result["error"].lower()
    
    def test_empty_results_returns_success_with_zero_count(self, tmp_path):
        """
        Test handling of SARIF with empty results array.
        
        Expected: Returns success=True with count=0 and empty paths array.
        """
        sarif_data = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "CodeQL"}},
                "results": []
            }]
        }
        
        sarif_path = tmp_path / "empty.sarif"
        with open(sarif_path, 'w') as f:
            json.dump(sarif_data, f)
        
        result = parse_sarif_detailed(str(sarif_path))
        
        assert result["success"] is True
        assert result["count"] == 0
        assert result["paths"] == []
    
    def test_no_runs_returns_success_with_zero_count(self, tmp_path):
        """
        Test handling of SARIF with no runs.
        
        Expected: Returns success=True with count=0.
        """
        sarif_data = {
            "version": "2.1.0",
            "runs": []
        }
        
        sarif_path = tmp_path / "no_runs.sarif"
        with open(sarif_path, 'w') as f:
            json.dump(sarif_data, f)
        
        result = parse_sarif_detailed(str(sarif_path))
        
        assert result["success"] is True
        assert result["count"] == 0
        assert result["paths"] == []
    
    def test_no_codeflows_skips_result(self, tmp_path):
        """
        Test handling of results without codeFlows.
        
        Expected: Results without codeFlows are skipped, but parsing succeeds.
        """
        sarif_data = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "CodeQL"}},
                "results": [{
                    "ruleId": "cpp/simple-issue",
                    "message": {"text": "Simple issue without taint flow"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "src/simple.c"},
                            "region": {"startLine": 15}
                        }
                    }]
                }]
            }]
        }
        
        sarif_path = tmp_path / "no_codeflows.sarif"
        with open(sarif_path, 'w') as f:
            json.dump(sarif_data, f)
        
        result = parse_sarif_detailed(str(sarif_path))
        
        assert result["success"] is True
        assert result["count"] == 0
        assert result["paths"] == []
    
    def test_single_location_threadflow_skipped(self, tmp_path):
        """
        Test handling of threadFlows with single location.
        
        Expected: ThreadFlows with fewer than 2 locations are skipped.
        """
        sarif_data = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "CodeQL"}},
                "results": [{
                    "ruleId": "cpp/tainted-data-flow",
                    "message": {"text": "Test"},
                    "codeFlows": [{
                        "threadFlows": [{
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/single.c"},
                                        "region": {"startLine": 10}
                                    }
                                }
                            ]
                        }]
                    }]
                }]
            }]
        }
        
        sarif_path = tmp_path / "single_location.sarif"
        with open(sarif_path, 'w') as f:
            json.dump(sarif_data, f)
        
        result = parse_sarif_detailed(str(sarif_path))
        
        assert result["success"] is True
        assert result["count"] == 0
    
    def test_empty_threadflow_locations_skipped(self, tmp_path):
        """
        Test handling of threadFlows with empty locations.
        
        Expected: Empty threadFlows are skipped.
        """
        sarif_data = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "CodeQL"}},
                "results": [{
                    "ruleId": "cpp/test",
                    "message": {"text": "Test"},
                    "codeFlows": [{
                        "threadFlows": [{
                            "locations": []
                        }]
                    }]
                }]
            }]
        }
        
        sarif_path = tmp_path / "empty_threadflow.sarif"
        with open(sarif_path, 'w') as f:
            json.dump(sarif_data, f)
        
        result = parse_sarif_detailed(str(sarif_path))
        
        assert result["success"] is True
        assert result["count"] == 0


class TestParseSarifDetailedDataFormat:
    """Tests for verifying output data format."""
    
    def test_output_format_consistency(self, tmp_path):
        """
        Test that output format matches expected structure.
        
        Expected: All fields present with correct types.
        """
        sarif_data = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "CodeQL"}},
                "results": [{
                    "ruleId": "cpp/test",
                    "message": {"text": "Test message"},
                    "codeFlows": [{
                        "threadFlows": [{
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/a.c"},
                                        "region": {"startLine": 10, "startColumn": 5}
                                    },
                                    "logicalLocation": {"name": "func_a"}
                                },
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/b.c"},
                                        "region": {"startLine": 20, "startColumn": 15}
                                    },
                                    "logicalLocation": {"name": "func_b"}
                                }
                            ]
                        }]
                    }]
                }]
            }]
        }
        
        sarif_path = tmp_path / "format_test.sarif"
        with open(sarif_path, 'w') as f:
            json.dump(sarif_data, f)
        
        result = parse_sarif_detailed(str(sarif_path))
        
        assert isinstance(result["success"], bool)
        assert isinstance(result["count"], int)
        assert isinstance(result["paths"], list)
        
        if result["count"] > 0:
            path = result["paths"][0]
            assert isinstance(path["path_id"], str)
            assert isinstance(path["rule_id"], str)
            assert isinstance(path["message"], str)
            assert isinstance(path["source"], dict)
            assert isinstance(path["sink"], dict)
            assert isinstance(path["intermediate_locations"], list)
            
            # Check location structure
            for loc in [path["source"], path["sink"]]:
                assert "file_path" in loc
                assert "line_number" in loc
                assert "function_name" in loc
                assert "column" in loc
    
    def test_path_id_format(self, tmp_path):
        """
        Test that path IDs follow expected format (path_XXXX).
        
        Expected: Sequential IDs with leading zeros.
        """
        sarif_data = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "CodeQL"}},
                "results": [
                    {
                        "ruleId": "cpp/test",
                        "message": {"text": "Test"},
                        "codeFlows": [{
                            "threadFlows": [{
                                "locations": [
                                    {"physicalLocation": {"artifactLocation": {"uri": "a.c"}, "region": {"startLine": 1}}},
                                    {"physicalLocation": {"artifactLocation": {"uri": "b.c"}, "region": {"startLine": 2}}}
                                ]
                            }]
                        }]
                    },
                    {
                        "ruleId": "cpp/test2",
                        "message": {"text": "Test2"},
                        "codeFlows": [{
                            "threadFlows": [{
                                "locations": [
                                    {"physicalLocation": {"artifactLocation": {"uri": "c.c"}, "region": {"startLine": 3}}},
                                    {"physicalLocation": {"artifactLocation": {"uri": "d.c"}, "region": {"startLine": 4}}}
                                ]
                            }]
                        }]
                    }
                ]
            }]
        }
        
        sarif_path = tmp_path / "path_id_test.sarif"
        with open(sarif_path, 'w') as f:
            json.dump(sarif_data, f)
        
        result = parse_sarif_detailed(str(sarif_path))
        
        assert result["paths"][0]["path_id"] == "path_0001"
        assert result["paths"][1]["path_id"] == "path_0002"
