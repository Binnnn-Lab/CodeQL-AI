"""
Shared pytest fixtures for symbolic_sanitizer tests.
"""
import os
import sys
import json
import pytest
from pathlib import Path
from typing import Dict, Any, List


sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../src'))


@pytest.fixture
def sample_sarif_data() -> Dict[str, Any]:
    """
    Return a mock SARIF data structure with codeFlows and threadFlows.
    
    This represents a typical SARIF 2.1.0 output from CodeQL with taint flow analysis.
    """
    return {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "semanticVersion": "2.15.0"
                    }
                },
                "results": [
                    {
                        "ruleId": "cpp/tainted-data-flow",
                        "message": {
                            "text": "Tainted data reaches vulnerable sink"
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": "src/vuln.c"
                                    },
                                    "region": {
                                        "startLine": 50,
                                        "startColumn": 10
                                    }
                                },
                                "logicalLocation": {
                                    "name": "vulnerable_function"
                                }
                            }
                        ],
                        "codeFlows": [
                            {
                                "threadFlows": [
                                    {
                                        "locations": [
                                            {
                                                "physicalLocation": {
                                                    "artifactLocation": {
                                                        "uri": "src/input.c"
                                                    },
                                                    "region": {
                                                        "startLine": 20,
                                                        "startColumn": 15
                                                    }
                                                },
                                                "logicalLocation": {
                                                    "name": "get_user_input"
                                                }
                                            },
                                            {
                                                "physicalLocation": {
                                                    "artifactLocation": {
                                                        "uri": "src/processing.c"
                                                    },
                                                    "region": {
                                                        "startLine": 35,
                                                        "startColumn": 8
                                                    }
                                                },
                                                "logicalLocation": {
                                                    "name": "process_data"
                                                }
                                            },
                                            {
                                                "physicalLocation": {
                                                    "artifactLocation": {
                                                        "uri": "src/vuln.c"
                                                    },
                                                    "region": {
                                                        "startLine": 50,
                                                        "startColumn": 10
                                                    }
                                                },
                                                "logicalLocation": {
                                                    "name": "vulnerable_function"
                                                }
                                            }
                                        ]
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "ruleId": "cpp/buffer-overflow",
                        "message": {
                            "text": "Buffer overflow vulnerability detected"
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": "src/buffer.c"
                                    },
                                    "region": {
                                        "startLine": 75,
                                        "startColumn": 5
                                    }
                                },
                                "logicalLocation": {
                                    "name": "unsafe_copy"
                                }
                            }
                        ],
                        "codeFlows": [
                            {
                                "threadFlows": [
                                    {
                                        "locations": [
                                            {
                                                "physicalLocation": {
                                                    "artifactLocation": {
                                                        "uri": "src/main.c"
                                                    },
                                                    "region": {
                                                        "startLine": 10,
                                                        "startColumn": 20
                                                    }
                                                },
                                                "logicalLocation": {
                                                    "name": "main"
                                                }
                                            },
                                            {
                                                "physicalLocation": {
                                                    "artifactLocation": {
                                                        "uri": "src/buffer.c"
                                                    },
                                                    "region": {
                                                        "startLine": 75,
                                                        "startColumn": 5
                                                    }
                                                },
                                                "logicalLocation": {
                                                    "name": "unsafe_copy"
                                                }
                                            }
                                        ]
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }
        ]
    }


@pytest.fixture
def sample_sarif_no_codeflows() -> Dict[str, Any]:
    """Return SARIF data without codeFlows (for testing edge cases)."""
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "semanticVersion": "2.15.0"
                    }
                },
                "results": [
                    {
                        "ruleId": "cpp/simple-issue",
                        "message": {
                            "text": "Simple issue without taint flow"
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": "src/simple.c"
                                    },
                                    "region": {
                                        "startLine": 15
                                    }
                                }
                            }
                        ]
                    }
                ]
            }
        ]
    }


@pytest.fixture
def sample_sarif_empty_results() -> Dict[str, Any]:
    """Return SARIF data with empty results array."""
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeQL"
                    }
                },
                "results": []
            }
        ]
    }


@pytest.fixture
def sample_sarif_no_runs() -> Dict[str, Any]:
    """Return SARIF data with no runs."""
    return {
        "version": "2.1.0",
        "runs": []
    }


@pytest.fixture
def invalid_sarif_data() -> str:
    """Return invalid JSON string for testing error handling."""
    return '{"version": "2.1.0", "runs": [}'


@pytest.fixture
def sample_taint_json() -> Dict[str, Any]:
    """
    Return a sample taint_json structure for Step 2.
    
    Format expected by find_potential_functions MCP tool.
    """
    return {
        "source": {
            "source_file_path": "src/input.c",
            "source_start_line": 20,
            "source_target_name": "get_user_input"
        },
        "sink": {
            "sink_file_path": "src/vuln.c",
            "sink_start_line": 50,
            "sink_target_name": "memcpy"
        }
    }


@pytest.fixture
def sample_taint_json_buffer_overflow() -> Dict[str, Any]:
    """Return another sample taint_json structure."""
    return {
        "source": {
            "source_file_path": "src/main.c",
            "source_start_line": 10,
            "source_target_name": "fgets"
        },
        "sink": {
            "sink_file_path": "src/buffer.c",
            "sink_start_line": 75,
            "sink_target_name": "strcpy"
        }
    }


@pytest.fixture
def temp_sarif_file(tmp_path):
    """
    Create a temporary SARIF file and return its path.
    
    Usage:
        def test_something(temp_sarif_file):
            sarif_path = temp_sarif_file(sample_sarif_data)
            # Use sarif_path...
    """
    def _create_sarif_file(sarif_data: Dict[str, Any]) -> Path:
        sarif_path = tmp_path / "test.sarif"
        with open(sarif_path, 'w', encoding='utf-8') as f:
            json.dump(sarif_data, f, indent=2)
        return sarif_path
    return _create_sarif_file


@pytest.fixture
def mock_taint_analysis_result() -> Dict[str, Any]:
    """
    Return mock result from run_taint_analysis function.
    
    This represents the successful output from find_potential_functions.
    """
    return {
        "success": True,
        "potential_sanitizer_functions": [
            "validate_input",
            "sanitize_data",
            "check_bounds"
        ],
        "sarif_path": "/tmp/find_potential_functions_1234567890.sarif",
        "tmp_ql_path": "/path/to/find_potential_functions.ql",
        "command": "codeql database analyze --rerun /db /path/to/find_potential_functions.ql --format=sarif-latest --output=/tmp/find_potential_functions_1234567890.sarif",
        "message": "CodeQL 污点分析完成，结果保存至: /tmp/find_potential_functions_1234567890.sarif"
    }


@pytest.fixture
def mock_taint_analysis_no_functions() -> Dict[str, Any]:
    """Return mock result when no potential functions are found."""
    return {
        "success": True,
        "potential_sanitizer_functions": [],
        "sarif_path": "/tmp/find_potential_functions_1234567890.sarif",
        "tmp_ql_path": "/path/to/find_potential_functions.ql",
        "command": "codeql database analyze --rerun /db /path/to/find_potential_functions.ql",
        "message": "CodeQL 污点分析完成，结果保存至: /tmp/find_potential_functions_1234567890.sarif"
    }


@pytest.fixture
def mock_taint_analysis_failure() -> Dict[str, Any]:
    """Return mock result when taint analysis fails."""
    return {
        "success": False,
        "error": "CodeQL 分析失败: Database not found",
        "command": "codeql database analyze --rerun /invalid/db /path/to/find_potential_functions.ql"
    }
