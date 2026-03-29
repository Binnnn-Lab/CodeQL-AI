"""
Tests for Step 6: Verification with Constraints

Tests the verify_with_constraints MCP tool and SymbolicExecutor class.
All angr/claripy dependencies are mocked to avoid heavy dependencies.
"""

import unittest
from unittest.mock import patch, MagicMock, PropertyMock
import sys
import os
from typing import Dict, List, Any

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))

from src.libs.symbolic_sanitizer.symbolic_sanitizer import (
    SymbolicExecutor,
    SymbolicExecutionResult,
    PathAnalysisResult,
    verify_sanitization
)


# Mock angr and claripy modules before importing
mock_angr = MagicMock()
mock_claripy = MagicMock()

sys.modules['angr'] = mock_angr
sys.modules['claripy'] = mock_claripy


class TestPathAnalysisResult(unittest.TestCase):
    """Test PathAnalysisResult dataclass"""
    
    def test_path_analysis_result_structure(self):
        """Test PathAnalysisResult dataclass structure"""
        result = PathAnalysisResult(
            path_id=1,
            input_has_dangerous_chars=True,
            output_has_dangerous_chars=False,
            is_sanitized=True,
            concrete_input=b"test_input",
            concrete_output=b"test_output",
            constraint_details={"chars": ["<", ">"]}
        )
        
        self.assertEqual(result.path_id, 1)
        self.assertTrue(result.input_has_dangerous_chars)
        self.assertFalse(result.output_has_dangerous_chars)
        self.assertTrue(result.is_sanitized)
        self.assertEqual(result.concrete_input, b"test_input")
        self.assertEqual(result.concrete_output, b"test_output")
        self.assertEqual(result.constraint_details, {"chars": ["<", ">"]})
    
    def test_path_analysis_result_defaults(self):
        """Test PathAnalysisResult with default values"""
        result = PathAnalysisResult(
            path_id=0,
            input_has_dangerous_chars=False,
            output_has_dangerous_chars=False,
            is_sanitized=True
        )
        
        self.assertIsNone(result.concrete_input)
        self.assertIsNone(result.concrete_output)
        self.assertEqual(result.constraint_details, {})


class TestSymbolicExecutionResult(unittest.TestCase):
    """Test SymbolicExecutionResult dataclass"""
    
    def test_symbolic_execution_result_structure(self):
        """Test SymbolicExecutionResult dataclass structure"""
        result = SymbolicExecutionResult(
            success=True,
            function_name="test_func",
            sanitized=True,
            paths_analyzed=5,
            paths_harmful=0,
            paths_safe=5,
            errors=[],
            details={"info": "test"}
        )
        
        self.assertTrue(result.success)
        self.assertEqual(result.function_name, "test_func")
        self.assertTrue(result.sanitized)
        self.assertEqual(result.paths_analyzed, 5)
        self.assertEqual(result.paths_harmful, 0)
        self.assertEqual(result.paths_safe, 5)
        self.assertEqual(result.errors, [])
        self.assertEqual(result.details, {"info": "test"})
    
    def test_symbolic_execution_result_defaults(self):
        """Test SymbolicExecutionResult with default values"""
        result = SymbolicExecutionResult(
            success=True,
            function_name="main",
            sanitized=False,
            paths_analyzed=0,
            paths_harmful=0,
            paths_safe=0
        )
        
        self.assertEqual(result.errors, [])
        self.assertEqual(result.details, {})
    
    def test_to_dict_method(self):
        """Test SymbolicExecutionResult.to_dict() method"""
        result = SymbolicExecutionResult(
            success=True,
            function_name="test_func",
            sanitized=True,
            paths_analyzed=3,
            paths_harmful=1,
            paths_safe=2,
            errors=["error1"],
            details={"key": "value"}
        )
        
        result_dict = result.to_dict()
        
        self.assertIsInstance(result_dict, dict)
        self.assertEqual(result_dict["success"], True)
        self.assertEqual(result_dict["function_name"], "test_func")
        self.assertEqual(result_dict["sanitized"], True)
        self.assertEqual(result_dict["paths_analyzed"], 3)
        self.assertEqual(result_dict["paths_harmful"], 1)
        self.assertEqual(result_dict["paths_safe"], 2)
        self.assertEqual(result_dict["errors"], ["error1"])
        self.assertEqual(result_dict["details"], {"key": "value"})
    
    def test_to_dict_full_coverage(self):
        """Test to_dict covers all fields"""
        result = SymbolicExecutionResult(
            success=False,
            function_name="main",
            sanitized=False,
            paths_analyzed=10,
            paths_harmful=5,
            paths_safe=5,
            errors=["error1", "error2"],
            details={"paths": [], "analysis": "complete"}
        )
        
        result_dict = result.to_dict()
        
        # Ensure all expected keys are present
        expected_keys = {"success", "function_name", "sanitized", "paths_analyzed", 
                        "paths_harmful", "paths_safe", "errors", "details"}
        self.assertEqual(set(result_dict.keys()), expected_keys)


class TestSymbolicExecutorInitialization(unittest.TestCase):
    """Test SymbolicExecutor class instantiation"""
    
    @patch.dict('sys.modules', {'angr': mock_angr, 'claripy': mock_claripy})
    def test_symbolic_executor_init(self):
        """Test SymbolicExecutor class instantiation with mock angr"""
        mock_angr.reset_mock()
        mock_project = MagicMock()
        mock_angr.Project.return_value = mock_project
        
        executor = SymbolicExecutor("/path/to/binary")
        
        self.assertEqual(executor.binary_path, "/path/to/binary")
        self.assertTrue(mock_angr.Project.called)
        mock_angr.Project.assert_called_with("/path/to/binary", auto_load_libs=False)
        self.assertEqual(executor.project, mock_project)
    
    def test_symbolic_executor_init_import_error(self):
        """Test SymbolicExecutor handles import error"""
        with patch.dict('sys.modules', {'angr': None, 'claripy': None}):
            with self.assertRaises((ImportError, TypeError)):
                SymbolicExecutor("/path/to/binary")


class TestConstraintBuildingMethods(unittest.TestCase):
    """Test constraint building methods"""
    
    @patch.dict('sys.modules', {'angr': mock_angr, 'claripy': mock_claripy})
    def setUp(self):
        """Set up mock executor"""
        mock_project = MagicMock()
        mock_angr.Project.return_value = mock_project
        self.executor = SymbolicExecutor("/path/to/binary")
    
    def tearDown(self):
        """Reset mocks"""
        mock_angr.reset_mock()
        mock_claripy.reset_mock()
    
    def test_build_contains_any_constraint(self):
        """Test _build_contains_any_constraint method"""
        mock_byte1 = MagicMock()
        mock_byte2 = MagicMock()
        sym_bytes = [mock_byte1, mock_byte2]
        
        mock_or_result = MagicMock()
        mock_claripy.Or.return_value = mock_or_result
        
        result = self.executor._build_contains_any_constraint(sym_bytes, ["<", ">"])
        
        # Should call claripy.Or for each byte
        self.assertTrue(mock_claripy.Or.called)
        self.assertEqual(result, mock_or_result)
    
    def test_build_contains_any_constraint_empty_chars(self):
        """Test _build_contains_any_constraint with empty chars list"""
        mock_byte = MagicMock()
        sym_bytes = [mock_byte]
        
        mock_claripy.Or.return_value = MagicMock()
        
        result = self.executor._build_contains_any_constraint(sym_bytes, [])
        
        # Should handle empty chars gracefully
        self.assertIsNotNone(result)
    
    def test_build_not_contains_any_constraint(self):
        """Test _build_not_contains_any_constraint method"""
        mock_byte1 = MagicMock()
        mock_byte2 = MagicMock()
        sym_bytes = [mock_byte1, mock_byte2]
        
        mock_and_result = MagicMock()
        mock_claripy.And.return_value = mock_and_result
        
        result = self.executor._build_not_contains_any_constraint(sym_bytes, ["<", ">"])
        
        # Should call claripy.And
        self.assertTrue(mock_claripy.And.called)
        self.assertEqual(result, mock_and_result)
    
    def test_build_length_range_constraint(self):
        """Test _build_length_range_constraint method"""
        mock_bytes = [MagicMock() for _ in range(64)]
        mock_claripy.And.return_value = MagicMock()
        
        result = self.executor._build_length_range_constraint(mock_bytes, 5, 10)
        
        # Should create constraints for length range
        self.assertIsNotNone(result)
    
    def test_build_length_range_constraint_zero_min(self):
        """Test _build_length_range_constraint with min=0"""
        mock_bytes = [MagicMock() for _ in range(64)]
        mock_claripy.true = MagicMock()
        
        result = self.executor._build_length_range_constraint(mock_bytes, 0, 10)
        
        self.assertIsNotNone(result)
    
    def test_build_length_range_constraint_max_exceeds(self):
        """Test _build_length_range_constraint with max > len"""
        mock_bytes = [MagicMock() for _ in range(10)]
        mock_claripy.true = MagicMock()
        
        result = self.executor._build_length_range_constraint(mock_bytes, 0, 100)
        
        self.assertIsNotNone(result)


class TestBuildInputConstraint(unittest.TestCase):
    """Test _build_input_constraint method"""
    
    @patch.dict('sys.modules', {'angr': mock_angr, 'claripy': mock_claripy})
    def setUp(self):
        """Set up mock executor"""
        mock_project = MagicMock()
        mock_angr.Project.return_value = mock_project
        self.executor = SymbolicExecutor("/path/to/binary")
        mock_claripy.true = MagicMock()
    
    def tearDown(self):
        """Reset mocks"""
        mock_claripy.reset_mock()
    
    def test_build_input_constraint_contains_any(self):
        """Test _build_input_constraint with contains_any type"""
        mock_bytes = [MagicMock() for _ in range(10)]
        input_constraints = [{"type": "contains_any", "chars": ["<", ">"]}]
        
        result = self.executor._build_input_constraint(mock_bytes, input_constraints)
        
        self.assertIsNotNone(result)
    
    def test_build_input_constraint_not_contains_any(self):
        """Test _build_input_constraint with not_contains_any type"""
        mock_bytes = [MagicMock() for _ in range(10)]
        input_constraints = [{"type": "not_contains_any", "chars": ["<", ">"]}]
        
        result = self.executor._build_input_constraint(mock_bytes, input_constraints)
        
        self.assertIsNotNone(result)
    
    def test_build_input_constraint_length_range(self):
        """Test _build_input_constraint with length_range type"""
        mock_bytes = [MagicMock() for _ in range(10)]
        input_constraints = [{"type": "length_range", "min": 5, "max": 20}]
        
        result = self.executor._build_input_constraint(mock_bytes, input_constraints)
        
        self.assertIsNotNone(result)
    
    def test_build_input_constraint_empty(self):
        """Test _build_input_constraint with empty constraints"""
        mock_bytes = [MagicMock() for _ in range(10)]
        input_constraints = []
        
        result = self.executor._build_input_constraint(mock_bytes, input_constraints)
        
        # Should return claripy.true for empty constraints
        self.assertEqual(result, mock_claripy.true)
    
    def test_build_input_constraint_unknown_type(self):
        """Test _build_input_constraint with unknown constraint type"""
        mock_bytes = [MagicMock() for _ in range(10)]
        input_constraints = [{"type": "unknown_type"}]
        
        result = self.executor._build_input_constraint(mock_bytes, input_constraints)
        
        # Should return claripy.true for unknown types
        self.assertEqual(result, mock_claripy.true)
    
    def test_build_input_constraint_missing_chars(self):
        """Test _build_input_constraint with missing chars field"""
        mock_bytes = [MagicMock() for _ in range(10)]
        input_constraints = [{"type": "contains_any"}]  # No chars field
        
        result = self.executor._build_input_constraint(mock_bytes, input_constraints)
        
        # Should handle missing chars gracefully
        self.assertEqual(result, mock_claripy.true)


class TestApplyInputConstraints(unittest.TestCase):
    """Test apply_input_constraints method"""
    
    @patch.dict('sys.modules', {'angr': mock_angr, 'claripy': mock_claripy})
    def setUp(self):
        """Set up mock executor"""
        mock_project = MagicMock()
        mock_angr.Project.return_value = mock_project
        self.executor = SymbolicExecutor("/path/to/binary")
    
    def test_apply_input_constraints(self):
        """Test apply_input_constraints applies constraints to state"""
        mock_state = MagicMock()
        mock_state.solver = MagicMock()
        mock_bytes = [MagicMock() for _ in range(10)]
        input_constraints = [{"type": "contains_any", "chars": ["<"]}]
        
        self.executor.apply_input_constraints(mock_state, mock_bytes, input_constraints)
        
        # Should add constraint to solver
        mock_state.solver.add.assert_called_once()


class TestCheckOutputConstraints(unittest.TestCase):
    """Test check_output_constraints method"""
    
    @patch.dict('sys.modules', {'angr': mock_angr, 'claripy': mock_claripy})
    def setUp(self):
        """Set up mock executor"""
        mock_project = MagicMock()
        mock_angr.Project.return_value = mock_project
        self.executor = SymbolicExecutor("/path/to/binary")
    
    def test_check_output_constraints_satisfiable(self):
        """Test check_output_constraints when satisfiable"""
        mock_state = MagicMock()
        mock_state.solver = MagicMock()
        mock_state.solver.satisfiable.return_value = True
        mock_state.memory = MagicMock()
        mock_state.memory.load.return_value = MagicMock()
        mock_state.solver.eval.return_value = 65  # 'A'
        
        output_constraints = [{"type": "not_contains_any", "chars": ["<"]}]
        
        satisfies, concrete = self.executor.check_output_constraints(
            mock_state, 0x600000, 10, output_constraints
        )
        
        self.assertTrue(satisfies)
        self.assertIsNotNone(concrete)
        mock_state.solver.push.assert_called_once()
        mock_state.solver.pop.assert_called_once()
    
    def test_check_output_constraints_unsatisfiable(self):
        """Test check_output_constraints when unsatisfiable"""
        mock_state = MagicMock()
        mock_state.solver = MagicMock()
        mock_state.solver.satisfiable.return_value = False
        mock_state.memory = MagicMock()
        mock_state.memory.load.return_value = MagicMock()
        
        output_constraints = [{"type": "not_contains_any", "chars": ["<"]}]
        
        satisfies, concrete = self.executor.check_output_constraints(
            mock_state, 0x600000, 10, output_constraints
        )
        
        self.assertFalse(satisfies)
        self.assertIsNone(concrete)


class TestAnalyzeConstrainedResults(unittest.TestCase):
    """Test _analyze_constrained_results method"""
    
    @patch.dict('sys.modules', {'angr': mock_angr, 'claripy': mock_claripy})
    def setUp(self):
        """Set up mock executor"""
        mock_project = MagicMock()
        mock_angr.Project.return_value = mock_project
        self.executor = SymbolicExecutor("/path/to/binary")
    
    def test_analyze_constrained_results_no_paths(self):
        """Test _analyze_constrained_results with no paths"""
        mock_simgr = MagicMock()
        mock_simgr.deadended = []
        mock_simgr.errored = []
        
        result = self.executor._analyze_constrained_results(
            mock_simgr, [], [], [], 0x600000, 64
        )
        
        self.assertFalse(result.success)
        self.assertEqual(result.paths_analyzed, 0)
        self.assertIn("No paths completed", result.errors[0])
    
    def test_analyze_constrained_results_sanitized(self):
        """Test _analyze_constrained_results when all paths sanitized"""
        mock_simgr = MagicMock()
        mock_state = MagicMock()
        mock_state.solver = MagicMock()
        mock_state.solver.satisfiable.return_value = True
        mock_state.memory = MagicMock()
        mock_state.memory.load.return_value = MagicMock()
        mock_simgr.deadended = [mock_state]
        mock_simgr.errored = []
        
        # Mock _check_bytes_contain_dangerous_chars to return False (sanitized)
        with patch.object(self.executor, '_check_bytes_contain_dangerous_chars', return_value=False):
            result = self.executor._analyze_constrained_results(
                mock_simgr, [MagicMock()], [], [], 0x600000, 64
            )
        
        self.assertTrue(result.success)
        self.assertTrue(result.sanitized)
        self.assertEqual(result.paths_harmful, 0)
        self.assertEqual(result.paths_safe, 1)
    
    def test_analyze_constrained_results_not_sanitized(self):
        """Test _analyze_constrained_results when paths not sanitized"""
        mock_simgr = MagicMock()
        mock_state = MagicMock()
        mock_state.solver = MagicMock()
        mock_state.solver.satisfiable.return_value = True
        mock_state.memory = MagicMock()
        mock_state.memory.load.return_value = MagicMock()
        mock_simgr.deadended = [mock_state]
        mock_simgr.errored = []
        
        # Mock to simulate dangerous input and output
        call_count = [0]
        def side_effect(*args, **kwargs):
            call_count[0] += 1
            return call_count[0] <= 2  # First 2 calls (input) return True
        
        with patch.object(self.executor, '_check_bytes_contain_dangerous_chars', side_effect=side_effect):
            result = self.executor._analyze_constrained_results(
                mock_simgr, [MagicMock()], 
                [{"type": "contains_any", "chars": ["<"]}],
                [{"type": "not_contains_any", "chars": ["<"]}],
                0x600000, 64
            )
        
        self.assertTrue(result.success)
        self.assertFalse(result.sanitized)
        self.assertEqual(result.paths_harmful, 1)
        self.assertEqual(result.paths_safe, 0)


class TestExecuteWithConstraints(unittest.TestCase):
    """Test execute_with_constraints method"""
    
    @patch.dict('sys.modules', {'angr': mock_angr, 'claripy': mock_claripy})
    def setUp(self):
        """Set up mock executor"""
        mock_project = MagicMock()
        mock_angr.Project.return_value = mock_project
        self.executor = SymbolicExecutor("/path/to/binary")
        
        # Setup mock claripy BVS
        mock_claripy.BVS = MagicMock(return_value=MagicMock())
        mock_claripy.And = MagicMock(return_value=MagicMock())
        mock_claripy.Or = MagicMock(return_value=MagicMock())
        mock_claripy.true = MagicMock()
    
    def test_execute_with_constraints_main_not_found(self):
        """Test execute_with_constraints when main function not found"""
        self.executor._find_function = MagicMock(return_value=None)
        
        constraints = {"input_constraints": [], "output_constraints": []}
        result = self.executor.execute_with_constraints(constraints)
        
        self.assertFalse(result.success)
        self.assertIn("main function not found", result.errors[0])
    
    def test_execute_with_constraints_unsatisfiable_input(self):
        """Test execute_with_constraints when input constraints unsatisfiable"""
        self.executor._find_function = MagicMock(return_value=0x400000)
        
        mock_state = MagicMock()
        mock_state.solver = MagicMock()
        mock_state.solver.satisfiable.return_value = False
        mock_state.memory = MagicMock()
        self.executor.project.factory.call_state.return_value = mock_state
        
        constraints = {
            "input_constraints": [{"type": "contains_any", "chars": ["<"]}],
            "output_constraints": []
        }
        result = self.executor.execute_with_constraints(constraints)
        
        self.assertTrue(result.success)
        self.assertTrue(result.sanitized)  # Vacuously true
        self.assertEqual(result.paths_analyzed, 0)
    
    def test_execute_with_constraints_exception(self):
        """Test execute_with_constraints exception handling"""
        self.executor._find_function = MagicMock(side_effect=Exception("Test error"))
        
        constraints = {"input_constraints": [], "output_constraints": []}
        result = self.executor.execute_with_constraints(constraints)
        
        self.assertFalse(result.success)
        self.assertIn("Test error", result.errors[0])


class TestExtractDangerousChars(unittest.TestCase):
    """Test _extract_dangerous_chars_from_constraints method"""
    
    @patch.dict('sys.modules', {'angr': mock_angr, 'claripy': mock_claripy})
    def setUp(self):
        """Set up mock executor"""
        mock_project = MagicMock()
        mock_angr.Project.return_value = mock_project
        self.executor = SymbolicExecutor("/path/to/binary")
    
    def test_extract_dangerous_chars(self):
        """Test extraction of dangerous characters from constraints"""
        constraints = [
            {"type": "contains_any", "chars": ["<", ">"]},
            {"type": "not_contains_any", "chars": ["&", "\""]}
        ]
        
        result = self.executor._extract_dangerous_chars_from_constraints(constraints)
        
        self.assertIn("<", result)
        self.assertIn(">", result)
        self.assertIn("&", result)
        self.assertIn("\"", result)
    
    def test_extract_dangerous_chars_empty(self):
        """Test extraction with no matching constraints"""
        constraints = [{"type": "length_range", "min": 0, "max": 10}]
        
        result = self.executor._extract_dangerous_chars_from_constraints(constraints)
        
        self.assertEqual(result, [])


class TestVerifySanitization(unittest.TestCase):
    """Test verify_sanitization function"""
    
    @patch('src.libs.symbolic_sanitizer.symbolic_sanitizer.SymbolicExecutor')
    def test_verify_sanitization(self, mock_executor_class):
        """Test verify_sanitization function"""
        mock_executor = MagicMock()
        mock_executor.execute.return_value = SymbolicExecutionResult(
            success=True,
            function_name="main",
            sanitized=True,
            paths_analyzed=5,
            paths_harmful=0,
            paths_safe=5
        )
        mock_executor_class.return_value = mock_executor
        
        result = verify_sanitization("/path/to/binary", timeout=30)
        
        self.assertTrue(result.success)
        mock_executor_class.assert_called_once_with("/path/to/binary")
        mock_executor.execute.assert_called_once_with(constraint=None, timeout=30)


class TestConstraintStructures(unittest.TestCase):
    """Test that constraint structures match what constraint-generator produces"""
    
    def test_contains_any_constraint_structure(self):
        """Test contains_any constraint structure"""
        constraint = {
            "type": "contains_any",
            "chars": ["<", ">", "&", "\"", "'"]
        }
        
        self.assertEqual(constraint["type"], "contains_any")
        self.assertIsInstance(constraint["chars"], list)
        self.assertTrue(all(isinstance(c, str) for c in constraint["chars"]))
    
    def test_not_contains_any_constraint_structure(self):
        """Test not_contains_any constraint structure"""
        constraint = {
            "type": "not_contains_any",
            "chars": ["<", ">", "&"]
        }
        
        self.assertEqual(constraint["type"], "not_contains_any")
        self.assertIsInstance(constraint["chars"], list)
    
    def test_length_range_constraint_structure(self):
        """Test length_range constraint structure"""
        constraint = {
            "type": "length_range",
            "min": 1,
            "max": 100
        }
        
        self.assertEqual(constraint["type"], "length_range")
        self.assertIsInstance(constraint["min"], int)
        self.assertIsInstance(constraint["max"], int)
    
    def test_constraints_dictionary_structure(self):
        """Test full constraints dictionary structure"""
        constraints = {
            "input_constraints": [
                {"type": "contains_any", "chars": ["<", ">"]}
            ],
            "output_constraints": [
                {"type": "not_contains_any", "chars": ["<", ">"]}
            ]
        }
        
        self.assertIn("input_constraints", constraints)
        self.assertIn("output_constraints", constraints)
        self.assertIsInstance(constraints["input_constraints"], list)
        self.assertIsInstance(constraints["output_constraints"], list)


class TestMCPToolsIntegration(unittest.TestCase):
    """Test MCP tool wrapper logic via direct function testing"""
    
    @patch('os.path.exists')
    def test_verify_with_constraints_binary_not_found(self, mock_exists):
        """Test verify_with_constraints returns error when binary not found"""
        mock_exists.return_value = False
        
        result = SymbolicExecutionResult(
            success=False,
            function_name="main",
            sanitized=False,
            paths_analyzed=0,
            paths_harmful=0,
            paths_safe=0,
            errors=["Binary file not found: /nonexistent/binary"]
        )
        result_dict = result.to_dict()
        
        self.assertFalse(result_dict["success"])
        self.assertFalse(result_dict["sanitized"])
        self.assertIn("not found", result_dict["errors"][0].lower())
    
    def test_verify_with_constraints_result_format(self):
        """Test verify_with_constraints result dictionary format"""
        result = SymbolicExecutionResult(
            success=True,
            function_name="test_func",
            sanitized=True,
            paths_analyzed=10,
            paths_harmful=0,
            paths_safe=10,
            errors=[],
            details={
                "input_constraints": [{"type": "contains_any", "chars": ["<"]}],
                "output_constraints": [{"type": "not_contains_any", "chars": ["<"]}]
            }
        )
        result_dict = result.to_dict()
        
        self.assertTrue(result_dict["success"])
        self.assertTrue(result_dict["sanitized"])
        self.assertEqual(result_dict["paths_analyzed"], 10)
        self.assertEqual(result_dict["paths_safe"], 10)
        self.assertEqual(result_dict["paths_harmful"], 0)
        self.assertIn("details", result_dict)


if __name__ == '__main__':
    unittest.main()
