"""Tests for SymbolicExecutor.execute_reachability (sink reachability via angr)."""
import os
import sys
import pytest
from unittest.mock import MagicMock, patch, PropertyMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../src'))

# Pre-inject mocks so top-level `import angr` / `import claripy` in the module
# don't fail when those packages are absent from the environment.
_mock_angr = MagicMock()
_mock_claripy = MagicMock()
sys.modules.setdefault('angr', _mock_angr)
sys.modules.setdefault('claripy', _mock_claripy)

# Import the module now (with mocks in place) so @patch can resolve the target.
import libs.symbolic_sanitizer.symbolic_sanitizer as _sym_mod
from libs.symbolic_sanitizer.symbolic_sanitizer import SymbolicExecutor


class TestExecuteReachability:
    """Test execute_reachability with mocked angr."""

    @patch('libs.symbolic_sanitizer.symbolic_sanitizer.angr')
    @patch('libs.symbolic_sanitizer.symbolic_sanitizer.claripy')
    def test_reachable_returns_true(self, mock_claripy, mock_angr):
        mock_project = MagicMock()
        mock_angr.Project.return_value = mock_project

        mock_symbol = MagicMock()
        mock_symbol.rebased_addr = 0x400000
        mock_sink_symbol = MagicMock()
        mock_sink_symbol.rebased_addr = 0x400100

        mock_input_symbol = MagicMock()
        mock_input_symbol.rebased_addr = 0x500000

        def find_symbol_side_effect(name):
            if name == "main":
                return mock_symbol
            if name == "__sink_reached":
                return mock_sink_symbol
            if name == "symbolic_input":
                return mock_input_symbol
            return None
        mock_project.loader.find_symbol.side_effect = find_symbol_side_effect

        mock_state = MagicMock()
        mock_state.solver.satisfiable.return_value = True
        mock_project.factory.call_state.return_value = mock_state

        mock_simgr = MagicMock()
        found_state = MagicMock()
        found_state.solver.eval.return_value = 0x41
        mock_simgr.found = [found_state]
        mock_project.factory.simgr.return_value = mock_simgr

        mock_claripy.BVS.return_value = MagicMock()

        executor = SymbolicExecutor.__new__(SymbolicExecutor)
        executor.project = mock_project
        executor.binary_path = "/fake/binary"

        result = executor.execute_reachability(
            constraints={"input_constraints": [{"type": "contains_any", "chars": [";"]}]},
            sink_marker="__sink_reached",
            timeout=60,
        )

        assert result["success"] is True
        assert result["reachable"] is True
        assert result["paths_to_sink"] == 1

    @patch('libs.symbolic_sanitizer.symbolic_sanitizer.angr')
    @patch('libs.symbolic_sanitizer.symbolic_sanitizer.claripy')
    def test_not_reachable_returns_false(self, mock_claripy, mock_angr):
        mock_project = MagicMock()
        mock_angr.Project.return_value = mock_project

        mock_symbol = MagicMock()
        mock_symbol.rebased_addr = 0x400000
        mock_sink_symbol = MagicMock()
        mock_sink_symbol.rebased_addr = 0x400100

        mock_input_symbol = MagicMock()
        mock_input_symbol.rebased_addr = 0x500000

        def find_symbol_side_effect(name):
            if name == "main":
                return mock_symbol
            if name == "__sink_reached":
                return mock_sink_symbol
            if name == "symbolic_input":
                return mock_input_symbol
            return None
        mock_project.loader.find_symbol.side_effect = find_symbol_side_effect

        mock_state = MagicMock()
        mock_state.solver.satisfiable.return_value = True
        mock_project.factory.call_state.return_value = mock_state

        mock_simgr = MagicMock()
        mock_simgr.found = []
        mock_project.factory.simgr.return_value = mock_simgr

        mock_claripy.BVS.return_value = MagicMock()

        executor = SymbolicExecutor.__new__(SymbolicExecutor)
        executor.project = mock_project
        executor.binary_path = "/fake/binary"

        result = executor.execute_reachability(
            constraints={"input_constraints": [{"type": "contains_any", "chars": [";"]}]},
            sink_marker="__sink_reached",
            timeout=60,
        )

        assert result["success"] is True
        assert result["reachable"] is False
        assert result["paths_to_sink"] == 0

    @patch('libs.symbolic_sanitizer.symbolic_sanitizer.angr')
    @patch('libs.symbolic_sanitizer.symbolic_sanitizer.claripy')
    def test_sink_marker_not_found(self, mock_claripy, mock_angr):
        mock_project = MagicMock()
        mock_angr.Project.return_value = mock_project

        mock_symbol = MagicMock()
        mock_symbol.rebased_addr = 0x400000
        mock_project.loader.find_symbol.side_effect = lambda name: mock_symbol if name == "main" else None

        executor = SymbolicExecutor.__new__(SymbolicExecutor)
        executor.project = mock_project
        executor.binary_path = "/fake/binary"

        result = executor.execute_reachability(
            constraints={"input_constraints": []},
            sink_marker="__sink_reached",
            timeout=60,
        )

        assert result["success"] is False
        assert "__sink_reached" in result["error"]
