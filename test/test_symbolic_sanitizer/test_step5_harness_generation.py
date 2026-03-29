"""
Tests for Step 5: Harness Generation and Compilation

Tests the generate_harness and compile_harness MCP tools.
"""

import unittest
from unittest.mock import patch, MagicMock, mock_open
import tempfile
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))

# Mock fastmcp before importing mcptools
sys.modules['fastmcp'] = MagicMock()
sys.modules['angr'] = MagicMock()
sys.modules['claripy'] = MagicMock()

from src.libs.symbolic_sanitizer.harness_generator import (
    generate_harness,
    compile_harness,
    HarnessResult,
    _find_header_file,
    _detect_include_paths,
    _find_io_c
)


class TestHarnessResult(unittest.TestCase):
    """Test HarnessResult dataclass"""
    
    def test_harness_result_dataclass(self):
        """Test HarnessResult dataclass structure and types"""
        result = HarnessResult(
            success=True,
            harness_code="int main() {}",
            harness_path="/tmp/harness.cpp",
            binary_path="/tmp/harness_bin",
            error=None
        )
        
        self.assertTrue(result.success)
        self.assertEqual(result.harness_code, "int main() {}")
        self.assertEqual(result.harness_path, "/tmp/harness.cpp")
        self.assertEqual(result.binary_path, "/tmp/harness_bin")
        self.assertIsNone(result.error)
    
    def test_harness_result_failure(self):
        """Test HarnessResult for failure case"""
        result = HarnessResult(
            success=False,
            harness_code="",
            error="Compilation failed"
        )
        
        self.assertFalse(result.success)
        self.assertEqual(result.error, "Compilation failed")
        self.assertIsNone(result.harness_path)
        self.assertIsNone(result.binary_path)


class TestGenerateHarness(unittest.TestCase):
    """Test generate_harness function"""
    
    def test_generate_harness_signature_and_return_type(self):
        """Test generate_harness function signature returns HarnessResult"""
        result = generate_harness("TestClass", "/path/to/source.cpp")
        
        self.assertIsInstance(result, HarnessResult)
        self.assertTrue(result.success)
        self.assertIsNotNone(result.harness_code)
    
    def test_generate_harness_simple_class(self):
        """Test generate_harness with valid function_name and source_file"""
        result = generate_harness("MyClass", "/some/path/source.cpp")
        
        self.assertTrue(result.success)
        self.assertIn("MyClass", result.harness_code)
        self.assertIn("#include", result.harness_code)
        self.assertIn("int main", result.harness_code)
        self.assertIn("symbolic_input", result.harness_code)
    
    def test_generate_harness_namespace_class(self):
        """Test generate_harness with namespace::ClassName format"""
        result = generate_harness("Namespace::MyClass", "/path/source.cpp")
        
        self.assertTrue(result.success)
        self.assertIn("Namespace::MyClass", result.harness_code)
    
    def test_generate_harness_destructor(self):
        """Test generate_harness with destructor format Namespace::ClassName::~ClassName"""
        result = generate_harness("Namespace::MyClass::~MyClass", "/path/source.cpp")
        
        self.assertTrue(result.success)
        self.assertIn("Namespace::MyClass", result.harness_code)
        # Should not include the destructor part in the harness
        self.assertNotIn("::~MyClass", result.harness_code)
    
    def test_generate_harness_includes_header(self):
        """Test that generate_harness includes header when found"""
        with patch('src.libs.symbolic_sanitizer.harness_generator._find_header_file') as mock_find:
            mock_find.return_value = "source.h"
            result = generate_harness("TestClass", "/path/source.cpp")
            
            self.assertIn('#include "source.h"', result.harness_code)
    
    def test_generate_harness_no_header(self):
        """Test generate_harness when no header is found"""
        with patch('src.libs.symbolic_sanitizer.harness_generator._find_header_file') as mock_find:
            mock_find.return_value = None
            result = generate_harness("TestClass", "/path/source.cpp")
            
            # Should not have include statement when no header found
            lines = result.harness_code.split('\n')
            include_lines = [l for l in lines if l.startswith('#include "')]
            self.assertEqual(len(include_lines), 0)


class TestFindHeaderFile(unittest.TestCase):
    """Test _find_header_file helper function"""
    
    @patch('pathlib.Path.exists')
    def test_find_header_with_suffix_goodB2G(self, mock_exists):
        """Test finding header for source file with _goodB2G suffix"""
        mock_exists.return_value = True
        result = _find_header_file("/path/source_goodB2G.cpp")
        self.assertEqual(result, "source.h")
    
    @patch('pathlib.Path.exists')
    def test_find_header_with_suffix_goodG2B(self, mock_exists):
        """Test finding header for source file with _goodG2B suffix"""
        mock_exists.return_value = True
        result = _find_header_file("/path/source_goodG2B.cpp")
        self.assertEqual(result, "source.h")
    
    @patch('pathlib.Path.exists')
    def test_find_header_with_suffix_bad(self, mock_exists):
        """Test finding header for source file with _bad suffix"""
        mock_exists.return_value = True
        result = _find_header_file("/path/source_bad.cpp")
        self.assertEqual(result, "source.h")
    
    @patch('pathlib.Path.exists')
    def test_find_header_not_exists(self, mock_exists):
        """Test when header file does not exist"""
        mock_exists.return_value = False
        result = _find_header_file("/path/source.cpp")
        self.assertIsNone(result)


class TestCompileHarness(unittest.TestCase):
    """Test compile_harness function with mocked subprocess"""
    
    @patch('src.libs.symbolic_sanitizer.harness_generator.subprocess.run')
    @patch('src.libs.symbolic_sanitizer.harness_generator.tempfile.mkdtemp')
    @patch('src.libs.symbolic_sanitizer.harness_generator._detect_include_paths')
    @patch('src.libs.symbolic_sanitizer.harness_generator._find_io_c')
    @patch('builtins.open', mock_open())
    def test_compile_harness_success(self, mock_find_io, mock_detect, mock_mkdtemp, mock_run):
        """Test compile_harness with successful compilation"""
        mock_mkdtemp.return_value = "/tmp/symbolic_harness_123"
        mock_detect.return_value = ["/path/include"]
        mock_find_io.return_value = None
        
        # Mock successful compilation
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        
        harness_code = "int main() { return 0; }"
        result = compile_harness(harness_code, "/path/source.cpp")
        
        self.assertTrue(result.success)
        self.assertEqual(result.harness_code, harness_code)
        self.assertEqual(result.harness_path, "/tmp/symbolic_harness_123/harness.cpp")
        self.assertEqual(result.binary_path, "/tmp/symbolic_harness_123/harness_bin")
        self.assertIsNone(result.error)
        
        # Verify subprocess was called with correct arguments
        mock_run.assert_called_once()
        call_args = mock_run.call_args
        self.assertEqual(call_args[0][0][0], "g++")
        self.assertIn("-O0", call_args[0][0])
        self.assertIn("-g", call_args[0][0])
        self.assertIn("-fno-stack-protector", call_args[0][0])
    
    @patch('src.libs.symbolic_sanitizer.harness_generator.subprocess.run')
    @patch('src.libs.symbolic_sanitizer.harness_generator.tempfile.mkdtemp')
    @patch('src.libs.symbolic_sanitizer.harness_generator._detect_include_paths')
    @patch('src.libs.symbolic_sanitizer.harness_generator._find_io_c')
    @patch('src.libs.symbolic_sanitizer.harness_generator.shutil.rmtree')
    @patch('builtins.open', mock_open())
    def test_compile_harness_failure(self, mock_rmtree, mock_find_io, mock_detect, mock_mkdtemp, mock_run):
        """Test compile_harness error handling when compilation fails"""
        mock_mkdtemp.return_value = "/tmp/symbolic_harness_123"
        mock_detect.return_value = ["/path/include"]
        mock_find_io.return_value = None
        
        # Mock failed compilation
        mock_run.return_value = MagicMock(returncode=1, stderr="error: undefined reference")
        
        harness_code = "int main() { return 0; }"
        result = compile_harness(harness_code, "/path/source.cpp")
        
        self.assertFalse(result.success)
        self.assertEqual(result.harness_code, harness_code)
        self.assertIsNone(result.harness_path)
        self.assertIn("Compilation failed", result.error)
        self.assertIn("undefined reference", result.error)
        
        # Verify temp directory was cleaned up
        mock_rmtree.assert_called_once_with("/tmp/symbolic_harness_123", ignore_errors=True)
    
    @patch('src.libs.symbolic_sanitizer.harness_generator.tempfile.mkdtemp')
    @patch('src.libs.symbolic_sanitizer.harness_generator.shutil.rmtree')
    @patch('builtins.open', mock_open())
    def test_compile_harness_exception(self, mock_rmtree, mock_mkdtemp):
        """Test compile_harness error handling on exception"""
        mock_mkdtemp.return_value = "/tmp/symbolic_harness_123"
        
        # Make open raise an exception
        with patch('builtins.open', side_effect=IOError("Disk full")):
            harness_code = "int main() { return 0; }"
            result = compile_harness(harness_code, "/path/source.cpp")
            
            self.assertFalse(result.success)
            self.assertIn("Compilation error", result.error)
            self.assertIn("Disk full", result.error)
    
    @patch('src.libs.symbolic_sanitizer.harness_generator.subprocess.run')
    @patch('src.libs.symbolic_sanitizer.harness_generator.tempfile.mkdtemp')
    @patch('src.libs.symbolic_sanitizer.harness_generator._detect_include_paths')
    @patch('src.libs.symbolic_sanitizer.harness_generator._find_io_c')
    @patch('builtins.open', mock_open())
    def test_compile_harness_with_io_c(self, mock_find_io, mock_detect, mock_mkdtemp, mock_run):
        """Test compile_harness includes io.c when found"""
        mock_mkdtemp.return_value = "/tmp/symbolic_harness_123"
        mock_detect.return_value = ["/path/include"]
        mock_find_io.return_value = "/path/include/io.c"
        
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        
        harness_code = "int main() { return 0; }"
        result = compile_harness(harness_code, "/path/source.cpp")
        
        self.assertTrue(result.success)
        
        # Verify io.c was included in compilation
        call_args = mock_run.call_args[0][0]
        self.assertIn("/path/include/io.c", call_args)
    
    @patch('src.libs.symbolic_sanitizer.harness_generator.subprocess.run')
    @patch('src.libs.symbolic_sanitizer.harness_generator.tempfile.mkdtemp')
    @patch('src.libs.symbolic_sanitizer.harness_generator._detect_include_paths')
    @patch('src.libs.symbolic_sanitizer.harness_generator._find_io_c')
    @patch('builtins.open', mock_open())
    def test_compile_harness_custom_compiler(self, mock_find_io, mock_detect, mock_mkdtemp, mock_run):
        """Test compile_harness with custom compiler"""
        mock_mkdtemp.return_value = "/tmp/symbolic_harness_123"
        mock_detect.return_value = ["/path/include"]
        mock_find_io.return_value = None
        
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        
        harness_code = "int main() { return 0; }"
        result = compile_harness(harness_code, "/path/source.cpp", compiler="clang++")
        
        self.assertTrue(result.success)
        
        # Verify clang++ was used
        call_args = mock_run.call_args[0][0]
        self.assertEqual(call_args[0], "clang++")


class TestDetectIncludePaths(unittest.TestCase):
    """Test _detect_include_paths helper function"""
    
    @patch('pathlib.Path.exists')
    def test_detect_include_paths_basic(self, mock_exists):
        """Test basic include path detection"""
        mock_exists.return_value = False
        result = _detect_include_paths("/project/src/file.cpp")
        
        self.assertIn("/project/src", result)
    
    @patch('pathlib.Path.exists')
    def test_detect_include_paths_with_testcasesupport(self, mock_exists):
        """Test detection when testcasesupport directory exists"""
        def exists_side_effect():
            return True
        mock_exists.return_value = True
        
        result = _detect_include_paths("/project/testcasesupport/file.cpp")
        
        self.assertTrue(any("testcasesupport" in p for p in result))


class TestFindIoC(unittest.TestCase):
    """Test _find_io_c helper function"""
    
    @patch('pathlib.Path.exists')
    def test_find_io_c_exists(self, mock_exists):
        """Test finding io.c when it exists"""
        mock_exists.return_value = True
        result = _find_io_c(["/path/include", "/other/include"])
        self.assertEqual(result, "/path/include/io.c")
    
    @patch('pathlib.Path.exists')
    def test_find_io_c_not_exists(self, mock_exists):
        """Test when io.c does not exist"""
        mock_exists.return_value = False
        result = _find_io_c(["/path/include"])
        self.assertIsNone(result)


class TestMCPToolsIntegration(unittest.TestCase):
    """Test MCP tool wrapper logic by testing the underlying functions that wrappers call"""
    
    @patch('src.libs.symbolic_sanitizer.harness_generator._find_header_file')
    def test_mcp_generate_harness_logic(self, mock_find_header):
        """Test MCP generate_harness tool logic - verify underlying function behavior"""
        mock_find_header.return_value = None
        
        result = generate_harness("TestClass", "/path/file.cpp")
        
        self.assertTrue(result.success)
        self.assertIn("TestClass", result.harness_code)
        self.assertIsNone(result.error)
    
    @patch('src.libs.symbolic_sanitizer.harness_generator.subprocess.run')
    @patch('src.libs.symbolic_sanitizer.harness_generator.tempfile.mkdtemp')
    @patch('src.libs.symbolic_sanitizer.harness_generator._detect_include_paths')
    @patch('src.libs.symbolic_sanitizer.harness_generator._find_io_c')
    @patch('builtins.open', mock_open())
    def test_mcp_compile_harness_logic(self, mock_find_io, mock_detect, mock_mkdtemp, mock_run):
        """Test MCP compile_harness tool logic - verify underlying function behavior"""
        mock_mkdtemp.return_value = "/tmp/symbolic_harness_123"
        mock_detect.return_value = ["/path/include"]
        mock_find_io.return_value = None
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        
        harness_code = "int main() { return 0; }"
        result = compile_harness(harness_code, "/path/file.cpp")
        
        self.assertTrue(result.success)
        self.assertEqual(result.harness_path, "/tmp/symbolic_harness_123/harness.cpp")
        self.assertEqual(result.binary_path, "/tmp/symbolic_harness_123/harness_bin")


if __name__ == '__main__':
    unittest.main()
