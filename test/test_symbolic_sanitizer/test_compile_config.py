"""Tests for compile_config module."""
import os
import sys
import stat
import pytest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../src'))

from libs.symbolic_sanitizer.compile_config import resolve_compile_config, write_compile_config


class TestResolveCompileConfig:
    def test_found_existing_config(self, tmp_path):
        config_dir = tmp_path / ".CodeQL-AI"
        config_dir.mkdir()
        script = config_dir / "compile.sh"
        script.write_text("#!/bin/bash\ngcc $1 -o $2\n")
        script.chmod(script.stat().st_mode | stat.S_IEXEC)

        result = resolve_compile_config(str(tmp_path))
        assert result["found"] is True
        assert result["compile_script"] == str(script)

    def test_not_found_returns_listing(self, tmp_path):
        (tmp_path / "src").mkdir()
        (tmp_path / "include").mkdir()
        (tmp_path / "main.c").touch()

        result = resolve_compile_config(str(tmp_path))
        assert result["found"] is False
        assert str(tmp_path) in result["dataset_path"]
        assert isinstance(result["directory_listing"], list)
        assert "src" in result["directory_listing"]

    def test_nonexistent_dataset_path(self):
        result = resolve_compile_config("/nonexistent/path")
        assert result["found"] is False


class TestWriteCompileConfig:
    def test_creates_directory_and_script(self, tmp_path):
        script_content = "#!/bin/bash\ngcc -O0 $1 -o $2\n"
        result = write_compile_config(str(tmp_path), script_content)
        assert result["success"] is True

        script_path = Path(result["compile_script"])
        assert script_path.exists()
        assert script_path.read_text() == script_content
        assert os.access(str(script_path), os.X_OK)

    def test_overwrites_existing(self, tmp_path):
        config_dir = tmp_path / ".CodeQL-AI"
        config_dir.mkdir()
        (config_dir / "compile.sh").write_text("old content")

        result = write_compile_config(str(tmp_path), "new content")
        assert result["success"] is True
        assert Path(result["compile_script"]).read_text() == "new content"
