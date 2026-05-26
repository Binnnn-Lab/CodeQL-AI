import os
import pytest

from libs.symbolic_sanitizer.harness_builder import (
    select_source_mode, render_harness, build_binary, build_harness,
    DEFAULT_COMPILE_SH, DEFAULT_HARNESS_COMPILE_SH,
)


def test_select_source_mode_libc():
    assert select_source_mode("fscanf") == "libc_stdin"
    assert select_source_mode("fgets") == "libc_stdin"
    assert select_source_mode("read") == "libc_stdin"


def test_select_source_mode_unknown():
    assert select_source_mode("custom_recv_packet") == "mid_function"


def test_select_source_mode_none():
    assert select_source_mode(None) == "mid_function"


def test_render_harness_void_entry():
    code = render_harness(vuln_entry="goodB2G", entry_signature="void")
    assert "extern void goodB2G(void);" in code
    assert "goodB2G();" in code
    assert "void __sink_reached(void)" in code


def test_render_harness_int_entry():
    code = render_harness(vuln_entry="vuln_entry", entry_signature="int")
    assert "extern int vuln_entry(void);" in code
    assert "(void)vuln_entry();" in code


def test_default_compile_sh_has_g_O0_fno_inline():
    assert "-g" in DEFAULT_COMPILE_SH
    assert "-O0" in DEFAULT_COMPILE_SH
    assert "-fno-inline" in DEFAULT_COMPILE_SH


def test_build_binary_end_to_end(tmp_path):
    src = tmp_path / "main.c"
    src.write_text(
        '#include <stdio.h>\n'
        'int main(void) { return 0; }\n'
    )
    compile_sh = tmp_path / "compile.sh"
    compile_sh.write_text(DEFAULT_COMPILE_SH)
    compile_sh.chmod(0o755)

    res = build_binary(
        source_file=str(src),
        source_api="fscanf",
        compile_script=str(compile_sh),
    )
    assert res["success"] is True, res.get("error")
    assert os.path.exists(res["binary_path"])
    assert res["source_mode"] == "libc_stdin"
    assert res["dwarf_ok"] is True


def test_build_harness_missing_compile_script(tmp_path):
    res = build_harness(
        source_file=str(tmp_path / "no.c"),
        vuln_entry="vuln_entry",
        source_api="fscanf",
        compile_script=str(tmp_path / "no_compile.sh"),
    )
    assert res["success"] is False
    assert "compile" in res["error"].lower() or "source" in res["error"].lower()


def test_build_harness_end_to_end(tmp_path):
    src = tmp_path / "vuln.c"
    src.write_text(
        '#include <stdio.h>\n'
        'void vuln_entry(void) { volatile int x = 0; (void)x; }\n'
    )
    compile_sh = tmp_path / "compile.sh"
    compile_sh.write_text(DEFAULT_HARNESS_COMPILE_SH)
    compile_sh.chmod(0o755)

    res = build_harness(
        source_file=str(src),
        vuln_entry="vuln_entry",
        source_api="fscanf",
        compile_script=str(compile_sh),
    )
    assert res["success"] is True, res.get("error")
    assert os.path.exists(res["binary_path"])
    assert res["source_mode"] == "libc_stdin"
    assert res["dwarf_ok"] is True
