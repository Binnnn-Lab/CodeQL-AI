"""DWARF resolver — file:line <-> address, variable storage lookup."""
from __future__ import annotations

import os
from typing import Optional, Tuple, NamedTuple
from elftools.elf.elffile import ELFFile


class Storage(NamedTuple):
    kind: str          # "register" | "frame_offset"
    value: int         # reg num, or signed offset from CFA/fbreg


def _open_dwarf(binary_path: str):
    f = open(binary_path, "rb")
    elf = ELFFile(f)
    if not elf.has_dwarf_info():
        f.close()
        return None, None
    return f, elf.get_dwarf_info()


def line_to_addr(binary_path: str, source_file: str, line_number: int) -> Optional[int]:
    f, dwarf = _open_dwarf(binary_path)
    if dwarf is None:
        return None
    try:
        target_basename = os.path.basename(source_file)
        for cu in dwarf.iter_CUs():
            lineprog = dwarf.line_program_for_CU(cu)
            if lineprog is None:
                continue
            file_entries = lineprog["file_entry"]
            for entry in lineprog.get_entries():
                state = entry.state
                if state is None or state.end_sequence:
                    continue
                if state.line != line_number:
                    continue
                file_idx = state.file
                if file_idx == 0 or file_idx > len(file_entries):
                    continue
                fname = file_entries[file_idx - 1].name.decode("utf-8", "replace")
                if os.path.basename(fname) == target_basename:
                    return state.address
        return None
    finally:
        f.close()


from elftools.dwarf.locationlists import LocationEntry, LocationParser


def nearest_line_addr(
    binary_path: str,
    source_file: str,
    line_number: int,
    max_forward_lines: int = 2,
) -> Optional[int]:
    """Resolve a source line to an executable address.

    DWARF often maps a call expression to the next emitted line row rather than
    the exact SARIF line.  Prefer the exact line, then a small forward search so
    real sink lines can be used without a synthetic marker function.
    """
    exact = line_to_addr(binary_path, source_file, line_number)
    if exact is not None:
        return exact
    for delta in range(1, max_forward_lines + 1):
        addr = line_to_addr(binary_path, source_file, line_number + delta)
        if addr is not None:
            return addr
    return None


def func_entry(binary_path: str, func_name: str) -> Optional[int]:
    f, dwarf = _open_dwarf(binary_path)
    if dwarf is None:
        return None
    try:
        for cu in dwarf.iter_CUs():
            for die in cu.iter_DIEs():
                if die.tag != "DW_TAG_subprogram":
                    continue
                name_attr = die.attributes.get("DW_AT_name")
                if name_attr is None:
                    continue
                if name_attr.value.decode("utf-8", "replace") != func_name:
                    continue
                low_pc = die.attributes.get("DW_AT_low_pc")
                if low_pc is None:
                    continue
                return low_pc.value
        return None
    finally:
        f.close()


def _decode_simple_location(expr_bytes: bytes) -> Optional[Storage]:
    """Decode a single-op DWARF expression. Handles common cases:
    DW_OP_regN (0x50..0x6f), DW_OP_fbreg (0x91 + sleb128), DW_OP_breg6 (0x76 + sleb128).
    """
    if not expr_bytes:
        return None
    op = expr_bytes[0]
    if 0x50 <= op <= 0x6f:
        return Storage(kind="register", value=op - 0x50)
    if op == 0x91:  # DW_OP_fbreg <sleb128>
        offset = _read_sleb128(expr_bytes[1:])
        return Storage(kind="frame_offset", value=offset)
    if op == 0x76:  # DW_OP_breg6 (rbp) <sleb128>  -- treat like frame offset
        offset = _read_sleb128(expr_bytes[1:])
        return Storage(kind="frame_offset", value=offset)
    return None


def _read_sleb128(data: bytes) -> int:
    result = 0
    shift = 0
    for b in data:
        result |= (b & 0x7f) << shift
        shift += 7
        if (b & 0x80) == 0:
            if b & 0x40:  # sign bit
                result -= (1 << shift)
            return result
    return result


def var_storage(binary_path: str, func_name: str, var_name: str, pc: int) -> Optional[Storage]:
    f, dwarf = _open_dwarf(binary_path)
    if dwarf is None:
        return None
    try:
        loc_lists = dwarf.location_lists()
        parser = LocationParser(loc_lists) if loc_lists is not None else None
        for cu in dwarf.iter_CUs():
            for die in cu.iter_DIEs():
                if die.tag != "DW_TAG_subprogram":
                    continue
                name_attr = die.attributes.get("DW_AT_name")
                if name_attr is None or name_attr.value.decode("utf-8", "replace") != func_name:
                    continue
                for child in die.iter_children():
                    if child.tag not in ("DW_TAG_variable", "DW_TAG_formal_parameter"):
                        continue
                    cname = child.attributes.get("DW_AT_name")
                    if cname is None or cname.value.decode("utf-8", "replace") != var_name:
                        continue
                    loc_attr = child.attributes.get("DW_AT_location")
                    if loc_attr is None:
                        return None
                    form = loc_attr.form
                    if form in ("DW_FORM_exprloc", "DW_FORM_block", "DW_FORM_block1"):
                        return _decode_simple_location(bytes(loc_attr.value))
                    if parser is not None and parser.attribute_has_location(loc_attr, cu["version"]):
                        loclist = parser.parse_from_attribute(loc_attr, cu["version"])
                        for entry in loclist:
                            if isinstance(entry, LocationEntry):
                                if entry.begin_offset <= pc < entry.end_offset:
                                    return _decode_simple_location(bytes(entry.loc_expr))
                    return None
        return None
    finally:
        f.close()


def addr_to_line(binary_path: str, addr: int) -> Optional[Tuple[str, int]]:
    f, dwarf = _open_dwarf(binary_path)
    if dwarf is None:
        return None
    try:
        for cu in dwarf.iter_CUs():
            lineprog = dwarf.line_program_for_CU(cu)
            if lineprog is None:
                continue
            file_entries = lineprog["file_entry"]
            prev_state = None
            for entry in lineprog.get_entries():
                state = entry.state
                if state is None:
                    continue
                if state.end_sequence:
                    prev_state = None
                    continue
                if prev_state is not None and prev_state.address <= addr < state.address:
                    file_idx = prev_state.file
                    if file_idx == 0 or file_idx > len(file_entries):
                        continue
                    fname = file_entries[file_idx - 1].name.decode("utf-8", "replace")
                    return fname, prev_state.line
                prev_state = state
        return None
    finally:
        f.close()
