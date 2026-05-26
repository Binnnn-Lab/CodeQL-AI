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
