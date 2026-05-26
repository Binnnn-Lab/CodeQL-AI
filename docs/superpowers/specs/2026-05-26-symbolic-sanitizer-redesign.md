# Symbolic Sanitizer Redesign — Path-Guided Selective Symbolic Execution

**Date:** 2026-05-26
**Status:** Draft (pending user review)
**Supersedes:** `2026-05-23-symbolic-sanitizer-refactor-design.md`

## 1. Motivation

The current 7-tool MCP pipeline pushes too much C-level reasoning onto the
agent: it must hand-translate sanitizer logic into a `call_chain` string, hand-
write `input_constraints` for the attack, and the resulting "symbolic execution"
runs only on a few inlined lines in a synthetic `main` — not along the actual
SARIF taint path through real code. This makes the tool work on self-contained
Juliet toys but unusable on real codebases where sanitizers span functions,
involve structs/macros/library calls, and where taint sources are not a single
`fscanf` call.

This redesign:

1. Compiles the **real source file** (with `-g -O0 -fno-inline`) into a
   debuggable analysis binary, so symbolic execution runs over actual
   sanitizer code without a synthetic harness entry.
2. Uses **DWARF** to map SARIF `file:line` to binary addresses, enabling
   mid-function entry when the taint source is not a libc API.
3. Reduces the agent's role to a **single decision point**: given the
   tainted-branch candidates discovered on the SARIF path, decide which to
   treat as sanitizers (include their guard as a constraint) and provide an
   attack predicate over named taint variables.
4. Cuts the MCP surface from 7 tools to 4, eliminating tools whose only job
   was concatenating absolute paths or reading source files the agent already
   located via SARIF.

## 2. Goals & Non-Goals

**Goals**

- Verify sanitizer effectiveness by symbolic execution along the SARIF taint
  path through the original compiled binary.
- Support libc-sourced taint (scanf/fgets/recv/...) via symbolic stdin and
  non-libc taint via DWARF-resolved mid-function entry.
- Surface tainted branches to the agent for one-shot include/exclude decisions
  (no stateful resume protocol).
- Sole agent input is a SARIF file plus dataset root; agent output is branch
  decisions plus a simple attack predicate keyed by taint variable name.

**Non-Goals**

- Whole-program symbolic execution (we still follow a single SARIF path).
- Loop unrolling heuristics beyond angr's defaults.
- Multi-predicate (AND/OR) attack conditions in v1 — single predicate only.
- Custom user-supplied `SimProcedure`s for framework-specific source APIs
  (deferred — covered by future extension `register_source_api`).
- Source-API inference beyond a built-in libc list (taint source recognised by
  function name match against the SARIF source node).

## 3. Architecture

### 3.1 MCP Tool Surface (4 tools)

| Tool | Input | Output | Agent involved |
|------|-------|--------|----------------|
| `parse_sarif` | `sarif_path`, `dataset_root` | `paths[]` — each path includes source/sink/intermediate nodes with absolute paths AND the source code of each enclosing function (deduped by `(file, function)`) | No |
| `build_binary` | `source_file`, `source_api`, `compile_script`, `dataset_path` | `{binary_path, dwarf_ok: bool, source_mode: "libc_stdin"\|"mid_function"\|"entry_fallback"}` | No |
| `scan_path_branches` | `binary_path`, `path` | `{tainted_branches[]}` — each branch: `{branch_id, file, line, condition_src, surrounding_code (5 lines), taint_vars[]}` | No |
| `verify_with_decisions` | `binary_path`, `path`, `branch_decisions: {branch_id: bool}`, `attack_predicate` | `{reachable, counterexample, sat_branches, paths_explored, degraded?: str}` | No |

The agent's sole reasoning happens **between `scan_path_branches` and
`verify_with_decisions`**: pick which branches to treat as sanitizers, then
fill in the attack predicate.

### 3.2 End-to-End Flow

```
parse_sarif(sarif_path, dataset_root)
  └─> paths[]                                          (deterministic)

for each path in paths:
    build_binary(...)              → binary_path       (deterministic)
    scan_path_branches(binary, path) → tainted_branches  (deterministic)

    ─── agent decision (only reasoning point) ───
    Read tainted_branches, decide:
      branch_decisions = {b1: true, b2: false, ...}
      attack_predicate = {taint_var, op, value, width, signed}
    ─────────────────────────────────────────────

    verify_with_decisions(binary, path,
                          branch_decisions,
                          attack_predicate)
      → {reachable, counterexample, ...}
```

### 3.3 Tool Details

#### `parse_sarif`

Combines the previous `parse_sarif_detailed` + `read_path_context`. Internally:

1. Parse SARIF (codeFlows; fallback to `relatedLocations[0]` as source +
   `locations[0]` as sink for results without codeFlows).
2. Join `file_path` with `dataset_root` to absolute paths.
3. For each `(file, function)` on every path, read the enclosing function's
   source via the existing line-range/AST helper. Dedupe.
4. Return per-path: `{source, sink, intermediate_locations, function_sources}`.

The agent never has to call a second tool to read context.

#### `build_binary`

Replaces the previous `generate_harness` + `compile_harness` path. It compiles
the original dataset source directly and does not emit `__sink_reached` or call
a synthetic entry wrapper. Downstream tools use SARIF plus DWARF to resolve the
real source and sink addresses. compile.sh enforces `-g -O0 -fno-inline` so
DWARF is reliable.

Returns `source_mode`:
- `libc_stdin` — SARIF source-node API name is in the built-in libc list
  (`scanf, fscanf, sscanf, fgets, gets, getc, getchar, read, recv, fread`).
  Runtime uses `full_init_state(stdin=SimFileStream(content=BVS))` plus
  explicit hooks for common scanf/fread-style source APIs.
- `mid_function` — DWARF resolves the source `file:line` to an address; runtime
  uses `project.factory.call_state(addr=source_addr)` and stores symbolic BVs
  into the variables named by the SARIF source node.
- `entry_fallback` — DWARF cannot map the source line (e.g. inlined despite
  `-fno-inline`, or symbol stripped); runtime falls back to
  `call_state(func_entry_addr)`. Result is marked `degraded`.

#### `scan_path_branches`

Sole purpose: enumerate the tainted-branch candidates the agent must rule on.

1. Load binary via angr (existing `SymbolicExecutor` is restructured here).
2. Initialize state per `source_mode` (see above). Tag the initial symbolic
   bytes with `taint_id` annotations.
3. Walk the path: `explore(find=next_intermediate_addr, ...)` from source
   through every intermediate, stopping just before sink.
4. At every conditional jump while exploring, inspect the guard expression's
   AST. If any leaf is annotated with a `taint_id`, record:

   ```
   {
     "branch_id": "b_<sha1[:8]>",
     "file": "<resolved via DWARF rev-lookup>",
     "line": <int>,
     "condition_src": "<text from source via file:line>",
     "surrounding_code": "<+/-2 lines>",
     "taint_vars": ["data", ...]    # DWARF local var names whose
                                    # storage feeds the guard
   }
   ```

5. **Do not solve, do not continue past sink.** Return only the list.

`taint_vars` are resolved by walking DWARF location lists for the function: for
each symbolic leaf in the guard, find which `DW_TAG_variable` covers its
storage (register or stack offset) at the current PC.

#### `verify_with_decisions`

1. Fresh state with same `source_mode` initialization.
2. Walk the path the same way as `scan_path_branches`, but at each tainted
   branch with `branch_decisions[branch_id] == true`, add the guard expression
   as a hard constraint (forcing the sanitizer's **accept** side). For
   `false`, do nothing (angr explores both sides naturally).
3. Resolve `attack_predicate.taint_var` to its symbolic BV via DWARF, build the
   comparison (`uge/ule/eq` per `op` and `signed`), add as constraint.
4. `explore(find=sink_addr)`. Return `{reachable, counterexample (32 bytes
   hex), paths_explored, sat_branches: [branch_ids whose include constraint
   was satisfied]}`.
5. If any step degrades (e.g. DWARF lookup miss for a specific intermediate),
   set `degraded` field with a short reason; the result is still returned.

### 3.4 Attack Predicate Schema

```json
{
  "taint_var": "data",
  "op": ">=" | "<=" | "==" | "!=" | ">" | "<",
  "value": 65536,
  "width": 4,
  "signed": false
}
```

- `taint_var` — DWARF-visible local in the source function. Resolved by name
  at the binary location corresponding to the SARIF source node.
- `width` — byte width of the comparison (1/2/4/8).
- `signed` — selects signed vs unsigned comparison opcodes.

Compound predicates (AND/OR) are deferred to v2.

## 4. Component Layout

```
src/libs/symbolic_sanitizer/
  sarif_parser.py        # parse_sarif() — SARIF + path-context merge
  harness_builder.py     # build_binary(), legacy build_harness(), compile templates
  dwarf_resolver.py      # NEW: pyelftools-based file:line<->addr, var name<->storage
  path_executor.py       # NEW: shared angr driver used by both scan + verify
  branch_scanner.py      # NEW: scan_path_branches() — taint-aware branch enum
  verifier.py            # RENAMED: verify_with_decisions() — replaces symbolic_sanitizer.py's
                         # constraint-only model
  readme.md              # agent prompt (rewritten for 4-tool flow)

src/mcptools/
  symbolic_sanitizer.py  # 4 tool entrypoints (down from 7)

test/test_symbolic_sanitizer/
  test_parse_sarif.py
  test_harness_builder.py
  test_dwarf_resolver.py
  test_scan_path_branches.py
  test_verify_with_decisions.py
  test_end_to_end_juliet.py    # CWE-190 fscanf_square / fscanf_add as fixtures
```

The previous `symbolic_sanitizer.py` (the angr driver) is split: shared parts
into `path_executor.py`, scan-specific into `branch_scanner.py`, verify-
specific into `verifier.py`.

## 5. Compile Script Contract

compile.sh is now called as:

```
bash compile.sh <source_src> <output_binary> <lang>
```

Template (Juliet/POSIX):

```bash
#!/bin/bash
SRC="$1"; OUT="$2"; LANG="${3:-c}"
case "$LANG" in
  cpp) CC=g++ ; STD=-std=c++17 ;;
  *)   CC=gcc ; STD=-std=c11   ;;
esac
"$CC" $STD -g -O0 -fno-inline \
  -I"$JULIET_ROOT/testcasesupport" \
  "$SRC" -o "$OUT" -lm 2>&1
```

`-g -O0 -fno-inline` is non-negotiable; the DWARF resolver depends on it. If
the dataset's compile.sh already exists but lacks these flags, `build_binary`
returns `dwarf_ok: false` and surfaces a warning rather than silently producing
unmappable binaries.

## 6. DWARF Resolver

`dwarf_resolver.py` uses `pyelftools`:

- `line_to_addr(binary, file, line) -> Optional[int]` — search `.debug_line`
  rows.
- `addr_to_line(binary, addr) -> Optional[(file, line)]` — reverse of above
  (used by `scan_path_branches` to label branches).
- `var_storage(binary, func, var_name, pc) -> Optional[Storage]` — walk
  `DW_TAG_variable` under the function DIE; evaluate `DW_AT_location` at the
  given PC; return `{kind: "register"|"frame_offset", value: int}`.
- `func_entry(binary, func_name) -> Optional[int]` — for `entry_fallback`
  mode.

All lookups return `None` on failure; callers degrade gracefully.

## 7. Error / Degradation Modes

| Condition | Behaviour |
|-----------|-----------|
| SARIF has no codeFlows and no relatedLocations | path skipped, warning emitted |
| Original source missing on disk | `build_binary` fails fast with clear error |
| compile.sh missing | `build_binary` fails fast with instruction to write one |
| compile.sh produces binary without DWARF | `build_binary` returns `dwarf_ok: false`; downstream tools use `entry_fallback`, results marked `degraded: "no_dwarf"` |
| DWARF present but specific source line not mapped (optimised out) | that branch is skipped during scan; if it was the source line itself, `source_mode = entry_fallback` |
| `taint_var` not found in DWARF at predicate-resolution time | `verify_with_decisions` returns `success: false` with `error: "taint_var <name> not visible at source location"` |
| angr explore times out | return `{reachable: false, degraded: "explore_timeout"}` with explored path count |

## 8. Test Plan

**Unit:**
- `parse_sarif`: codeFlows path, relatedLocations fallback, absolute-path join,
  function-source dedup.
- `dwarf_resolver`: line↔addr round-trip on a known fixture binary; var-storage
  for register and stack locals.
- `harness_builder`: direct binary compile, source_mode selection table, missing
  compile.sh, missing-g detection.
- `branch_scanner`: on a fixture binary with one tainted `if`, returns exactly
  one branch with correct file/line/var.
- `verifier`: include vs exclude flips reachability on a known Juliet case;
  attack predicate `data >= 65536` yields the documented bypass on
  `fscanf_square`.

**End-to-end:**
- CWE-190 `fscanf_square` (libc_stdin) — expect reachable=true with bypass
  counterexample matching the historical `c0efffff`-style result.
- CWE-190 `fscanf_add` with predicate `data == 127` — expect reachable=false.
- One synthetic non-libc-source fixture exercising `mid_function` mode.
- One stripped-DWARF binary fixture exercising `entry_fallback` + `degraded`
  result.

## 9. Migration & Cleanup

- Delete `harness_generator.py` (replaced by `harness_builder.py`).
- Replace `symbolic_sanitizer.py` driver with `path_executor.py` +
  `branch_scanner.py` + `verifier.py`.
- Rewrite `src/libs/symbolic_sanitizer/readme.md` (agent prompt) to describe
  the 4-tool flow, the single decision point, and the attack predicate schema.
- Update `src/mcptools/symbolic_sanitizer.py` to expose only the 4 new tools.
- Old tests (`test_step5_harness_generation.py`,
  `test_step6_verify_with_constraints.py`) deleted; replaced by the test list
  in §8.
- `scripts/eval_symbolic_sanitizer.py` updated to drive the 4-tool flow.

## 10. Open Items (resolved in implementation plan)

- Exact ordering of `state.solver.add` calls relative to `explore` for include
  branches — needs verification that constraints added pre-explore propagate
  to all forked states (angr semantics: yes, but write a regression test).
- pyelftools dependency added to project requirements.
- How `scan_path_branches` handles loops on the path (initial pass: rely on
  angr's default veritesting/loop bound; do not unroll explicitly).
