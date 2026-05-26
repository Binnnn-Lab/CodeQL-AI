# Symbolic Sanitizer Redesign — Path-Guided Selective Symbolic Execution

**Date:** 2026-05-26
**Status:** Reconciled with implementation (2026-05-26 evening pass; see §11 Change Log)
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

### 3.1 MCP Tool Surface (4 core + 2 compile helpers)

| Tool | Input | Output | Agent involved |
|------|-------|--------|----------------|
| `parse_sarif` | `sarif_path`, `dataset_root` | `paths[]` — each path includes source/sink/intermediate nodes with absolute paths AND the source code of each enclosing function (deduped by `(file, function)`) | No |
| `build_binary` | `source_file`, `source_api`, `compile_script`, `dataset_path?` | `{binary_path, dwarf_ok: bool, source_mode: "libc_stdin"\|"mid_function"\|"entry_fallback"}` | No |
| `scan_path_branches` | `binary_path`, `path`, `source_mode` | `{tainted_branches[]}` — see §3.3 for entry schema (one entry per conditional jump address, with `alternatives[]` listing the fork-side guards) | No |
| `verify_with_decisions` | `binary_path`, `path`, `source_mode`, `branch_decisions: {branch_id: bool}`, `attack_predicate` | `{reachable, counterexample, sat_branches, paths_explored, degraded?: str}` | No |
| `resolve_compile_config` (helper) | `dataset_path` | `{found, compile_script?}` | No |
| `write_compile_config` (helper) | `dataset_path`, `script_content?` | writes `compile.sh`; default template enforces `-g -O0 -fno-inline` and forwards `dataset_path` as `$4` | No |

`source_mode` is returned by `build_binary` and **threaded explicitly** by the
caller into both `scan_path_branches` and `verify_with_decisions`. We do not
hide it as tool-internal state — keeping the tools pure-functional makes the
pipeline easier to test and resume.

`dataset_path` on `build_binary` is **optional and forwarded as the 4th
positional arg to `compile.sh`**. Different datasets (Juliet, SARD, custom
benches) live under different roots; the compile script is responsible for
using `$4` to resolve testcasesupport / shared headers / multi-file
companions. Spec does not hardcode any dataset root.

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
  Runtime **starts at the enclosing function's entry via `call_state`** when
  the source node's function name can be resolved (from the SARIF
  `function_sources` table or DWARF symbol lookup). The scanf/fread
  SimProcedure hooks write symbolic bytes directly into the destination
  pointer, so no `SimFileStream` is required and we avoid running through
  `_start → main → …` which can blow the step budget on benchmarks like
  Juliet `_01` variants. Only when the enclosing function cannot be
  resolved do we fall back to `full_init_state(stdin=SimFileStream(BVS))`.
- `mid_function` — DWARF resolves the source `file:line` to an address; runtime
  uses `project.factory.call_state(addr=source_addr)` and stores symbolic BVs
  into a scratch buffer indexed by the attack predicate's `byte_offset`.
- `entry_fallback` — DWARF cannot map the source line (e.g. inlined despite
  `-fno-inline`, or symbol stripped); runtime falls back to
  `call_state(func_entry_addr)`. Result is marked `degraded`.

Note on the scanf-family SimProcedure: `num_args` MUST be set explicitly
(via constructor) so that angr's calling-convention resolver pulls the
variadic destination pointers. Declaring `def run(self, *args)` yields
`num_args=0` and the hook silently injects zero bytes — taint never reaches
the program and every downstream conditional is concrete-True. This is a
non-obvious angr footgun and is enforced in `path_executor._make_scanf_hook`.

#### `scan_path_branches`

Sole purpose: enumerate the tainted-branch candidates the agent must rule on.

1. Load binary via angr (existing `SymbolicExecutor` is restructured here).
2. Initialize state per `source_mode` (see above). Tag the initial symbolic
   bytes with `taint_id` annotations.
3. Walk the path: `explore(find=next_intermediate_addr, ...)` from source
   through every intermediate, stopping just before sink.
4. At every conditional jump while exploring, inspect the guard expression's
   AST. If any leaf depends on a tainted byte (`sym_byte_*`), record an entry
   keyed by the guard's basic-block address:

   ```
   {
     "branch_id": "b_<sha1[:8]>",          # stable: hash of (guard_addr, op-chain)
     "file": "<resolved via DWARF rev-lookup>",
     "line": <int>,
     "condition_src": "<text from source via file:line>",
     "surrounding_code": "<+/-2 lines>",
     "taint_vars": ["sym_byte_0", ...],
     "alternatives": [                      # both fork sides of the same jump
       {"guard_repr": "<expr taken side>", "taint_vars": [...]},
       {"guard_repr": "<expr not-taken side>", "taint_vars": [...]}
     ]
   }
   ```

   **branch_id stability**: `branch_id` MUST be deterministic across separate
   Python processes given the same binary + same source line. Hashing the
   claripy AST's `repr` is forbidden, because claripy assigns monotonically
   increasing internal serial numbers to BVS (`sym_byte_0_3_8` vs.
   `sym_byte_0_42_8` for the same source variable). Instead hash
   `(guard_addr, op_chain_fingerprint)`. Stability is required because the
   agent must round-trip these IDs through `verify_with_decisions`.

   **Dedup by conditional, not by fork side**: a single conditional jump
   produces two forked states (taken / not_taken). They share the same
   `guard_addr` and therefore the same `branch_id`; the scanner merges them
   into one entry whose `alternatives[]` lists both guard expressions. The
   agent picks `branch_decisions[branch_id] = true` to mark the *conditional*
   as a sanitizer — not to take one specific side. See §3.3 verify for the
   decision semantics.

5. **Do not solve, do not continue past sink** — except for the in-block
   conditional at `sink_addr` itself; see §3.5.

#### `verify_with_decisions`

1. Fresh state with same `source_mode` initialization.
2. Compose the symbolic input bytes `sym_bytes[byte_offset:byte_offset+width]`
   (big- or little-endian per `project.arch`), build the predicate
   comparison op (`uge/ule/eq/…`, signed flag selects signed opcodes), and
   add it to the initial state's constraints **before** explore.
3. Walk the path the same way as `scan_path_branches`. For each tainted
   branch encountered:
   - `branch_decisions[branch_id] == true` → treat the conditional as a
     sanitizer. The state's path-condition guard at this jump is already
     part of its constraint set; the step function additionally checks
     satisfiability of that guard with the current constraints (including
     the attack predicate). If unsat, the state is pruned (the sanitizer
     incompatible with the attack on this path). If sat, record
     `branch_id` in `sat_branches`.
   - `branch_decisions[branch_id]` missing or `false` → no pruning; angr
     explores both fork sides naturally.
4. `explore(find=sink_addr)`. Apply the §3.5 extra-step extension so the
   in-block conditional at `sink_addr` is captured. Return
   `{reachable, counterexample (32 bytes hex), paths_explored,
   sat_branches: [branch_ids whose include constraint was satisfied]}`.
5. If any step degrades (e.g. DWARF lookup miss for a specific intermediate),
   set `degraded` field with a short reason; the result is still returned.

### 3.4 Attack Predicate Schema

```json
{
  "byte_offset": 0,
  "width": 4,
  "op": ">=" | "<=" | "==" | "!=" | ">" | "<",
  "value": 65536,
  "signed": false
}
```

- `byte_offset` — index into the symbolic input buffer (`libc_stdin`: byte
  position in stdin stream as consumed by the first scanf/fread hook;
  `mid_function`: byte position in the scratch buffer the mid-function entry
  point allocates). The agent picks it from the SARIF source node's
  first-read variable.
- `width` — byte width of the comparison (1/2/4/8). The bytes are composed
  in the project's native endianness so the BV matches in-memory layout.
- `signed` — selects signed vs unsigned comparison opcodes.

We **deliberately do not** use a DWARF-resolved `taint_var` name. The
named-variable approach (proposed in an earlier draft) requires walking
DWARF location lists and matching storage to BVS leaves at the SARIF source
PC, which is brittle under optimization, missing for stripped binaries, and
non-trivial to keep in sync with angr's memory model. `byte_offset` is
stable, language-agnostic, and sufficient for every Juliet rule_id we have
tested.

Compound predicates (AND/OR) are deferred to v2.

### 3.5 Sink-At-Sanitizer Semantics

CodeQL frequently places the sink at the *expression* of the sanitizer's
`if` (`cpp/integer-overflow-tainted` is the canonical case: sink column
points at `abs((long)data)` inside `if (abs((long)data) < sqrt(UINT_MAX))`).
Naively `explore(find=sink_addr)` stops at the first instruction of the
basic block that ends in the tainted conditional jump — *before* that jump
has been evaluated. The result is empty `tainted_branches[]` (scanner) or
trivially `reachable=true` without any sanitizer constraint applied
(verifier).

To recover the intended semantics without modifying the SARIF, both
`scan_path_branches` and `verify_with_decisions` extend exploration past
`sink_addr`:

1. Run `simgr.explore(find=sink_addr, num_find=4)` as before.
2. If any state reaches `sink_addr`, take that state's basic block one to
   three more steps with the `step_func` still attached. This lets the
   in-block conditional fork, the branch collector observe its guard, and
   the verifier apply branch decisions / prune by satisfiability.
3. Verifier marks `reachable=true` iff at least one post-extension
   survivor is satisfiable under the combined constraint set (path
   constraints + included branch guards + attack predicate) **AND its bbl
   history reaches the sink body entry** (see below). Counterexample is
   extracted from the first such survivor.

**Accept-corridor filter (mandatory).** After the extra steps, the
forked descendants of the original found state split between the
sanitizer's *accept* side (fall-through past the cmp/jcc chain) and its
*reject* side (jumped to the else block). Without filtering, both kinds
satisfy `state.satisfiable()` and the verifier would happily pick a
reject-side state as its witness — producing `reachable=true` with a
counterexample that the sanitizer *actually catches*. This is a real
correctness bug; the §3.5 fix mandates:

```python
def sink_body_entry(project, sink_addr, max_walk=8):
    """Walk fall-through (non-taken cmp/jcc edges) from sink_addr until we
    leave the conditional chain. The first non-conditional block reached is
    the 'sink body entry' — the address execution lands at AFTER passing
    every sanitizer guard on the accept side."""
    cur = sink_addr
    for _ in range(max_walk):
        blk = project.factory.block(cur)
        last = blk.capstone.insns[-1]
        if last.mnemonic.startswith('j') and last.mnemonic != 'jmp':
            cur = last.address + last.size   # fall-through
            continue
        return cur
    return cur

# In verifier post-extra-step filtering:
body_entry = sink_body_entry(project, sink_addr)
survivors = [s for s in candidates
             if s.satisfiable()
             and body_entry in list(s.history.bbl_addrs)]
```

When `sink_addr` already points inside the unsafe body (e.g. SARIF places
sink at the actual `imul` instruction, not at the sanitizer's `if`),
`sink_body_entry` returns `sink_addr` unchanged and the filter is a
no-op for all found states. The filter only kicks in when SARIF placed
sink on the sanitizer line.

Consequence for interpretation: when the SARIF sink coincides with the
sanitizer's `if`, `reachable=true` with a counterexample bytes value that
falls inside the sanitizer's accept range means the sanitizer **as
compiled** is bypassable on that input — even though the source-level
sanitizer looks correct. This is a real binary-level finding (typically
caused by signed-cast or constant-folding quirks during compilation) and
should be reported as `bypassable`, *not* as "confirmed false positive".

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

compile.sh is called as:

```
bash compile.sh <source_src> <output_binary> <lang> [<dataset_root>]
```

`<dataset_root>` is the 4th positional arg, forwarded by `build_binary` from
its `dataset_path` parameter. The compile script is responsible for using it
to resolve dataset-specific includes (testcasesupport headers, shared utility
sources, multi-file companions); the spec does not hardcode any particular
layout. Scripts that ignore `$4` keep working on standalone single-file
sources.

Default template (no dataset assumption):

```bash
#!/bin/bash
# Args: <source_src> <output_binary> <lang> [<dataset_root>]
SRC="$1"; OUT="$2"; LANG="${3:-c}"; SRCROOT="${4:-}"
case "$LANG" in
  cpp) CC=g++ ; STD=-std=c++17 ;;
  *)   CC=gcc ; STD=-std=c11   ;;
esac
INC=""
[ -n "$SRCROOT" ] && INC="-I$SRCROOT"
"$CC" $STD -g -O0 -fno-inline $INC "$SRC" -o "$OUT" -lm 2>&1
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

## 11. Change Log

**2026-05-26 evening — reconciliation pass after first end-to-end test on
`CWE190_Integer_Overflow__unsigned_int_fscanf_square_01.c`:**

- §3.1 — tool surface clarified as **4 core + 2 compile helpers**; legacy
  `build_harness` compatibility wrapper removed; `source_mode` documented
  as a caller-threaded arg; `build_binary` gains optional `dataset_path`.
- §3.3 `build_binary` — `libc_stdin` start changed from `full_init_state`
  to `call_state(source_function_entry)` whenever the source-enclosing
  function is resolvable. Added explicit warning about angr's
  `num_args=0` footgun in `_make_scanf_hook`.
- §3.3 `scan_path_branches` — output schema gains `alternatives[]`;
  branches deduped by `guard_addr`; `branch_id` stability requirement
  formalised (no `ast!r` in the hash).
- §3.3 `verify_with_decisions` — predicate now composed from
  `byte_offset`/`width` and added pre-explore; branch decision semantics
  re-stated as satisfiability-pruning rather than guard-side-forcing.
- §3.4 — attack predicate schema migrated from `taint_var` to
  `byte_offset`; rationale recorded.
- §3.5 (new) — sink-at-sanitizer extra-step semantics; interpretation
  guidance for "bypassable" vs "false positive".
- §5 — compile.sh accepts `dataset_root` as 4th positional arg; default
  template no longer hardcodes any project path.
- §3.5 — added the **accept-corridor filter** to fix a real correctness
  bug where `verify_with_decisions` could report `reachable=true` with a
  counterexample from a state that actually jumped to the sanitizer's
  reject side. Verified on CWE-190 `_01.c`: pre-fix returned a bogus
  `cex=0x80000000` (which fails `data ≥s 0xffff0002`); post-fix returns
  `cex=0xffff8000` (truly inside the binary-level bypass window
  `[0xffff0002, 0xffffffff]`), and `attack: data == 65536` now correctly
  reports `reachable=false`.
