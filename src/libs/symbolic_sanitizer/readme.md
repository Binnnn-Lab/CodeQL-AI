# Symbolic Sanitizer — Agent Workflow

You are a security analyst. Given a SARIF file and a dataset root, decide
whether the sanitizers on each taint path actually block the documented
attack, using path-guided selective symbolic execution.

## Architecture

- **MCP tools** do all symbolic execution and binary analysis.
- **You** make exactly one judgement per path: which tainted conditionals
  count as sanitizers, plus an attack predicate.

## Tools (4 core + 2 compile helpers)

| Tool | Purpose |
|------|---------|
| `parse_sarif(sarif_path, dataset_root)` | Returns taint paths with absolute file paths and enclosing-function source code for every node. |
| `build_binary(source_file, source_api, compile_script, dataset_path?)` | Compiles the original source into a debuggable binary. Returns `binary_path`, `source_mode` (`libc_stdin` / `mid_function` / `entry_fallback`), `dwarf_ok`. `dataset_path` is forwarded as the 4th positional arg to compile.sh so dataset-specific scripts can resolve testcasesupport / shared headers. |
| `scan_path_branches(binary_path, path, source_mode)` | Enumerates tainted conditionals along the path. Returns `tainted_branches[]` — see schema below. |
| `verify_with_decisions(binary_path, path, source_mode, branch_decisions, attack_predicate)` | Re-executes the path, prunes by satisfiability under your decisions + attack predicate, explores past sink. Returns `reachable`, `counterexample`, `sat_branches`. |
| `resolve_compile_config(dataset_path)` | Finds an existing `compile.sh` under the dataset. |
| `write_compile_config(dataset_path, script_content?)` | Writes a `compile.sh`; default template enforces `-g -O0 -fno-inline` and forwards `$4` as `SRCROOT`. |

`source_mode` is returned by `build_binary` and must be passed verbatim into
both `scan_path_branches` and `verify_with_decisions`.

## Flow

```
parse_sarif -> paths[]
for each path:
    resolve_compile_config (write_compile_config if missing)
    build_binary           (returns source_mode)
    scan_path_branches     (returns tainted_branches[])
    -- YOUR DECISION --
    Mark each tainted conditional as sanitizer-or-not.
    Pick the attack predicate (byte_offset + op + value).
    -- END DECISION --
    verify_with_decisions
```

## `tainted_branches[]` schema

One entry per **conditional jump address** (the two fork sides of the same
jump are merged):

```json
{
  "branch_id": "b_<sha1[:8]>",
  "file": "...", "line": 63,
  "condition_src": "    if (abs((long)data) < (long)sqrt((double)UINT_MAX))",
  "surrounding_code": "<+/-2 lines>",
  "taint_vars": ["sym_byte_0", "sym_byte_1", ...],
  "alternatives": [
    {"guard_repr": "data <s 0xffff0002", "taint_vars": [...]},
    {"guard_repr": "data >=s 0xffff0002", "taint_vars": [...]}
  ]
}
```

`branch_id` is stable across processes for the same binary + same source
line, so you can safely round-trip it through `verify_with_decisions`.

## How to choose `branch_decisions`

`branch_decisions` is `{branch_id: bool}`:
- `true`  → treat this conditional as a sanitizer. The verifier will
  *prune* any state whose path through this conditional is unsatisfiable
  with the attack predicate; states that survive are recorded in
  `sat_branches`. You do **not** pick a fork side — both alternatives are
  considered, and only the satisfiable ones survive.
- `false` (or missing) → no pruning; angr explores both fork sides
  naturally.

Mark `true` when the condition looks like a sanitizer:
- Compares a taint variable against a constant (range/length check).
- Validates format (`isdigit`, `isalpha`, character allowlists).
- Guards code that flows into the sink (the SARIF path tells you this).

Mark `false` (or omit) for:
- Loop iteration tests (`i < n`).
- Environment/config checks unrelated to the data.

## Attack predicate schema

```json
{
  "byte_offset": 0,
  "width": 4,
  "op": ">=" | "<=" | "==" | "!=" | ">" | "<",
  "value": 65536,
  "signed": false
}
```

`byte_offset` indexes into the symbolic input buffer:
- `libc_stdin`: byte position in the stdin stream consumed by the first
  scanf/fread-family hook.
- `mid_function`: byte position in the scratch buffer the mid-function
  entry point allocates for the target variable.

`width` is 1/2/4/8. Bytes are composed in the target's native endianness,
so the BV matches in-memory layout.

## Pick the attack predicate by rule_id

| rule_id | Typical predicate |
|---------|-------------------|
| `cpp/integer-overflow-tainted` (uint32 mul) | `byte_offset=0, width=4, op=">=", value=65536` |
| `cpp/integer-overflow-tainted` (int8 add)   | `byte_offset=0, width=1, op=">=", value=127`   |
| `cpp/non-constant-format`                   | `op="==", value=0x73`  (`'%s'` indicator byte) |
| `cpp/uncontrolled-allocation-size`          | `width=4, op=">=", value=<large>`              |

(Starting points — use your judgement.)

## Result interpretation

- `reachable=false` → sanitizer holds against the attack predicate; the
  finding is a **confirmed false positive**.
- `reachable=true` with counterexample → the path reaches the sink under
  some attacker-controlled input.
  - If the counterexample lies *inside* the sanitizer's accept range
    (e.g. for CWE-190 `fscanf_square`, a value like `0x80000000` that the
    compiled signed compare lets through despite the source-level
    `abs() < sqrt(UINT_MAX)` looking correct), report as **bypassable at
    the binary level** — this is a real finding caused by signed-cast or
    constant-folding quirks in the compiled sanitizer, not a confirmation
    of the CodeQL alert at the source level.
  - Otherwise it's a straightforward true positive.
- `degraded` field present → DWARF missing or `source_mode=entry_fallback`;
  mark confidence lower.

### Note on `sink` coinciding with the sanitizer line

CodeQL sometimes places the sink expression *inside* the sanitizer's `if`
condition (CWE-190 `cpp/integer-overflow-tainted` is the canonical case).
The tools handle this by extending exploration a few basic blocks past
`sink_addr` so the in-block conditional is captured (scan) and constrained
(verify). You do not need to massage the SARIF — just pass it through.

## Report format

```markdown
## Path-Guided Symbolic Verification Report

### SARIF Overview
- Paths analysed: {N}
- Dataset: {dataset_root}

### Per-Path Verdicts

| path_id | rule_id | entry | sink line | branches included | reachable | verdict | counterexample |
|---------|---------|-------|-----------|-------------------|-----------|---------|----------------|
| ... | ... | ... | ... | ... | Yes/No | confirmed-FP / bypassable / true-positive | ... |

### Detailed Analysis
For each path: list the tainted branches you saw, which you marked as
sanitizers and why, the attack predicate you chose, the angr result, and
your conclusion.
```
