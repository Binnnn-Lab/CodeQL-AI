# Symbolic Sanitizer — Agent Workflow

You are a security analyst. Given a SARIF file and a dataset root, decide
whether the sanitizers on each taint path actually block the documented
attack, using path-guided selective symbolic execution.

## Setup (MCP)

The tools are exposed as an MCP server. Add this to your project's
`.mcp.json` (or `claude.json` `mcpServers`):

```json
{
  "mcpServers": {
    "symbolic-sanitizer": {
      "type": "stdio",
      "command": "python3",
      "args": ["/path/to/CodeQL-AI/src/mcptools/symbolic_sanitizer.py"],
      "cwd": "/path/to/CodeQL-AI/src"
    }
  }
}
```

The server entry point is `src/mcptools/symbolic_sanitizer.py`. It registers
all 6 tools via FastMCP over STDIO. Restart your Claude Code session after
adding the config — the tools will then appear in the tool list.

Once connected, you invoke the tools exactly as listed in the table below.
The workflow is the same regardless of whether you call them via MCP or
directly via Python — the **agent** drives the loop, the tools handle
compilation and symbolic execution.

## Architecture

- **MCP tools** do all symbolic execution and binary analysis.
- **You** make exactly one judgement per path: which tainted conditionals
  count as sanitizers, plus an attack predicate.

## Tools (4 core + 2 compile helpers)

| Tool | Purpose |
|------|---------|
| `parse_sarif(sarif_path, dataset_root, output_dir?)` | Saves each taint path as `{path_id}.json` + `_index.json` under `output_dir` (default: `{sarif}_paths/`). Returns `count`, `paths_dir`, `index_file` — no path content inline. Use `Read` on `_index.json` to pick a path, then `Read` its `path_file` to get the full object for downstream tools. |
| `build_binary(source_file, source_api, compile_script, dataset_path?)` | Compiles the original source into a debuggable binary. Returns `binary_path`, `source_mode` (`libc_stdin` / `mid_function` / `entry_fallback`), `dwarf_ok`. `dataset_path` is forwarded as the 4th positional arg to compile.sh so dataset-specific scripts can resolve testcasesupport / shared headers. |
| `scan_path_branches(binary_path, path, source_mode)` | Enumerates tainted conditionals along the path. Returns `tainted_branches[]` — see schema below. |
| `verify_with_decisions(binary_path, path, source_mode, branch_decisions, attack_predicate)` | Re-executes the path, prunes by satisfiability under your decisions + attack predicate, explores past sink. Returns `reachable`, `counterexample`, `sat_branches`. |
| `resolve_compile_config(dataset_path)` | Finds an existing `compile.sh` under the dataset. |
| `write_compile_config(dataset_path, script_content?)` | Writes a `compile.sh`; default template enforces `-g -O0 -fno-inline` and forwards `$4` as `SRCROOT`. |

`source_mode` is returned by `build_binary` and must be passed verbatim into
both `scan_path_branches` and `verify_with_decisions`.

## Flow

```
parse_sarif -> index (lightweight summary + path_file pointers)
Read path_file -> full path object
for each path:
    resolve_compile_config (write_compile_config if missing)
    build_binary           (returns source_mode + binary_path)
    scan_path_branches     (returns tainted_branches[])
    -- YOUR DECISION --
    Mark each tainted conditional as sanitizer-or-not.
    Pick the attack predicate (byte_offset + op + value).
    -- END DECISION --
    verify_with_decisions
```

### Step-by-step with concrete values

A complete run for a Juliet CWE-190 `char_fscanf_add` path:

```
1. parse_sarif("/data/batch/final.sarif", "/data/juliet-c")
   → index_file, paths_dir

2. Read _index.json → pick path_0001
   Read path_0001.json → full path object
   Note: source.file_path = ".../char_fscanf_add_83_goodB2G.cpp"
         message = "value read by fscanf"

3. resolve_compile_config("/data/juliet-c")
   → compile_script path (or write_compile_config if missing)

4. build_binary(
     source_file   = path.source.file_path,
     source_api    = "fscanf",            ← extracted from message
     compile_script = <from step 3>,
     dataset_path  = "/data/juliet-c",    ← same as dataset_root
   ) → binary_path, source_mode="libc_stdin"

5. scan_path_branches(binary_path, path=<full path object>, source_mode)
   → tainted_branches[] — agent inspects each one

6. verify_with_decisions(
     binary_path,
     path=<same full path object>,
     source_mode,
     branch_decisions = {"b_e7199060": true},
     attack_predicate = {"byte_offset":0, "width":1, "op":">=", "value":127, "signed":true},
   ) → reachable, counterexample, sat_branches
```

### Deriving `source_api` from the SARIF message

The `source_api` parameter tells `build_binary` which libc function reads
attacker-controlled input.  Extract it from the SARIF `message` field:

| SARIF message pattern | `source_api` |
|----------------------|--------------|
| `"value read by fscanf"` | `"fscanf"` |
| `"value read by scanf"` | `"scanf"` |
| `"value read from fgets"` | `"fgets"` |
| `"value read from recv"` | `"recv"` |
| `"value read from connect_socket"` | `"recv"` |
| `"value read from listen_socket"` | `"recv"` |

The full set of recognized APIs: `scanf`, `fscanf`, `sscanf`, `fgets`, `gets`,
`getc`, `getchar`, `read`, `recv`, `fread`, `recvfrom`, `recvmsg`.  When the
API is one of these, `source_mode` will be `"libc_stdin"`; otherwise it falls
back to `"mid_function"`.

### `dataset_root` vs `dataset_path`

`parse_sarif` takes `dataset_root`; `build_binary` takes `dataset_path`.
They are the **same value** — the root of the dataset checkout (e.g.
`/data/benchmark/juliet/juliet-test-suite-c`).  The different names reflect
their primary role in each tool (path resolution vs. compiler include
resolution), but you pass the same directory to both.

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

`signed` controls whether the symbolic bytes are interpreted as a signed or
unsigned integer when evaluating the comparison.  Set it based on the C type
of the tainted variable:

| C type | `width` | `signed` |
|--------|---------|----------|
| `char` / `signed char` | 1 | `true` |
| `short` / `signed short` | 2 | `true` |
| `int` / `signed int` | 4 | `true` |
| `int64_t` | 8 | `true` |
| `unsigned char` | 1 | `false` |
| `unsigned short` | 2 | `false` |
| `unsigned int` / `uint32_t` | 4 | `false` |
| `uint64_t` | 8 | `false` |

When in doubt, check the source file: the variable declaration near
`source.line_number` tells you the type.

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
- `degraded` field present → DWARF missing or `source_mode=entry_fallback`;
  mark confidence lower.

## Report format

```markdown
## Path-Guided Symbolic Verification Report

### SARIF Overview
- Paths analysed: {N}
- Dataset: {dataset_root}

### Per-Path Verdicts

| path_id | rule_id | entry | sink line | branches included | reachable  | counterexample |
|---------|---------|-------|-----------|-------------------|-----------|----------------|
| ... | ... | ... | ... | ... | Yes/No |  ... |

### Detailed Analysis
For each path: list the tainted branches you saw, which you marked as
sanitizers and why, the attack predicate you chose, the angr result, and
your conclusion.
```
