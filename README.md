# CodeQL-AI

CodeQL-AI 提供一组基于 LLM MCP 的工具，用于优化 CodeQL 静态分析结果。典型使用方式是让 Claude Code 这类 Agent 连接 MCP server：Agent 读取 SARIF、QL 和源码上下文，按固定流程调用工具，完成安全判断，并输出优化后的 QL 或可复用的误报经验。

当前包含 4 类 MCP 工具：

| 工具 | MCP 入口 | 目标 |
|---|---|---|
| Symbolic Sanitizer | `src/mcptools/symbolic_sanitizer.py` | 通过路径引导的符号执行，验证 taint path 上的分支条件是否真的阻断攻击。 |
| Function-Level Sanitizer | `src/mcptools/function_level_sanitizer.py` | 在 taint path 上查找函数，读取函数实现，判断是否存在 CodeQL 未识别的 sanitizer，并写入 patched QL。 |
| QL Optimizer | `src/mcptools/ql_optimizer.py` | 读取 QL 和误报源码，辅助 Agent 生成优化后的 QL 查询。 |
| FP Experience | `src/mcptools/fp_scan_tool.py` 和 `src/mcptools/fp_apply_tool.py` | 先从误报 SARIF 中提取可复用经验，再将经验匹配到后续 QL 优化任务中。 |

## 环境要求

- Python 3.10+
- 支持 MCP 的 Claude Code
- CodeQL CLI：使用会运行 CodeQL 分析的工具时需要
- 对应任务所需的 CodeQL database、SARIF 文件、源码目录和目标 QL 文件

安装 Python 依赖：

```bash
pip install -r requirements.txt
```

`symbolic-sanitizer` 还需要目标源码数据集具备可用的 `compile.sh`。工具提供 `resolve_compile_config` / `write_compile_config`，可用于发现或生成编译脚本。

## Quick Start

下面示例统一使用 `<CODEQL_AI_ROOT>` 作为仓库路径。实际使用时请替换为你的本地绝对路径。

Claude Code 可以从项目根目录的 `.mcp.json` 读取 MCP 配置，也可以从 Claude Code `settings.json` 的 `mcpServers` 字段读取。修改 MCP 配置后，需要重启 Claude Code。

### 1. Symbolic Sanitizer

**目标：** 验证 SARIF taint path 上的分支条件是否是真正的 sanitizer。适用于 CodeQL 报出一条路径，但源码中看起来存在范围检查、类型检查或其他 guard 条件的场景。

**配置 MCP server：**

```json
{
  "mcpServers": {
    "symbolic-sanitizer": {
      "type": "stdio",
      "command": "python3",
      "args": [
        "<CODEQL_AI_ROOT>/src/mcptools/symbolic_sanitizer.py"
      ],
      "cwd": "<CODEQL_AI_ROOT>/src"
    }
  }
}
```

**给 Agent 的启动 prompt：**

```text
用 MCP 工具 symbolic-sanitizer 分析 /data/benchmark/juliet/output/final_good_tree_cwe-190_db.sarif，dataset_root /data/benchmark/juliet/juliet-test-suite-c。完全按 README 调用 MCP tool 的流程执行：解析 SARIF，选择路径，准备 compile.sh，编译二进制，扫描 tainted branches，由你判断 sanitizer branch 和 attack predicate，最后验证每条路径是否 reachable。输出每条 path 的 branch 决策、attack predicate、reachable 结果、counterexample 和最终 false positive 判断。
```

**Agent 调用流程：**

1. 调用 `parse_sarif(sarif_path, dataset_root, output_dir?)`。
2. 读取返回的 `_index.json`，再读取每个 `path_file`，获得完整 path 对象。
3. 调用 `resolve_compile_config(dataset_root)`。如果没有可用脚本，调用 `write_compile_config(dataset_root)`。
4. 对每条 path，从 SARIF message 中推导 `source_api`，例如 `value read by fscanf` 对应 `source_api="fscanf"`。
5. 调用 `build_binary(source_file=path.source.file_path, source_api, compile_script, dataset_path=dataset_root)`。
6. 调用 `scan_path_branches(binary_path, path, source_mode)`。
7. Agent 阅读 `tainted_branches[]`，构造：
   - `branch_decisions`：`{branch_id: true|false}`，其中 `true` 表示将该分支视为 sanitizer。
   - `attack_predicate`：例如 `{"byte_offset": 0, "width": 1, "op": ">=", "value": 127, "signed": true}`。
8. 调用 `verify_with_decisions(binary_path, path, source_mode, branch_decisions, attack_predicate)`。

**主要工具输出：**

- `parse_sarif`：`count`、`paths_dir`、`index_file`。
- `build_binary`：`binary_path`、`source_mode`、`dwarf_ok`。
- `scan_path_branches`：`tainted_branches[]`，包含 `branch_id`、源码位置、条件文本、taint 变量和分支 alternatives。
- `verify_with_decisions`：`reachable`、`counterexample`、`sat_branches`、`paths_explored`。

**最终输出：** Agent 应输出路径级符号验证报告。若在选定 `attack_predicate` 下 `reachable=false`，说明 sanitizer 阻断了攻击路径，该告警很可能是误报。若 `reachable=true` 且存在 counterexample，说明攻击输入仍可到达 sink。

### 2. Function-Level Sanitizer

**目标：** 查找 CodeQL taint path 上经过的函数，判断其中是否存在未被 CodeQL 建模的 sanitizer，并把对应逻辑写入 patched QL。

**配置 MCP server：**

```json
{
  "mcpServers": {
    "function-level-sanitizer": {
      "type": "stdio",
      "command": "python3",
      "args": [
        "<CODEQL_AI_ROOT>/src/mcptools/function_level_sanitizer.py",
        "--stdio"
      ],
      "cwd": "<CODEQL_AI_ROOT>/src"
    }
  }
}
```

**给 Agent 的启动 prompt：**

```text
用 MCP 工具 function-level-sanitizer 分析一个 CodeQL 误报。CodeQL database 是 /data/benchmark/project/codeql-db，原始 QL 是 /data/codeql/queries/cpp/CWE-134/NonConstantFormat.ql。SARIF 中 source 是 /data/project/src/input.c:21 的 data，sink 是 /data/project/src/print.c:88 的 printf。请构造 taint_json，调用 find_potential_functions 查找数据流路径上的潜在 sanitizer，读取每个函数实现，判断是否为有效 sanitizer；如果确认是误报，请把完整 patched QL 写入 <CODEQL_AI_ROOT>/scripts/.CODEQL-AI/patched-ql/NonConstantFormat.ql，并传入 original_ql_path 维护映射表。最后输出候选函数、判断理由、patched QL 路径和映射表路径。
```

**Agent 调用流程：**

1. 根据 SARIF source/sink 构造 `taint_json`：

```json
{
  "source": {
    "source_file_path": "/data/project/src/input.c",
    "source_start_line": 21,
    "source_target_name": "data"
  },
  "sink": {
    "sink_file_path": "/data/project/src/print.c",
    "sink_start_line": 88,
    "sink_target_name": "printf"
  }
}
```

2. 调用 `find_potential_functions(taint_json, database_path)`。
3. 对每个返回的函数，调用 `read_function_implementation(function_name, file_path)`。
4. Agent 根据函数源码判断该函数是否是当前漏洞类型的有效 sanitizer。
5. 如果确认需要修补 QL，Agent 生成完整 QL 内容，并调用 `patch_ql(patched_ql_path, new_content, original_ql_path)`。

**主要工具输出：**

- `find_potential_functions`：`potential_sanitizer_functions`、生成的 SARIF 路径、临时 QL 路径、CodeQL 命令。
- `read_function_implementation`：函数源码、起止行号；如果找不到实现，会提示可能是库函数。
- `patch_ql`：`patched_ql_path`、`patched_ql_dir`、`ql_mappings_path`。

**最终输出：** Agent 应输出 sanitizer 分析结论，并在 `scripts/.CODEQL-AI/patched-ql/` 下生成 patched QL。原始 QL 不会被直接覆盖，映射关系记录在 `scripts/.CODEQL-AI/ql_mappings.json`。

### 3. QL Optimizer

**目标：** 读取 QL 查询和代表性误报源码，由 Agent 分析误报根因并写入优化后的 QL。相比 Function-Level Sanitizer，这个流程更轻量，主要提供受控的文件读取和 patched QL 写入能力。

**配置 MCP server：**

```json
{
  "mcpServers": {
    "ql-optimizer": {
      "type": "stdio",
      "command": "python3",
      "args": [
        "<CODEQL_AI_ROOT>/src/mcptools/ql_optimizer.py"
      ],
      "cwd": "<CODEQL_AI_ROOT>/src"
    }
  }
}
```

**给 Agent 的启动 prompt：**

```text
用 MCP 工具 ql-optimizer 优化 /data/codeql/queries/cpp/CWE-190/IntegerOverflow.ql。误报样例源码是 /data/benchmark/juliet/juliet-test-suite-c/testcases/CWE190_Integer_Overflow/s01/CWE190_char_fscanf_add_83_goodB2G.cpp。请先 inspect_ql_query，再 inspect_source_code，解释误报根因，生成完整优化后的 QL，调用 write_ql_query 写入 patched-ql 目录，并传入 original_ql_path。最后输出优化策略、patched QL 路径和映射表路径。
```

**Agent 调用流程：**

1. 调用 `inspect_ql_query(ql_query)`，读取并概览 QL 文件。
2. 调用 `inspect_source_code(source_code_path)`，读取误报源码文件。
3. Agent 判断问题来自过宽的 source/sink、缺失 barrier、类型不匹配，还是缺失 sanitizer 谓词。
4. 调用 `write_ql_query(ql_name, ql_content, original_ql_path)`，写入完整优化后的 QL 内容。

**主要工具输出：**

- `inspect_ql_query`：QL 文件内容，以及 import 数量、predicate/class 数量、行数、是否存在 `where`/`select` 等摘要。
- `inspect_source_code`：源码内容和基础摘要。
- `write_ql_query`：patched QL 路径和映射信息。

**最终输出：** Agent 应输出优化理由，并把 patched QL 写入 `scripts/.CODEQL-AI/patched-ql/<ql_name>`。

### 4. FP Experience：scan + apply

**目标：** 将已确认的误报 SARIF 转换为可复用知识，并在后续扫描前用这些知识辅助优化 QL。该工具包含两个步骤：

- `fp_scan_tool.py`：从误报 SARIF 中提取 false-positive pattern，并保存到知识库。
- `fp_apply_tool.py`：读取历史经验，将其匹配到目标 QL 文件，并给出修补建议。

#### 4.1 扫描并保存误报经验

**配置 MCP server：**

```json
{
  "mcpServers": {
    "fp-scan": {
      "type": "stdio",
      "command": "python3",
      "args": [
        "<CODEQL_AI_ROOT>/src/mcptools/fp_scan_tool.py",
        "--stdio"
      ],
      "cwd": "<CODEQL_AI_ROOT>/src"
    }
  }
}
```

**给 Agent 的启动 prompt：**

```text
用 MCP 工具 fp-scan 从 /data/benchmark/juliet/output/final_good_tree_cwe-190_db.sarif 中提取误报经验，source_root 是 /data/benchmark/juliet/juliet-test-suite-c，repo_id 是 juliet-test-suite，language 是 cpp，cwe 是 CWE-190。请调用 analyze_fp_report 得到 ruleId、QL 路径、告警位置和 codeFlows；读取关键源码上下文，分析误报类型、root cause、状态转移规则；合并同类误报后调用 save_fp_experience 保存为 low confidence 经验。最后输出 experience_id、知识库路径、pattern_summary 和 transitions。
```

**Agent 调用流程：**

1. 调用 `analyze_fp_report(sarif_path, rule_id_map_path?, source_root?)`。
2. 对代表性告警调用 `read_source_context(file_path, start_line, end_line?, context_lines, source_root?)`。
3. Agent 将误报归类为以下类型之一：
   - `missing_internal_call_sanitizer`
   - `missing_guard_barrier`
   - `wrong_pattern_match`
   - `overly_broad_source`
   - `overly_broad_sink`
   - `type_mismatch_in_condition`
4. Agent 用状态机形式描述误报模式，组织 `initial_states`、`states` 和 `transitions`。
5. 调用 `save_fp_experience(...)` 保存经验。新经验通常应使用 `confidence="low"`。

**主要工具输出：**

- `analyze_fp_report`：`rule_to_ql`、`result_count`、`results[]`，其中包含告警位置、related locations 和 code flows。
- `read_source_context`：目标代码片段及其上下文。
- `save_fp_experience`：`experience_id`、完整经验记录和 `knowledge_file`。

**最终输出：** Agent 应输出已保存的误报知识，供后续 QL 优化复用。

#### 4.2 应用历史误报经验

**配置 MCP server：**

```json
{
  "mcpServers": {
    "fp-apply": {
      "type": "stdio",
      "command": "python3",
      "args": [
        "<CODEQL_AI_ROOT>/src/mcptools/fp_apply_tool.py",
        "--stdio"
      ],
      "cwd": "<CODEQL_AI_ROOT>/src"
    }
  }
}
```

如果希望 Agent 在同一个 Claude Code 会话里继续写入 patched QL，还需要同时配置 `function-level-sanitizer` 或 `ql-optimizer`。原因是 `fp-apply` 负责经验加载和匹配，但本身不暴露 QL 写入工具。

**给 Agent 的启动 prompt：**

```text
用 MCP 工具 fp-apply 为 /data/codeql/queries/cpp/CWE-190/IntegerOverflow.ql 匹配历史误报经验。repo_id 是 juliet-test-suite，language 是 cpp，cwe 是 CWE-190，experience_type 是 false_positive，min_confidence 是 low。请调用 extract_and_match 或先 load_applicable_experiences 再 match_experience_to_ql，输出匹配分数、matched_details、matched_transitions 和最佳修补建议。如果存在 matched=true 且 score>=0.5 的经验，请基于经验说明应如何修改 QL；如已配置 ql-optimizer 或 function-level-sanitizer，请继续写入 patched QL。
```

**Agent 调用流程：**

1. 调用 `extract_and_match(ql_file_path, repo_id?, language?, cwe?, query_id?, experience_type="false_positive", min_confidence="low")`。
2. 或者先调用 `load_applicable_experiences(...)`，再对每条候选经验调用 `match_experience_to_ql(experience, ql_file_path)`。
3. Agent 默认将 `matched=true` 且 `score>=0.5` 的经验视为可应用。
4. Agent 根据 `pattern_summary`、`root_cause`、`fp_type` 和 `transitions` 推导 QL 修补方案。
5. 如果需要写入 patch，调用 `ql-optimizer` 的 `write_ql_query`，或调用 `function-level-sanitizer` 的 `patch_ql`。

**主要工具输出：**

- `load_applicable_experiences`：候选历史经验。
- `match_experience_to_ql`：`matched`、`score`、`matched_details`、`matched_transitions`、`unmatched_transitions`、`suggestion`。
- `extract_and_match`：排序后的 `matches`、`best_match`、`matched_count` 和修补建议。

**最终输出：** Agent 应输出经验到 QL 的匹配报告；如果同时配置了可写 QL 的 MCP server，还应输出 patched QL 文件。

## Patched QL 文件

优化后的 QL 统一写入：

```text
scripts/.CODEQL-AI/patched-ql/
```

QL 映射表路径：

```text
scripts/.CODEQL-AI/ql_mappings.json
```

使用映射表批量替换或还原 QL：

```bash
python3 scripts/swap_ql.py apply scripts/.CODEQL-AI/ql_mappings.json
python3 scripts/swap_ql.py restore scripts/.CODEQL-AI/ql_mappings.json
```

MCP 工具不应直接覆盖原始 QL 文件。

## 开发说明

- MCP server 使用 FastMCP，并通过 STDIO 与 Claude Code 集成。
- `symbolic-sanitizer` 使用 `angr`，需要适合调试分析的二进制，建议使用 `-g -O0 -fno-inline` 编译。
- false-positive experience 默认以低置信度保存，经过验证后再提升置信度，不应直接作为稳定 suppress 规则使用。
- `scripts/.CODEQL-AI/` 是生成文件工作区，用于保存 patched QL、旧 QL 备份和映射表。
