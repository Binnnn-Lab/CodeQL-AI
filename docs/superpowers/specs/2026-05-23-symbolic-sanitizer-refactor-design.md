# Symbolic Sanitizer 重构设计：分支级选择性符号执行

## 1 目标

重构 `symbolic_sanitizer` MCP Server，将 LLM 的核心价值从"选函数"提升为"选分支/路径条件"，使其更贴合"AI 辅助代码审计"叙事。

### 1.1 非目标

- 不涉及 `function_level_sanitizer` 的改动
- 不实现多语言支持（仅 C/C++）
- 不实现闭环修正（不自动调用 patch_ql）
- 不改变 MCP Server 的运行方式（仍为独立进程）

## 2 架构

### 2.1 系统组成

```
Agent (由 src/libs/symbolic_sanitizer/readme.md prompt 驱动)
  │
  ├── MCP Server: function_level_sanitizer (不动)
  │     ├── find_potential_functions
  │     ├── read_function_implementation
  │     └── patch_ql
  │
  └── MCP Server: symbolic_sanitizer (重构)
        ├── parse_sarif_detailed        ← 保留
        ├── read_path_context           ← 新增
        ├── compile_harness             ← 保留，去除 Juliet 硬编码
        └── verify_branch               ← 新增，替代旧验证接口
```

### 2.2 职责分界

| 层 | 职责 | 实现位置 |
|----|------|---------|
| MCP Tool | 确定性原子操作：文件解析、源码读取、编译、符号执行 | `src/mcptools/symbolic_sanitizer.py` → `src/libs/symbolic_sanitizer/` |
| Agent (LLM) | 语义推理：分支分析、约束生成、harness 代码生成 | Agent 自身推理，由 readme.md prompt 引导 |

## 3 Agent 工作流（6 步）

```
Step 1: parse_sarif_detailed          → MCP Tool
Step 2: read_path_context             → MCP Tool
Step 3: 分支分析                       → Agent 推理（无 tool）
Step 4: 生成 harness                   → Agent 生成代码（无 tool）
Step 5: compile_harness                → MCP Tool
Step 6: verify_branch                  → MCP Tool
```

### Step 1: 解析 SARIF

调用 `parse_sarif_detailed(sarif_path)`，提取污点路径列表。每条路径包含 source、sink、intermediate_locations、rule_id、message。

输入：SARIF 文件路径。
输出：TaintPath 列表。

### Step 2: 读取路径上下文

调用 `read_path_context(locations)`，批量读取路径上所有节点所在函数的源码。

输入：Step 1 中路径的所有节点 `[{file_path, line_number, function_name}, ...]`（包含 source、sink、所有 intermediate）。
输出：每个节点对应的函数完整源码。

### Step 3: 分支分析（Agent 推理）

LLM 阅读 Step 2 返回的全部源码，完成：

1. 识别路径上所有与净化相关的分支条件（if/switch/循环守卫）
2. 判断哪个分支是关键净化逻辑，标注文件+行号+条件表达式
3. 判断净化类型：判定型（branch guard）或过滤型（字符替换/删除）
4. 根据漏洞类型（rule_id）生成攻击输入约束
5. 给出初步判断和置信度

输出格式：

```json
{
  "target_branch": {
    "file": "src/validate.c",
    "line": 25,
    "condition": "if(strchr(input, ';') != NULL)"
  },
  "sanitization_type": "判定型",
  "input_constraints": [
    {"type": "contains_any", "chars": [";", "|", "&"]}
  ],
  "confidence": "medium",
  "reasoning": "strchr 检查了分号但未检查管道符和 &，可能存在绕过"
}
```

### Step 4: 生成 Harness（Agent 生成）

LLM 根据 Step 3 的分析结果，生成定制化的 C 测试代码。

Harness 需满足：
- 包含目标函数的调用链
- 使用 `char symbolic_input[64]` 作为符号输入
- 在 sink 位置插入 `__sink_reached()` 标记函数调用
- `__sink_reached` 定义为空函数，仅作为 angr 的探测目标

Harness 模板参考（Agent 可根据实际情况调整）：

```c
#include <string.h>
// ... 必要的 include

void __sink_reached() {}

char symbolic_input[64];

int main() {
    // 调用路径上的函数链
    char* result = sanitize(symbolic_input);
    if (validate(result)) {
        __sink_reached();  // sink 标记
    }
    return 0;
}
```

### Step 5: 编译 Harness

调用 `compile_harness(harness_code, source_file)`，编译 Agent 生成的 harness。

### Step 6: 符号执行验证

调用 `verify_branch(binary_path, constraints, sink_marker, timeout)`。

angr 的验证逻辑：
1. 创建符号输入，施加 input_constraints
2. 设置 exploration：find = `sink_marker` 函数地址
3. 运行符号执行
4. 如果 `simgr.found` 非空 → `reachable = True`（净化无效，存在绕过）
5. 如果 `simgr.found` 为空 → `reachable = False`（净化有效）

## 4 MCP Tool 接口设计

### 4.1 parse_sarif_detailed（保留，不变）

```python
@mcp.tool()
def parse_sarif_detailed(sarif_path: str) -> dict:
```

### 4.2 read_path_context（新增）

```python
@mcp.tool()
def read_path_context(locations: list[dict]) -> dict:
    """
    批量读取污点路径上所有节点的函数源码。

    Args:
        locations: 节点列表，每个节点包含：
            - file_path: 源文件路径
            - line_number: 行号
            - function_name: 函数名（可选，为 None 时按行号定位所在函数）

    Returns:
        {
            "success": true,
            "context": [
                {
                    "file_path": "src/a.c",
                    "function_name": "foo",
                    "line_number": 25,
                    "source_code": "int foo(char* input) { ... }",
                    "start_line": 20,
                    "end_line": 35
                },
                ...
            ],
            "failed": [
                {"file_path": "lib/unknown.c", "line_number": 10, "reason": "file not found"}
            ]
        }
    """
```

实现要点：
- 复用 `lib_sanitizer.read_function_implementation` 的花括号匹配逻辑
- 对 `function_name` 为 `None` 的节点，扫描文件找到包含 `line_number` 的函数定义
- 去重：同一函数只返回一次
- 失败的节点收集到 `failed` 列表，不中断整体流程

### 4.3 compile_harness（保留，简化）

```python
@mcp.tool()
def compile_harness(harness_code: str, source_file: str) -> dict:
    """
    编译 harness 代码。

    Returns:
        {
            "success": true,
            "binary_path": "/tmp/harness_xxx/harness_bin",
            "harness_path": "/tmp/harness_xxx/harness.cpp",
            "error": null
        }
    """
```

变更：
- 去掉 `_find_header_file` 中对 Juliet 后缀（`_goodB2G` 等）的处理
- 去掉 `_find_io_c` 逻辑
- 保留通用的 include path 探测

### 4.4 verify_branch（新增，替代旧验证接口）

```python
@mcp.tool()
def verify_branch(
    binary_path: str,
    constraints: dict,
    sink_marker: str = "__sink_reached",
    timeout: int = 120
) -> dict:
    """
    用 angr 验证攻击输入能否到达 sink 标记点。

    Args:
        binary_path: 编译后的二进制路径
        constraints: {"input_constraints": [...]}
        sink_marker: harness 中 sink 标记函数名
        timeout: 符号执行超时秒数

    Returns:
        {
            "success": true,
            "reachable": false,
            "paths_explored": 15,
            "paths_to_sink": 0,
            "counterexample": null,
            "error": null
        }

    reachable=true 时 counterexample 为满足约束且到达 sink 的具体输入（hex）。
    """
```

## 5 libs 层实现结构

```
src/libs/symbolic_sanitizer/
  ├── __init__.py              # 导出公共接口
  ├── sarif_parser.py          # 保留，删除 parse_sarif 简版函数
  ├── path_context.py          # 新建：read_path_context 逻辑
  ├── harness_generator.py     # 简化：只保留 compile_harness
  ├── symbolic_sanitizer.py    # 重构：去掉 I/O 对比，改为 sink 可达性
  ├── verifier.py              # 保留
  └── readme.md                # 重写：新工作流 prompt
```

### 5.1 symbolic_sanitizer.py 重构

`SymbolicExecutor` 类重构：

**删除**：
- `execute()` 方法（旧的无约束执行）
- `execute_with_constraints()` 方法（I/O 对比逻辑）
- `_analyze_constrained_results()` 方法
- `_build_not_contains_any_constraint()` / `check_output_constraints()` 等输出约束相关方法

**新增**：
- `execute_reachability(constraints, sink_marker, timeout)` 方法

```python
def execute_reachability(
    self, constraints: dict, sink_marker: str, timeout: int
) -> dict:
    """
    检测满足 input_constraints 的输入能否到达 sink_marker 函数。

    核心逻辑：
    1. 查找 main 和 sink_marker 的地址
    2. 创建符号输入，施加 input_constraints
    3. simgr.explore(find=sink_addr)
    4. 如果 found 非空 → reachable=True，提取 counterexample
    5. 如果 found 为空 → reachable=False
    """
```

**保留**：
- `_find_function()` 方法
- `_build_contains_any_constraint()` 方法
- `_build_length_range_constraint()` 方法
- `_build_input_constraint()` 方法
- `apply_input_constraints()` 方法

### 5.2 path_context.py 新建

```python
def read_path_context(locations: list[dict]) -> dict:
    """
    批量读取节点源码。

    对每个节点：
    1. 如果有 function_name → 用 read_function_implementation 提取
    2. 如果 function_name 为 None → 用 find_enclosing_function 按行号定位
    3. 去重（同文件同函数只保留一份）
    4. 收集失败节点
    """

def find_enclosing_function(file_path: str, line_number: int) -> dict:
    """
    给定文件和行号，找到包含该行的函数定义。
    向上扫描找函数签名，向下匹配花括号找函数结束。
    """
```

## 6 删除清单

| 文件/函数 | 原因 |
|-----------|------|
| `symbolic_sanitizer.py` 中 `execute()` | 被 `execute_reachability()` 替代 |
| `symbolic_sanitizer.py` 中 `execute_with_constraints()` | 被 `execute_reachability()` 替代 |
| `symbolic_sanitizer.py` 中 `_analyze_constrained_results()` | I/O 对比逻辑不再使用 |
| `symbolic_sanitizer.py` 中 `check_output_constraints()` | 不再检查输出 |
| `symbolic_sanitizer.py` 中 `_build_not_contains_any_constraint()` | 不再有输出约束 |
| `symbolic_sanitizer.py` 中 `_build_output_constraint()` | 不再有输出约束 |
| `symbolic_sanitizer.py` 中 `_check_bytes_contain_dangerous_chars()` | I/O 对比专用 |
| `symbolic_sanitizer.py` 中 `_extract_dangerous_chars_from_constraints()` | I/O 对比专用 |
| `symbolic_sanitizer.py` 中 `PathAnalysisResult` 数据类 | I/O 对比专用 |
| `symbolic_sanitizer.py` 中 `SymbolicExecutionResult` 数据类 | 用新的返回 dict 替代 |
| `harness_generator.py` 中 `generate_harness()` | harness 改由 Agent 生成 |
| `harness_generator.py` 中 `_find_header_file()` | Juliet 专用逻辑 |
| `harness_generator.py` 中 `_find_io_c()` | Juliet 专用逻辑 |
| `sarif_parser.py` 中 `parse_sarif_result()` | 只保留 detailed 版本 |
| `mcptools/symbolic_sanitizer.py` 中 `parse_sarif()` tool | 只保留 detailed 版本 |
| `mcptools/symbolic_sanitizer.py` 中 `generate_harness()` tool | 改由 Agent 生成 |
| `mcptools/symbolic_sanitizer.py` 中 `verify_sanitization()` tool | 被 verify_branch 替代 |
| `mcptools/symbolic_sanitizer.py` 中 `verify_with_constraints()` tool | 被 verify_branch 替代 |
| `verifier.py` 中 `SanitizationVerifier` 类 | 编排逻辑移至 Agent prompt |
| `verifier.py` 中 `quick_verify()` 函数 | 编排逻辑移至 Agent prompt |

## 7 测试变更

现有测试文件需要对应更新：

| 测试文件 | 操作 |
|---------|------|
| `test_step1_parse_sarif_detailed.py` | 保留 |
| `test_step2_find_potential_functions.py` | 保留（属于 function_level_sanitizer） |
| `test_step3_function_selector_skill.py` | 删除（function-selector skill 不再使用） |
| `test_step4_constraint_generator_skill.py` | 删除（constraint-generator skill 不再使用） |
| `test_step5_harness_generation.py` | 重构：测试 compile_harness（不含 generate） |
| `test_step6_verify_with_constraints.py` | 重构：测试 verify_branch |
| 新增 `test_read_path_context.py` | read_path_context 单元测试 |
| 新增 `test_verify_branch.py` | verify_branch 集成测试 |
