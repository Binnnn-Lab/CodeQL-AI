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
        ├── generate_harness            ← 重构：结构化参数驱动
        ├── resolve_compile_config      ← 新增：数据集编译配置发现
        ├── write_compile_config        ← 新增：写入编译配置
        ├── compile_harness             ← 重构：调用 compile.sh
        └── verify_branch               ← 新增，替代旧验证接口
```

### 2.2 职责分界

| 层 | 职责 | 实现位置 |
|----|------|---------|
| MCP Tool | 确定性原子操作：文件解析、源码读取、harness 生成、编译配置、编译、符号执行 | `src/mcptools/symbolic_sanitizer.py` → `src/libs/symbolic_sanitizer/` |
| Agent (LLM) | 语义推理：分支分析、约束生成；首次遇到新数据集时生成 compile.sh | Agent 自身推理，由 readme.md prompt 引导 |

## 3 Agent 工作流（6 步）

```
Step 1: parse_sarif_detailed          → MCP Tool
Step 2: read_path_context             → MCP Tool
Step 3: 分支分析                       → Agent 推理（无 tool）
Step 4: generate_harness              → MCP Tool（结构化参数驱动）
Step 5: resolve/write compile config  → MCP Tool + Agent（仅首次）
Step 6: compile_harness               → MCP Tool（调用 compile.sh）
Step 7: verify_branch                  → MCP Tool
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

### Step 4: 生成 Harness（MCP Tool）

调用 `generate_harness(target_function, source_file, call_chain, sink_expression, includes)`。

Agent 在 Step 3 中已经分析出了目标函数、调用链、sink 位置。Step 4 将这些结构化信息传给 MCP Tool，由 Tool 拼装出标准化的 C harness 代码。

**Agent 提供语义决策（调用什么、sink 在哪），Tool 负责可靠的代码拼装。**

生成的 harness 结构：

```c
#include <string.h>
// ... includes（由参数指定）

void __sink_reached() {}

char symbolic_input[64];

int main() {
    // call_chain 中的调用序列
    char* result = sanitize(symbolic_input);
    if (validate(result)) {
        __sink_reached();  // sink_expression 位置插入标记
    }
    return 0;
}
```

### Step 5: 编译配置发现（MCP Tool + Agent，仅首次）

调用 `resolve_compile_config(dataset_path)` 检查 `{dataset}/.CodeQL-AI/compile.sh` 是否存在。

- **存在** → 返回 compile.sh 路径，直接进入 Step 6
- **不存在** → 返回 `{"found": false}`，Agent 浏览数据集结构（目录布局、include 目录、依赖文件），生成适用于整个数据集的 `compile.sh`，调用 `write_compile_config(dataset_path, script_content)` 写入

`compile.sh` 约定：接收两个参数 `<harness.c> <output_binary>`，例：

```bash
#!/bin/bash
# {dataset}/.CodeQL-AI/compile.sh
gcc -O0 -g -fno-stack-protector \
    -I ./testcasesupport \
    "$1" \
    ./testcasesupport/io.c \
    -o "$2"
```

**此配置是数据集级别的**：同一数据集的所有 harness 复用同一个 compile.sh，Agent 只在首次遇到新数据集时生成。

### Step 6: 编译 Harness（MCP Tool）

调用 `compile_harness(harness_code, compile_script)`。

Tool 将 harness_code 写入临时文件，调用 compile.sh 编译，返回二进制路径。compile_harness 本身不做任何 include path 探测或编译参数推断——所有编译逻辑由 compile.sh 决定。

### Step 7: 符号执行验证（MCP Tool）

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

### 4.3 generate_harness（重构：结构化参数驱动）

```python
@mcp.tool()
def generate_harness(
    target_function: str,
    source_file: str,
    call_chain: list[str],
    sink_expression: str,
    includes: list[str] = []
) -> dict:
    """
    根据结构化参数生成 C harness 代码。

    Args:
        target_function: 目标净化函数名，如 "validate_cmd"
        source_file: 目标函数所在源文件路径
        call_chain: 调用序列，每个元素是一条 C 语句
                    如 ["char* result = sanitize(symbolic_input);",
                        "int ok = validate_cmd(result);"]
        sink_expression: sink 调用表达式，如 "system(result)"
                         Tool 会在此表达式前插入 __sink_reached()
        includes: 需要 #include 的头文件列表
                  如 ["validate.h", "sanitizer.h"]

    Returns:
        {
            "success": true,
            "harness_code": "#include ...\nvoid __sink_reached() {} ...",
            "error": null
        }
    """
```

Tool 负责拼装固定骨架（`__sink_reached` 定义、`symbolic_input` 声明、main 函数），Agent 只提供语义信息。

### 4.4 resolve_compile_config（新增）

```python
@mcp.tool()
def resolve_compile_config(dataset_path: str) -> dict:
    """
    检查数据集是否已有编译配置。

    查找路径: {dataset_path}/.CodeQL-AI/compile.sh

    Returns:
        {
            "found": true,
            "compile_script": "/path/to/dataset/.CodeQL-AI/compile.sh"
        }
        或
        {
            "found": false,
            "dataset_path": "/path/to/dataset",
            "directory_listing": ["src/", "include/", "testcasesupport/", ...]
        }

    found=false 时返回数据集顶层目录列表，辅助 Agent 分析目录结构以生成 compile.sh。
    """
```

### 4.5 write_compile_config（新增）

```python
@mcp.tool()
def write_compile_config(dataset_path: str, script_content: str) -> dict:
    """
    将 Agent 生成的 compile.sh 写入数据集配置目录。

    写入路径: {dataset_path}/.CodeQL-AI/compile.sh
    自动创建 .CodeQL-AI 目录（如不存在），自动添加可执行权限。

    Args:
        dataset_path: 数据集根目录
        script_content: compile.sh 内容

    Returns:
        {
            "success": true,
            "compile_script": "/path/to/dataset/.CodeQL-AI/compile.sh"
        }
    """
```

### 4.6 compile_harness（重构：调用 compile.sh）

```python
@mcp.tool()
def compile_harness(harness_code: str, compile_script: str) -> dict:
    """
    使用数据集的 compile.sh 编译 harness。

    Args:
        harness_code: harness C 源码
        compile_script: compile.sh 路径（来自 resolve_compile_config）

    流程:
        1. 将 harness_code 写入临时文件 /tmp/harness_xxx/harness.c
        2. 调用: bash {compile_script} /tmp/harness_xxx/harness.c /tmp/harness_xxx/harness_bin
        3. 返回二进制路径

    Returns:
        {
            "success": true,
            "binary_path": "/tmp/harness_xxx/harness_bin",
            "harness_path": "/tmp/harness_xxx/harness.c",
            "error": null
        }
    """
```

compile_harness 本身不做任何 include path 探测或编译参数推断——所有编译逻辑由 compile.sh 决定。

### 4.7 verify_branch（新增，替代旧验证接口）

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
  ├── harness_generator.py     # 重构：generate_harness（结构化参数）+ compile_harness（调用 compile.sh）
  ├── compile_config.py        # 新建：resolve_compile_config + write_compile_config
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
| `harness_generator.py` 中 `generate_harness()` | 用结构化参数版本重写 |
| `harness_generator.py` 中 `_find_header_file()` | Juliet 专用逻辑，由 compile.sh 替代 |
| `harness_generator.py` 中 `_find_io_c()` | Juliet 专用逻辑，由 compile.sh 替代 |
| `harness_generator.py` 中 `_detect_include_paths()` | 由 compile.sh 替代 |
| `harness_generator.py` 中 `compile_harness()` 旧签名 | 用 compile_script 参数版本重写 |
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
| `test_step5_harness_generation.py` | 重构：测试 generate_harness（结构化参数）+ compile_harness（compile.sh） |
| `test_step6_verify_with_constraints.py` | 重构：测试 verify_branch |
| 新增 `test_read_path_context.py` | read_path_context 单元测试 |
| 新增 `test_compile_config.py` | resolve/write_compile_config 单元测试 |
| 新增 `test_verify_branch.py` | verify_branch 集成测试 |
