---
name: constraint-generator
description: |
  基于漏洞类型构造用于 angr 符号执行的污点约束条件，验证 sanitizer 是否有效。
  接收漏洞信息（rule_id, sink_function, function_code, context），生成 input_constraints 和 output_constraints。
  用于判定：如果存在路径满足 input_constraints 但不满足 output_constraints，则 sanitizer 未生效/存在漏洞。
  支持 command_injection, sql_injection, buffer_overflow, format_string, path_traversal 等漏洞类型。
input_schema:
  rule_id: string
  sink_function: string
  function_code: string
  context: object
output_schema:
  constraints: array
    - constraint_id: string
      description: string
      vulnerability_type: string
      input_constraints: array
      output_constraints: array
      verification_logic: string
---

# 约束生成器 (Constraint Generator)

## 用途

基于漏洞类型构造用于 angr 符号执行的污点约束条件，用于验证 sanitizer 的有效性。

核心判定逻辑：
- **输入约束 (input_constraints)**：定义"危险输入"，模拟攻击者的输入
- **输出约束 (output_constraints)**：定义"安全输出"，验证 sanitizer 的输出
- **可满足性判定**：如果存在路径满足 input 但不满足 output，则 sanitizer 未生效/存在漏洞

## 输入格式

```json
{
  "rule_id": "cpp/command-line-injection",
  "sink_function": "system",
  "function_code": "void run_cmd(char* input) { char buf[64]; sanitize(input, buf); system(buf); }",
  "context": {
    "vulnerability_type": "command_injection",
    "buffer_size": 64,
    "line_number": 42
  }
}
```

### 字段说明

| 字段 | 类型 | 说明 |
|------|------|------|
| `rule_id` | string | CodeQL/SARIF 规则ID |
| `sink_function` | string | 接收污点的 sink 函数名 |
| `function_code` | string | 包含 sanitizer 的函数代码片段 |
| `context.vulnerability_type` | string | 漏洞类型（见下方支持类型） |
| `context.buffer_size` | number | 目标缓冲区大小（用于 buffer_overflow） |
| `context.line_number` | number | 代码行号 |

## 支持的漏洞类型

| 漏洞类型 | 描述 | 危险特征 |
|----------|------|----------|
| `command_injection` | 命令注入 | shell 元字符 (; \| & ` $ ( ) { } < >) |
| `sql_injection` | SQL注入 | SQL关键字 (' " OR AND ; --) |
| `buffer_overflow` | 缓冲区溢出 | 长度超过缓冲区大小 |
| `format_string` | 格式化字符串 | 格式说明符 (%n %p %x %s) |
| `path_traversal` | 路径遍历 | 路径跳转 (../ ..\ ~) |

## 输出格式

### Constraint 结构

```json
{
  "constraint_id": "cst_001",
  "description": "命令注入约束 - 过滤 shell 元字符",
  "vulnerability_type": "command_injection",
  "input_constraints": [
    {
      "type": "contains_any",
      "description": "输入必须包含至少一个危险字符（模拟攻击）",
      "chars": [";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">"]
    }
  ],
  "output_constraints": [
    {
      "type": "not_contains_any",
      "description": "输出不能包含危险字符（验证 sanitizer）",
      "chars": [";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">"]
    }
  ],
  "verification_logic": "如果存在路径：输入有危险字符且输出也有危险字符 → 未净化/存在漏洞"
}
```

### Constraint 类型定义

| 类型 | 说明 | 参数 |
|------|------|------|
| `contains_any` | 包含任意指定字符 | `chars`: 字符列表 |
| `not_contains_any` | 不包含任何指定字符 | `chars`: 字符列表 |
| `contains_all` | 包含所有指定字符 | `chars`: 字符列表 |
| `length_range` | 长度在范围内 | `min`, `max` |
| `matches_regex` | 匹配正则表达式 | `pattern`: 正则模式 |
| `always_true` | 无约束（用于 passthrough） | 无 |

## 漏洞类型详细示例

### 1. Command Injection (命令注入)

**输入示例：**
```json
{
  "rule_id": "cpp/command-line-injection",
  "sink_function": "system",
  "function_code": "void exec(char* input) { char cmd[128]; clean(input, cmd); system(cmd); }",
  "context": { "vulnerability_type": "command_injection", "buffer_size": 128 }
}
```

**输出约束：**
```json
{
  "constraint_id": "cst_cmd_001",
  "description": "命令注入约束 - 检测危险字符是否被过滤",
  "vulnerability_type": "command_injection",
  "input_constraints": [
    {
      "type": "contains_any",
      "description": "输入必须包含至少一个 shell 元字符",
      "chars": [";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">"]
    }
  ],
  "output_constraints": [
    {
      "type": "not_contains_any",
      "description": "输出不能包含 shell 元字符",
      "chars": [";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">"]
    }
  ],
  "verification_logic": "如果存在路径：输入有 shell 元字符且输出也有 shell 元字符 → 未净化/存在漏洞"
}
```

### 2. SQL Injection (SQL注入)

**输入示例：**
```json
{
  "rule_id": "cpp/sql-injection",
  "sink_function": "sqlite3_exec",
  "function_code": "void query(char* input) { char sql[256]; escape(input, sql); sqlite3_exec(db, sql, ...); }",
  "context": { "vulnerability_type": "sql_injection", "buffer_size": 256 }
}
```

**输出约束：**
```json
{
  "constraint_id": "cst_sql_001",
  "description": "SQL注入约束 - 检测 SQL 关键字是否被转义",
  "vulnerability_type": "sql_injection",
  "input_constraints": [
    {
      "type": "contains_any",
      "description": "输入必须包含至少一个 SQL 危险字符",
      "chars": ["'", "\"", ";", "-", "*", "/", "%", "_"]
    }
  ],
  "output_constraints": [
    {
      "type": "matches_regex",
      "description": "输出必须是参数化查询或已正确转义",
      "pattern": "^(SELECT|INSERT|UPDATE|DELETE).*\\?(?!.*['\";])"
    }
  ],
  "verification_logic": "如果存在路径：输入有 SQL 危险字符且输出可破坏查询语法 → 未净化/存在漏洞"
}
```

### 3. Buffer Overflow (缓冲区溢出)

**输入示例：**
```json
{
  "rule_id": "cpp/buffer-overflow",
  "sink_function": "strcpy",
  "function_code": "void copy(char* input) { char buf[64]; check_and_copy(input, buf); strcpy(dst, buf); }",
  "context": { "vulnerability_type": "buffer_overflow", "buffer_size": 64 }
}
```

**输出约束：**
```json
{
  "constraint_id": "cst_buf_001",
  "description": "缓冲区溢出约束 - 检测长度是否被限制",
  "vulnerability_type": "buffer_overflow",
  "input_constraints": [
    {
      "type": "length_range",
      "description": "输入长度超过缓冲区大小",
      "min": 65,
      "max": 1024
    }
  ],
  "output_constraints": [
    {
      "type": "length_range",
      "description": "输出长度必须在安全范围内",
      "min": 0,
      "max": 63
    }
  ],
  "verification_logic": "如果存在路径：输入长度超过缓冲区且输出长度也超过缓冲区 → 未净化/存在漏洞"
}
```

### 4. Format String (格式化字符串)

**输入示例：**
```json
{
  "rule_id": "cpp/format-string",
  "sink_function": "printf",
  "function_code": "void log_msg(char* input) { char msg[128]; filter(input, msg); printf(msg); }",
  "context": { "vulnerability_type": "format_string", "buffer_size": 128 }
}
```

**输出约束：**
```json
{
  "constraint_id": "cst_fmt_001",
  "description": "格式化字符串约束 - 检测格式说明符是否被移除",
  "vulnerability_type": "format_string",
  "input_constraints": [
    {
      "type": "contains_any",
      "description": "输入必须包含至少一个格式说明符",
      "chars": ["%n", "%p", "%x", "%s", "%d", "%f"]
    }
  ],
  "output_constraints": [
    {
      "type": "not_contains_any",
      "description": "输出不能包含危险的格式说明符",
      "chars": ["%n", "%p"]
    },
    {
      "type": "matches_regex",
      "description": "输出中的 % 必须被正确转义（%%）",
      "pattern": "^(?!.*%[npxsdf])"
    }
  ],
  "verification_logic": "如果存在路径：输入有 %n/%p 且输出也有 %n/%p → 未净化/存在漏洞"
}
```

### 5. Path Traversal (路径遍历)

**输入示例：**
```json
{
  "rule_id": "cpp/path-traversal",
  "sink_function": "fopen",
  "function_code": "void open_file(char* input) { char path[256]; validate(input, path); fopen(path, \"r\"); }",
  "context": { "vulnerability_type": "path_traversal", "buffer_size": 256 }
}
```

**输出约束：**
```json
{
  "constraint_id": "cst_path_001",
  "description": "路径遍历约束 - 检测路径跳转是否被阻止",
  "vulnerability_type": "path_traversal",
  "input_constraints": [
    {
      "type": "contains_any",
      "description": "输入必须包含至少一个路径跳转字符",
      "chars": ["../", "..\\", "~", ".."]
    },
    {
      "type": "matches_regex",
      "description": "输入匹配路径遍历模式",
      "pattern": "\\.\\.[/\\\\]|~"
    }
  ],
  "output_constraints": [
    {
      "type": "not_contains_any",
      "description": "输出不能包含路径跳转",
      "chars": ["../", "..\\", "~", ".."]
    },
    {
      "type": "matches_regex",
      "description": "输出路径必须是绝对路径或规范化后的相对路径",
      "pattern": "^(/[a-zA-Z0-9._-]+)+$|^[a-zA-Z0-9._-]+(/[a-zA-Z0-9._-]+)*$"
    }
  ],
  "verification_logic": "如果存在路径：输入有 ../ 且输出也有 ../ → 未净化/存在漏洞"
}
```

## 可满足性判定逻辑

### 核心判定公式

```
∃路径: (满足所有 input_constraints) ∧ (不满足任意 output_constraints)
→ sanitizer 未生效 / 存在漏洞
```

### 判定流程

```
1. 生成符号变量表示输入
2. 添加 input_constraints 作为约束条件
3. 使用 angr 进行符号执行
4. 在每个终止状态检查 output_constraints
5. 如果发现状态满足 input 但不满足 output → 报告漏洞
```

### angr 实现示例

```python
import angr
import claripy

def verify_sanitizer(binary_path, constraints):
    """
    验证 sanitizer 是否有效
    
    Args:
        binary_path: 待分析的二进制文件路径
        constraints: 约束条件结构（见上文格式）
    
    Returns:
        dict: 验证结果
    """
    # 创建 angr 项目
    p = angr.Project(binary_path, auto_load_libs=False)
    
    # 创建符号输入
    input_size = 64
    sym_input = claripy.BVS('input', input_size * 8)
    
    # 创建初始状态
    state = p.factory.entry_state(stdin=sym_input)
    
    # 添加 input_constraints
    for constraint in constraints['input_constraints']:
        if constraint['type'] == 'contains_any':
            # 输入必须包含至少一个危险字符
            chars = [ord(c) for c in constraint['chars']]
            byte_constraints = []
            for i in range(input_size):
                for ch in chars:
                    byte_constraints.append(sym_input.get_byte(i) == ch)
            state.solver.add(claripy.Or(*byte_constraints))
        
        elif constraint['type'] == 'length_range':
            # 长度约束（通过添加终止符位置约束实现）
            pass
    
    # 运行符号执行
    simgr = p.factory.simgr(state)
    simgr.explore()
    
    # 检查每个终止状态
    vulnerabilities = []
    for deadended in simgr.deadended:
        # 获取输出（假设输出在内存或寄存器中）
        output = extract_output(deadended)
        
        # 检查 output_constraints
        for oc in constraints['output_constraints']:
            if oc['type'] == 'not_contains_any':
                # 检查输出是否仍包含危险字符
                if contains_any(output, oc['chars']):
                    vulnerabilities.append({
                        'state': deadended,
                        'violated_constraint': oc,
                        'severity': 'high'
                    })
    
    return {
        'vulnerable': len(vulnerabilities) > 0,
        'vulnerabilities': vulnerabilities
    }
```

## 约束组合规则

### 多约束组合

当同时存在多个 input_constraints 时，默认使用 **AND** 关系：

```json
{
  "input_constraints": [
    { "type": "contains_any", "chars": ["../"], ... },
    { "type": "length_range", "min": 10, ... }
  ]
}
```
表示：输入必须包含 "../" **且** 长度至少为 10。

### OR 关系

如需 OR 关系，使用 `type: "or_group"`：

```json
{
  "type": "or_group",
  "constraints": [
    { "type": "contains_any", "chars": [";"] },
    { "type": "contains_any", "chars": ["|"] }
  ]
}
```

## 错误处理

### 未知漏洞类型

如果 `context.vulnerability_type` 不在支持列表中：

```json
{
  "error": "Unknown vulnerability type: xxx",
  "supported_types": ["command_injection", "sql_injection", "buffer_overflow", "format_string", "path_traversal"]
}
```

### 缺少必要参数

如果缺少必要参数（如 buffer_overflow 缺少 buffer_size）：

```json
{
  "error": "Missing required parameter: context.buffer_size",
  "required_for": "buffer_overflow"
}
```

## 完整示例流程

### 请求

```json
{
  "rule_id": "cpp/command-line-injection",
  "sink_function": "system",
  "function_code": "void run(char* input) { char buf[64]; sanitize(input, buf); system(buf); }",
  "context": {
    "vulnerability_type": "command_injection",
    "line_number": 15
  }
}
```

### 响应

```json
{
  "constraint_id": "cst_15_cmd",
  "description": "命令注入约束 - 检测 system() 调用的输入净化",
  "vulnerability_type": "command_injection",
  "input_constraints": [
    {
      "type": "contains_any",
      "description": "输入必须包含 shell 元字符（模拟攻击）",
      "chars": [";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">"]
    },
    {
      "type": "length_range",
      "description": "输入长度在合理范围",
      "min": 1,
      "max": 63
    }
  ],
  "output_constraints": [
    {
      "type": "not_contains_any",
      "description": "输出不能包含 shell 元字符（验证净化）",
      "chars": [";", "|", "&", "`", "$", "(", ")", "{", "}", "<", ">"]
    },
    {
      "type": "length_range",
      "description": "输出长度在安全范围",
      "min": 0,
      "max": 63
    }
  ],
  "verification_logic": "如果存在路径：输入有危险字符且输出也有危险字符 → 未净化/存在漏洞",
  "angr_code": "# 自动生成的 angr 约束代码\nimport claripy\n..."
}
```

## 使用建议

1. **优先使用漏洞类型映射**：根据 `rule_id` 自动推断 `vulnerability_type`，减少人工指定
2. **合理设置长度限制**：根据 `context.buffer_size` 自动计算长度约束
3. **组合约束**：对于复杂场景，组合使用多个约束类型
4. **验证结果审查**：符号执行可能有误报，需要人工审查验证结果
