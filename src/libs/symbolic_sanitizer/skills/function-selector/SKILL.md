---
name: function-selector
description: |
  从 find_potential_functions 返回的候选函数列表中，选择最值得进行符号执行分析的 function。
  基于函数位置、命名语义、漏洞类型匹配度等因素进行综合评估，选出最可能是 sanitizer/validator 的目标函数。
  用于优化符号执行资源分配，优先分析高价值的候选函数。
---

# 函数选择器 (Function Selector)

## 用途

从 taint analysis 识别出的潜在 sanitizer/validator 函数列表中，智能选择最适合进行符号执行验证的目标函数。通过多维度的优先级评估，最大化发现有效漏洞净化的概率。

## 输入格式

### 输入数据结构
```json
{
  "path_id": "path_0001",
  "source": {
    "file_path": "src/input.c",
    "line_number": 10,
    "function_name": "get_user_input"
  },
  "sink": {
    "file_path": "src/exec.c",
    "line_number": 50,
    "function_name": "system"
  },
  "potential_functions": [
    {"name": "sanitize_input", "file": "src/sanitizer.c", "line": 20},
    {"name": "validate_cmd", "file": "src/validate.c", "line": 30},
    {"name": "process_data", "file": "src/process.c", "line": 40}
  ],
  "rule_id": "cpp/command-line-injection",
  "message": "User input reaches system()"
}
```

### 关键字段说明
| 字段 | 类型 | 描述 |
|------|------|------|
| `path_id` | string | 污点路径唯一标识 |
| `source` | object | 污点源信息（用户输入位置） |
| `source.file_path` | string | 源文件路径 |
| `source.line_number` | integer | 源代码行号 |
| `source.function_name` | string | 源函数名 |
| `sink` | object | 污染汇聚点信息 |
| `sink.file_path` | string | sink文件路径 |
| `sink.line_number` | integer | sink代码行号 |
| `sink.function_name` | string | sink函数名 |
| `potential_functions` | array | 候选函数列表 |
| `potential_functions[].name` | string | 函数名 |
| `potential_functions[].file` | string | 函数所在文件 |
| `potential_functions[].line` | integer | 函数定义行号 |
| `rule_id` | string | CodeQL规则ID，用于判断漏洞类型 |
| `message` | string | 漏洞描述信息 |

## 选择标准

### 1. 位置优先级 (Location)

**评估原则**: 优先选择位于 source 和 sink 之间的函数

| 优先级 | 条件 | 说明 |
|--------|------|------|
| High | 位于 source 和 sink 之间 | 数据流路径中间，最可能进行净化处理 |
| Medium | 靠近 sink 的位置 | 可能是 sink 前的最后一道检查 |
| Low | 靠近 source 的位置 | 可能是输入验证，但后续可能绕过 |
| Ignore | 不在调用路径上 | 无法影响该污点路径的函数 |

### 2. 语义优先级 (Semantic)

**评估原则**: 函数名暗示净化/验证语义

| 优先级 | 关键词模式 | 示例函数名 |
|--------|-----------|-----------|
| High | sanitize*, clean*, escape* | sanitize_input, clean_buffer, escape_sql |
| High | validate*, verify*, check* | validate_cmd, verify_path, check_bounds |
| Medium | filter*, encode*, quote* | filter_chars, encode_html, quote_string |
| Medium | is_valid*, can_*, has_* | is_valid_filename, can_execute |
| Low | process*, handle*, prepare* | process_data, handle_request |

### 3. 漏洞类型匹配 (Vulnerability Type)

根据 `rule_id` 判断漏洞类型，优先匹配对应类型的净化函数:

| 漏洞类型 | Rule ID 关键词 | 关注函数名特征 | 示例 |
|----------|---------------|---------------|------|
| command_injection | command, cmd, exec, system, shell | cmd, command, shell, exec | validate_cmd, sanitize_shell |
| sql_injection | sql, query | sql, query, statement | escape_sql, sanitize_query |
| buffer_overflow | buffer, overflow, memcpy, strcpy | buffer, size, length, bounds | check_bounds, validate_size |
| integer_overflow | integer, arithmetic | int, number, overflow | check_overflow, validate_int |
| format_string | format, printf | format, string, print | check_format, validate_printf |
| path_traversal | path, directory, file | path, file, dir, filename | sanitize_path, validate_filename |

### 4. 排除条件

以下类型的函数应该**避免选择**:

| 类型 | 说明 | 示例 |
|------|------|------|
| 系统/库函数 | 标准库或系统调用 | strlen, memcpy, strcpy |
| 通用工具函数 | 与输入处理无关 | print_debug, log_error |
| 过于简单的函数 | 只包含单条语句 | get_flag, is_enabled |
| 与漏洞类型无关 | 功能不匹配当前漏洞 | 文件操作函数在处理 SQL 注入时 |

## 输出格式

### 输出数据结构
```json
{
  "selected_function": {
    "name": "sanitize_input",
    "file": "src/sanitizer.c",
    "line": 20,
    "reason": "函数名包含'sanitize'，位于source和sink之间，针对命令注入漏洞最可能是执行命令过滤的sanitizer"
  }
}
```

### 字段说明
| 字段 | 类型 | 描述 |
|------|------|------|
| `selected_function` | object | 选中的目标函数 |
| `selected_function.name` | string | 函数名 |
| `selected_function.file` | string | 文件路径 |
| `selected_function.line` | integer | 行号 |
| `selected_function.reason` | string | 选择理由的详细说明 |

## 选择逻辑步骤

1. **位置分析**
   - 检查每个候选函数是否位于 source 和 sink 的调用路径上
   - 记录函数在数据流中的相对位置

2. **语义评分**
   - 为每个函数名分配语义权重
   - High 语义关键词: +3 分
   - Medium 语义关键词: +2 分
   - Low 语义关键词: +1 分

3. **漏洞匹配评分**
   - 根据 rule_id 识别漏洞类型
   - 检查函数名是否包含该漏洞类型的相关关键词
   - 匹配: +2 分

4. **综合排序**
   - 总分 = 位置优先级 + 语义评分 + 漏洞匹配评分
   - 选择总分最高的函数
   - 如果分数相同，优先选择位置在 source-sink 中间的函数

## 示例

### 示例 1: 命令注入场景

**输入:**
```json
{
  "path_id": "path_0001",
  "source": {
    "file_path": "src/input.c",
    "line_number": 10,
    "function_name": "get_user_input"
  },
  "sink": {
    "file_path": "src/exec.c",
    "line_number": 50,
    "function_name": "system"
  },
  "potential_functions": [
    {"name": "strlen", "file": "src/utils.c", "line": 5},
    {"name": "process_data", "file": "src/process.c", "line": 40},
    {"name": "sanitize_input", "file": "src/sanitizer.c", "line": 20},
    {"name": "validate_cmd", "file": "src/validate.c", "line": 30},
    {"name": "log_debug", "file": "src/debug.c", "line": 100}
  ],
  "rule_id": "cpp/command-line-injection",
  "message": "User input reaches system()"
}
```

**分析过程:**

| 函数名 | 位置 | 语义评分 | 漏洞匹配 | 排除原因 | 总分 |
|--------|------|----------|----------|----------|------|
| strlen | N/A | 0 | 0 | 标准库函数 | 排除 |
| process_data | 中间 | 1 | 0 | 无 | 1 |
| sanitize_input | 中间 | 3 | 0 | 无 | 3 |
| validate_cmd | 中间 | 3 | 2 (cmd) | 无 | 5 |
| log_debug | N/A | 0 | 0 | 调试函数 | 排除 |

**输出:**
```json
{
  "selected_function": {
    "name": "validate_cmd",
    "file": "src/validate.c",
    "line": 30,
    "reason": "函数名包含'validate'语义关键词(高优先级)，且'cmd'与命令注入漏洞类型直接匹配，位于source和sink之间的调用路径上，最可能是针对命令注入的验证函数"
  }
}
```

### 示例 2: SQL 注入场景

**输入:**
```json
{
  "path_id": "path_0002",
  "source": {
    "file_path": "src/web.c",
    "line_number": 25,
    "function_name": "parse_request"
  },
  "sink": {
    "file_path": "src/db.c",
    "line_number": 80,
    "function_name": "sqlite3_exec"
  },
  "potential_functions": [
    {"name": "check_auth", "file": "src/auth.c", "line": 15},
    {"name": "escape_sql", "file": "src/db_utils.c", "line": 45},
    {"name": "prepare_statement", "file": "src/db.c", "line": 60},
    {"name": "memcpy", "file": "string.h", "line": 1},
    {"name": "is_valid_user", "file": "src/auth.c", "line": 30}
  ],
  "rule_id": "cpp/sql-injection",
  "message": "Tainted data used in SQL query"
}
```

**分析过程:**

| 函数名 | 位置 | 语义评分 | 漏洞匹配 | 排除原因 | 总分 |
|--------|------|----------|----------|----------|------|
| check_auth | 中间 | 0 | 0 | 无 | 0 |
| escape_sql | 中间 | 3 (escape) | 2 (sql) | 无 | 5 |
| prepare_statement | 中间 | 0 | 1 (statement) | 无 | 1 |
| memcpy | N/A | 0 | 0 | 标准库函数 | 排除 |
| is_valid_user | 中间 | 2 (is_valid) | 0 | 无 | 2 |

**输出:**
```json
{
  "selected_function": {
    "name": "escape_sql",
    "file": "src/db_utils.c",
    "line": 45,
    "reason": "函数名包含'escape'语义关键词(高优先级)，且'sql'与SQL注入漏洞类型完全匹配，位于source和sink之间，明确表明是SQL转义/净化函数"
  }
}
```

### 示例 3: 缓冲区溢出场景

**输入:**
```json
{
  "path_id": "path_0003",
  "source": {
    "file_path": "src/network.c",
    "line_number": 30,
    "function_name": "recv_packet"
  },
  "sink": {
    "file_path": "src/buffer.c",
    "line_number": 100,
    "function_name": "memcpy"
  },
  "potential_functions": [
    {"name": "check_bounds", "file": "src/utils.c", "line": 50},
    {"name": "validate_size", "file": "src/utils.c", "line": 55},
    {"name": "strcpy", "file": "string.h", "line": 1},
    {"name": "process_packet", "file": "src/network.c", "line": 45},
    {"name": "log_packet", "file": "src/debug.c", "line": 20}
  ],
  "rule_id": "cpp/overflow-buffer",
  "message": "Potential buffer overflow"
}
```

**分析过程:**

| 函数名 | 位置 | 语义评分 | 漏洞匹配 | 排除原因 | 总分 |
|--------|------|----------|----------|----------|------|
| check_bounds | 中间 | 3 (check) | 1 (bounds) | 无 | 4 |
| validate_size | 中间 | 3 (validate) | 1 (size) | 无 | 4 |
| strcpy | N/A | 0 | 0 | 危险库函数 | 排除 |
| process_packet | 中间 | 1 | 0 | 无 | 1 |
| log_packet | N/A | 0 | 0 | 调试函数 | 排除 |

**输出:**
```json
{
  "selected_function": {
    "name": "validate_size",
    "file": "src/utils.c",
    "line": 55,
    "reason": "函数名包含'validate'语义关键词(高优先级)，且'size'与缓冲区溢出漏洞的边界检查需求匹配，位于source和sink之间。相比'check_bounds'，'size'更直接对应缓冲区大小验证，更适合验证是否能防止溢出"
  }
}
```

## 理由编写指南

选择理由 (`reason`) 应该清晰、具体，包含以下要素:

### 必须包含的信息
1. **语义识别**: 明确说明检测到的语义关键词
2. **漏洞匹配**: 说明函数名与当前漏洞类型的关联
3. **位置说明**: 描述函数在调用路径中的位置
4. **选择逻辑**: 解释为什么该函数优于其他候选

### 理由模板
```
函数名包含'{语义关键词}'语义关键词({优先级})，
且'{关键词}'与{漏洞类型}漏洞类型{匹配程度}，
位于source和sink{位置描述}，
{额外优势说明}
```

### 良好示例
- "函数名包含'sanitize'语义关键词(高优先级)，位于source和sink之间，针对命令注入漏洞最可能是执行命令过滤的sanitizer"
- "函数名包含'validate'和'cmd'关键词，'validate'表明验证语义(高优先级)，'cmd'与命令注入漏洞直接匹配，位于sink前的关键路径上"
- "虽然'check_bounds'也符合，但'validate_size'的'size'更直接对应缓冲区大小验证，因此优先选择"

### 避免的理由
- ❌ "这个函数看起来不错" (过于主观)
- ❌ "选择了第一个函数" (没有说明原因)
- ❌ "函数名匹配" (过于笼统，没有具体说明)
- ❌ "因为它在路径上" (没有语义分析)

## 最佳实践

1. **优先语义匹配**
   - 函数名明确包含 sanitize/validate/check 等关键词时优先选择
   - 即使位置稍远，语义明确的函数也值得优先分析

2. **考虑组合因素**
   - 单一维度高分不如多维度均衡高分
   - 例如: 位置好 + 语义中等 > 位置差 + 语义高

3. **漏洞类型特异性**
   - 优先选择函数名包含漏洞类型相关词汇的函数
   - 如 SQL 注入场景优先选择含 sql/query 的函数

4. **排除法也很重要**
   - 明确排除系统函数和无关函数
   - 在理由中可以说明为什么排除了其他看似合理的候选

5. **处理平局情况**
   - 当多个函数得分相同时，选择:
     1. 位置最接近 source-sink 中间的
     2. 函数名更具体的 (含更多关键词)
     3. 文件路径更相关的 (与 sink 文件在同一模块)
