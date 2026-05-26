# FocalSym: LLM 引导的聚焦式符号执行净化函数验证方法

## 1 引言

### 1.1 研究背景：静态分析为什么会误报

静态分析工具（如 CodeQL）做污点追踪时，遇到分支条件、函数返回值、循环边界这类运行时才能确定的信息，只能做保守近似。它没法知道某个 `if` 分支在实际执行中是否可达，只能假设"都可能走到"。

举个 Java 的例子：

```java
public void processCommand(String userInput) {
    String sanitized = sanitize(userInput);
    if (isValid(sanitized)) {
        Runtime.getRuntime().exec(sanitized);  // sink
    }
}

private String sanitize(String input) {
    // 过滤掉 shell 元字符
    return input.replaceAll("[;&|`$]", "");
}

private boolean isValid(String input) {
    // 只允许字母数字和空格
    return input.matches("^[a-zA-Z0-9 ]+$");
}
```

CodeQL 会报这是一条命令注入路径：`userInput` → `sanitize()` → `exec()`。但实际上：

1. `sanitize()` 已经过滤了 shell 元字符
2. `isValid()` 的正则检查进一步限制了输入范围
3. 只有通过两层校验的输入才能到达 `exec()`

静态分析看不到 `replaceAll` 的实际效果，也不知道 `matches()` 返回 `true` 意味着什么约束。它只看到"污点数据流进了 `exec()`"，于是报警。

这类误报在真实代码库里大量存在。净化函数的逻辑可能分散在多层调用中，校验条件可能藏在 `if`/`switch`/`try-catch` 的各种分支里，静态分析没有能力把这些语义串起来。

### 1.2 核心思路：LLM 选点 + 局部符号执行

符号执行理论上能解决这个问题——它可以把 `sanitize()` 的返回值建模为符号表达式，把 `isValid()` 的分支条件加入路径约束，然后问求解器："存不存在一个输入，能同时满足 `isValid()` 返回 `true`、且到达 `exec()`？"

但符号执行有状态爆炸问题。对整个程序跑符号执行，路径数量指数增长，实际工程中几乎不可行。

这里做了一个 tradeoff：**用 LLM 收窄符号执行的作用范围。**

不是对整个程序做符号执行，而是：

1. **LLM 选点**：从污点路径上筛出最可疑的净化函数（比如上例中的 `sanitize()`）
2. **生成输入约束**：根据漏洞类型（命令注入）生成攻击输入的特征约束（包含 shell 元字符）
3. **局部符号执行**：只对这一个函数构造测试桩，跑符号执行，验证"是否存在攻击输入能到达 sink"

这个 tradeoff 的好处：

- **规避状态爆炸**：符号执行的输入是单个函数的测试桩，路径数量从指数级降到可控范围
- **保留确定性**：关键判定（"这条路径可不可达"）由求解器给出，不是 LLM 猜的
- **利用 LLM 的优势**：函数选择、约束生成这类需要语义理解的活，LLM 比手写规则灵活得多

本质上是把一个不可行的全局问题（对整个程序符号执行）转化成一系列可行的局部问题（对关键函数符号执行），用 LLM 做路由决策。

### 1.3 主要贡献

1. 提出 LLM 引导的聚焦式符号执行方法，用 LLM 选点规避状态爆炸，用符号执行保证判定确定性
2. 设计 MCP Tools + LLM Skills 混合架构，文件解析、编译执行交给工具，函数选择、约束构造交给 LLM
3. 给出基于路径可达性的判定模型：给定攻击输入约束，判断污点路径是否可达 sink

---

## 2 系统架构

### 2.1 整体架构

FocalSym 分两层：工具层和智能层。

工具层（MCP Tools）处理确定性任务：
- `parse_sarif_detailed`：读取 SARIF 2.1.0，恢复污点路径
- `find_potential_functions`：在 CodeQL database 里搜索候选函数
- `generate_harness` / `compile_harness`：生成和编译测试桩
- `verify_reachability`：调用 angr 做符号执行，判断路径可达性

智能层（LLM Skills）处理语义决策任务：
- `function-selector`：根据路径位置、命名和漏洞类型选目标函数
- `constraint-generator`：根据漏洞类型生成攻击输入约束

这样设计避免了让模型自由发挥，也避免了纯规则系统的僵化。

### 2.2 5 步工作流

| 步骤 | 名称 | 核心输入 | 核心输出 | 作用 |
|------|------|----------|----------|------|
| 1 | SARIF 解析 | SARIF 文件 | TaintPath 列表 | 恢复 source、sink 与中间路径 |
| 2 | 候选函数发现 | 污点路径、CodeQL database | 候选函数列表 | 缩小待分析范围 |
| 3 | 函数选择 | 候选函数、漏洞上下文 | 目标函数及理由 | LLM 选点，提升验证效率 |
| 4 | 约束生成 | 漏洞类型、sink 函数 | input_constraints | 形式化攻击输入特征 |
| 5 | 符号执行验证 | 测试桩、输入约束 | 可达性判定结果 | 给出净化有效性结论 |

Step 1 从 SARIF 的 codeFlows/threadFlows 提取污点路径。Step 2 调用 `find_potential_functions` 做静态筛选。Step 3 由 LLM 排序候选函数，选出最值得验证的目标。Step 4 根据漏洞类型生成攻击输入的约束条件。Step 5 构造测试桩，创建符号输入，探索路径，判断攻击输入能否到达 sink。

---

## 3 核心模块

### 3.1 SARIF 解析模块

把 CodeQL 生成的 SARIF 文件转成结构化路径信息。输出 TaintPath 数据结构，包含 source、sink 和 intermediate_locations。实现在 sarif_parser.py。

模块定义了 FunctionLocation 和 TaintPath 两个类。`extract_taint_paths` 处理 runs/results/codeFlows/threadFlows/locations 结构，首节点是 source，末节点是 sink，中间节点收集为 intermediate_locations。

### 3.2 候选函数发现模块

在污点路径上搜索潜在净化函数。输入污点路径和 CodeQL database，输出候选函数列表。对应 `function_level_sanitizer.find_potential_functions`。

这一步把符号执行的高成本推后，用静态筛选先剪枝。

### 3.3 函数选择模块 (LLM Skill)

从候选列表里选最值得验证的函数。选择标准：

1. **位置优先级**：source 与 sink 之间的函数最高，靠近 sink 的次之，不在路径上的忽略
2. **语义优先级**：函数名包含 sanitize、validate、check、escape、filter 等关键词
3. **漏洞类型匹配度**：函数名是否含有该漏洞类型相关特征词

输出 selected_function，包含 name、file、line 和 reason 字段。

### 3.4 约束生成模块 (LLM Skill)

根据漏洞类型生成攻击输入的约束条件。只需要 input_constraints，不需要 output_constraints。

为什么不需要输出约束？因为符号执行会自动处理：

- **判定型净化**（如 `if (!isValid(input)) return;`）：分支条件加入路径约束
- **过滤型净化**（如 `input.replaceAll(";", "")`）：符号表达式被变换

不管哪种，最终都体现在"从 source 到 sink 的路径是否可达"上。只要输入约束正确描述了攻击输入的特征，符号执行自己会算出"这个攻击能不能到达 sink"。

支持的约束类型：
- `contains_any`：输入至少包含某个危险字符
- `length_range`：输入长度超过某个阈值
- `matches_regex`：输入匹配某个攻击模式

### 3.5 符号执行验证模块

判断目标函数是否真正实现净化。核心问题：**给定攻击输入约束，污点路径是否可达 sink？**

SymbolicExecutor 基于 angr 构建工程对象，创建符号输入，apply_input_constraints 加入攻击输入约束，execute_with_constraints 探索路径。

判定逻辑：
- 如果求解器返回 **UNSAT**（不可达）→ 净化有效，攻击输入到不了 sink
- 如果求解器返回 **SAT**（可达）→ 净化无效，求解器还能给出一个具体的绕过样例

---

## 4 可达性判定模型

### 4.1 形式化定义

设攻击输入约束为 $I$（定义危险输入的特征），污点路径为 $p$，sink 为 $s$。

净化函数验证的核心问题：

> **给定攻击输入约束 $I$，是否存在一条满足 $I$ 的路径能到达 sink $s$？**

### 4.2 判定公式

净化失败（攻击输入可达 sink）：
$$
\exists p: I(p) \land \text{Reachable}(p, s) \Rightarrow \text{sanitized} = \text{False}
$$

净化成功（攻击输入不可达 sink）：
$$
\forall p: I(p) \Rightarrow \neg\text{Reachable}(p, s) \Rightarrow \text{sanitized} = \text{True}
$$

### 4.3 为什么这个模型成立

这个简化成立的前提是：**sink 本身就是危险操作**。

比如 `Runtime.exec(taint)`、`stmt.executeQuery(taint)`、`fopen(taint)` —— 只要污点数据能到达这里，就是漏洞，不需要再检查"输出是什么样"。

大多数经典漏洞类型（命令注入、SQL 注入、路径遍历）都符合"到达即危险"的模式。

### 4.4 符号执行如何处理净化逻辑

符号执行沿路径传播约束，净化函数的两种形式都会被自动处理：

| 净化类型 | 例子 | 符号执行怎么处理 |
|----------|------|------------------|
| **判定型** | `if (!isValid(input)) return;` | 分支条件加入路径约束，危险输入走 return 分支，到不了 sink |
| **过滤型** | `input = input.replaceAll(";", "")` | 符号表达式被变换，危险字符被移除 |

最终，求解器回答的问题是："存不存在一个满足攻击输入约束的具体值，能走完这条路径到达 sink？"

---

## 5 支持的漏洞类型

### 5.1 命令注入

危险字符：`;`、`|`、`&`、`` ` ``、`$`、`(`、`)`、`{`、`}`、`<`、`>`

输入约束：`contains_any(shell 元字符)`

验证逻辑：包含 shell 元字符的输入能否到达 `exec()`/`system()` 等 sink

### 5.2 SQL 注入

危险字符：`'`、`"`、`;`、`--`、`/*`

输入约束：`contains_any(SQL 注入字符)`

验证逻辑：包含 SQL 注入字符的输入能否到达 `executeQuery()`/`execute()` 等 sink

### 5.3 缓冲区溢出

输入约束：`length_range(min > buffer_size)`

验证逻辑：超长输入能否到达 `strcpy()`/`memcpy()` 等 sink

### 5.4 格式化字符串

危险格式说明符：`%n`、`%p`、`%x`、`%s`

输入约束：`contains_any(格式说明符)`

验证逻辑：包含格式说明符的输入能否到达 `printf()`/`sprintf()` 等 sink

### 5.5 路径遍历

危险模式：`../`、`..\`、`~`

输入约束：`contains_any(路径跳转片段)` 或 `matches_regex(路径遍历模式)`

验证逻辑：包含路径跳转的输入能否到达 `fopen()`/`open()` 等 sink

### 约束定义汇总

| 漏洞类型 | 输入约束 | 典型 sink | 验证问题 |
|----------|----------|-----------|----------|
| 命令注入 | contains_any(shell 元字符) | exec(), system() | 攻击输入能否到达 sink？ |
| SQL 注入 | contains_any(SQL 注入字符) | executeQuery() | 攻击输入能否到达 sink？ |
| 缓冲区溢出 | length_range(min > buffer_size) | strcpy(), memcpy() | 超长输入能否到达 sink？ |
| 格式化字符串 | contains_any(格式说明符) | printf(), sprintf() | 攻击输入能否到达 sink？ |
| 路径遍历 | contains_any(路径跳转) | fopen(), open() | 攻击输入能否到达 sink？ |

---

## 6 总结与展望

### 6.1 本文工作总结

本文提出 FocalSym，一种 LLM 引导的聚焦式符号执行方法，用于验证净化函数有效性。

核心思路：用 LLM 选点规避符号执行的状态爆炸问题，用符号执行的路径可达性判定保证结论确定性。把"危险输入能否绕过净化到达 sink"这个问题，转化为约束求解问题。

与纯静态分析相比，这个方法能理解分支条件和过滤逻辑的实际效果，降低误报。与全程序符号执行相比，这个方法通过 LLM 选点把分析范围收窄到关键函数，规避状态爆炸。

### 6.2 未来工作

三个方向：

1. 支持更多漏洞类型（整数溢出、XSS、认证绕过），补充对应的输入约束模板
2. 优化符号执行性能（路径剪枝、状态合并），进一步扩大可分析的函数规模
3. 提高 LLM 选点准确性，把函数调用图、数据流信息纳入选择依据
