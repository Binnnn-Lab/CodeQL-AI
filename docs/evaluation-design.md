# Evaluation Design

## 定位

本项目有 **4 个优化方案**（tool），每个方案独立接入 CodeQL 告警流水线，作为 **CodeQL 告警验证器 / 优化器**。评估的核心问题是：

> 每个 tool 能否正确区分 CodeQL 产生的真阳性告警和假阳性告警？

评估流水线（所有 tool 共用同一条）：

```
Juliet dataset → CodeQL 扫描 → SARIF 告警 → Tool X 验证/优化 → verdict
```

评估单位：**alert-level**（每条 CodeQL 告警作为一个评价单元）。

每个 tool 在每个 dataset 上独立运行，产出独立的 `alert_results.csv`，最终汇总对比。

---

## 图表总览

| 编号 | 类型 | 内容 | 回答的问题 |
|------|------|------|------------|
| Table 1 | 表 | 实验概况（per dataset） | 评了什么数据，每个 tool 跑到了多少 |
| Table 2 | 表 | 整体验证准确性（多 tool 对比） | 各 tool 的总体检测能力 |
| Figure 1 | 分组柱状图 | Per-CWE 验证效果 | 各 tool 擅长/不擅长哪些漏洞类型 |
| Figure 2 | 热力图 | 混淆矩阵（per tool） | 每个 tool 偏向漏报还是误报 |
| Figure 3 | 柱状图 | 运行时间与实用性 | 各 tool 是否实用 |

不需要 PR 曲线 / ROC 曲线（所有 tool 输出均为二值判定，无置信分数）。

---

## Table 1：实验概况（per dataset，所有 tool 共用）

这张表描述 dataset 本身和 CodeQL baseline，每个 dataset 填一行。

| 字段 | 说明 |
|------|------|
| dataset | 数据集名称，如 Juliet C/C++ |
| dataset_version | 数据集版本 |
| CWE scope | 覆盖的 CWE 类型列表 |
| #bad functions | Juliet 中 bad 函数总数（正样本） |
| #good functions | Juliet 中 good 函数总数（负样本） |
| #CodeQL alerts on bad | CodeQL 在 bad 函数上产生的告警数 |
| #CodeQL alerts on good | CodeQL 在 good 函数上产生的告警数（即 CodeQL 原始 FP） |
| #total CodeQL alerts | 送入各 tool 的总告警数 |

每个 tool 额外记录：

| 字段 | 说明 |
|------|------|
| tool_name | 工具名称 |
| #successfully verified | 该 tool 成功完成验证的告警数 |
| verification success rate | `#verified / #total` |
| total runtime | 总运行时间（秒） |
| median runtime per alert | 单告警中位耗时 |
| p95 runtime per alert | 单告警 P95 耗时 |
| tool config | 版本号、依赖版本、模型、commit hash 等 |

---

## Table 2：整体验证准确性（多 tool 对比）

### 混淆矩阵定义（适用于所有 tool）

|  | Tool: vulnerable | Tool: safe |
|--|--------------------:|----------------------:|
| Bad（真漏洞） | TP | FN |
| Good（安全） | FP | TN |

- **TP**：bad 告警 → tool 判定为 vulnerable（正确确认真漏洞）
- **FP**：good 告警 → tool 判定为 vulnerable（未能排除误报）
- **TN**：good 告警 → tool 判定为 safe（正确排除误报）
- **FN**：bad 告警 → tool 判定为 safe（错误排除真漏洞）

### 指标

| 指标 | 公式 | 含义 |
|------|------|------|
| Precision | `TP / (TP + FP)` | tool 判定 vulnerable 时的正确率 |
| Recall | `TP / (TP + FN)` | 真漏洞中被 tool 确认的比例 |
| F1 | `2PR / (P + R)` | 综合指标 |
| FPR | `FP / (FP + TN)` | 假阳率 |
| Balanced Accuracy | `(Recall + TNR) / 2` | 平衡准确率，TNR = TN/(TN+FP) |
| **FA Reduction** | `1 - FP_tool / FP_codeql` | 该 tool 消除了多少 CodeQL 原始假告警 |

### 对比表格式

| tool | TP | FP | TN | FN | Precision | Recall | F1 | FPR | FA Reduction |
|------|---:|---:|---:|---:|----------:|-------:|---:|----:|-----------:|
| CodeQL alone | — | — | — | — | — | — | — | — | baseline |
| Tool A | — | — | — | — | — | — | — | — | — |
| Tool B | — | — | — | — | — | — | — | — | — |
| Tool C | — | — | — | — | — | — | — | — | — |
| Tool D | — | — | — | — | — | — | — | — | — |
| Tool E | — | — | — | — | — | — | — | — | — |

如果在多个 dataset 上评估，每个 dataset 一张表。

---

## Figure 1：Per-CWE 验证效果（分组柱状图）

```
x 轴：CWE-78  CWE-89  CWE-120  CWE-134  CWE-22
y 轴：比率 (0-1)
分组：每个 CWE 下 5 根柱子，分别对应 5 个 tool
柱值：Recall 或 F1（选一个作为主指标）
标注：每个 CWE 的 #bad / #good 告警数
```

如果 5 个 tool 太拥挤，可拆成两张图：一张 Recall，一张 FA Reduction Rate。

数据来源：按 `(tool_name, cwe_id)` 分组计算 TP/FP/TN/FN。

---

## Figure 2：混淆矩阵（2x2 热力图，per tool）

每个 tool 一个 2x2 矩阵，横向排列：

```
Tool A          Tool B          Tool C          ...
     Vuln Safe       Vuln Safe       Vuln Safe
Bad  TP   FN   Bad  TP   FN   Bad  TP   FN
Good FP   TN   Good FP   TN   Good FP   TN
```

一眼看出每个 tool 的偏向：
- 高 Recall 但 FP 多 → 倾向于确认一切
- 高 Precision 但 FN 多 → 倾向于排除一切

---

## Figure 3：运行时间与实用性

```
x 轴：Tool A  Tool B  Tool C  Tool D  Tool E
y 轴：秒
柱子：median runtime (实心) | p95 runtime (条纹)
标注：success rate, timeout count
```

需要统计的运行时指标（per tool）：

| 指标 | 说明 |
|------|------|
| total_runtime_sec | 整个 benchmark 总时间 |
| median_runtime_sec | 中位单告警耗时 |
| p95_runtime_sec | P95 单告警耗时 |
| timeout_count | 超时数 |
| crash_count | 崩溃数 |
| analysis_success_rate | 成功分析比例 |

---

## 原始数据表：`alert_results.csv`

所有图表从这张表派生。**每个 tool 在每个 dataset 上产出一份**，用 `tool_name` 字段区分。

| 列名 | 必须 | 说明 |
|------|:----:|------|
| run_id | yes | 实验运行 ID |
| tool_name | yes | 工具名称（Tool A / Tool B / ...） |
| dataset | yes | 数据集名，如 Juliet-C/C++-v1.3 |
| cwe_id | yes | CWE 编号 |
| file_path | yes | 源文件路径 |
| function_name | yes | 被验证的函数名 |
| label | yes | bad / good（Juliet 地面真值） |
| y_true | yes | 1=bad, 0=good |
| codeql_alert_id | yes | CodeQL 告警标识 |
| verdict | yes | vulnerable / safe / error |
| predicted | yes | 1=vulnerable, 0=safe |
| analyzed | yes | 是否成功完成分析 |
| runtime_sec | yes | 该告警的处理耗时 |
| timeout | yes | 是否超时 |
| crashed | yes | 是否崩溃 |
| error_msg | optional | 若失败，错误信息 |

---

## End-to-End 执行记录清单

对某个 dataset 做一次完整实验，以下是 **CodeQL baseline** 和 **每个 tool** 各自需要记录的全部内容。

### Phase 0：环境与配置（实验开始前记录一次，所有 tool 共用）

| 记录项 | 示例 |
|--------|------|
| 操作系统 | macOS 14.3 / Ubuntu 22.04 |
| CPU / 内存 | Apple M2 Pro, 16GB |
| CodeQL CLI 版本 | 2.16.1 |
| CodeQL 查询套件 | cpp-security-and-quality |
| dataset 名称及版本 | Juliet C/C++ v1.3 |
| dataset 来源 | NIST SAMATE |
| 各 tool 的版本/配置 | 见各 tool 自身记录 |

### Phase 1：Dataset 解析（一次性，所有 tool 共用）

| 记录项 | 说明 |
|--------|------|
| CWE 列表 | 本次实验覆盖的 CWE |
| 每个 CWE 的 bad 函数数 | 正样本统计 |
| 每个 CWE 的 good 函数数 | 负样本统计 |
| 总函数数 | bad + good |
| 排除的文件/函数及原因 | 如编译失败、不在 scope 内 |

### Phase 2：CodeQL 扫描（一次性，产出 baseline + 所有 tool 的共同输入）

| 记录项 | 说明 |
|--------|------|
| 数据库创建命令 | `codeql database create ...` 完整命令 |
| 数据库创建耗时 | 秒 |
| 分析命令 | `codeql database analyze ...` 完整命令 |
| 分析耗时 | 秒 |
| SARIF 输出路径 | 文件位置 |
| 总告警数 | SARIF 中 results 数量 |
| 每个 CWE 的告警数 | 按 ruleId 分组 |
| 告警在 bad 函数上的数量 | CodeQL TP |
| 告警在 good 函数上的数量 | CodeQL FP |
| CodeQL 未覆盖的 bad 函数数 | CodeQL FN |

这一步产出 **CodeQL baseline** 的 TP/FP/FN/TN：
- CodeQL TP = bad 函数上有告警
- CodeQL FP = good 函数上有告警
- CodeQL FN = bad 函数上无告警
- CodeQL TN = good 函数上无告警

### Phase 3：各 Tool 独立运行（每个 tool 重复此阶段）

对 Phase 2 产生的每条 CodeQL 告警，每个 tool 各自记录：

| 记录项 | 说明 |
|--------|------|
| tool_name | 工具名称 |
| tool_config | 关键配置（模型、阈值、依赖版本等） |
| alert_id | 告警标识 |
| cwe_id | CWE 类型 |
| file_path | 文件 |
| function_name | 函数 |
| label | bad/good（ground truth） |
| verdict | vulnerable / safe / error |
| analyzed | 是否成功完成 |
| runtime_sec | 该告警的处理耗时 |
| timeout | 是否超时 |
| crashed | 是否崩溃 |
| error_msg | 若失败，错误信息 |

每个 tool 运行结束后写入一份 `alert_results_{tool_name}.csv`。

### Phase 4：汇总（合并所有 tool 的结果）

```
1. CodeQL alone:
   Precision, Recall, F1, FPR（baseline）

2. 每个 Tool:
   Precision, Recall, F1, FPR
   False Alarm Reduction Rate

3. Per-CWE 分组:
   每个 (tool, CWE) 组合的上述指标

4. 运行时统计（per tool）:
   total, median, p95, timeout_count, crash_count, success_rate
```

### 产出文件清单

| 文件 | 内容 | 数量 |
|------|------|------|
| `env_config.json` | Phase 0 环境配置 | 1 |
| `dataset_summary.csv` | Phase 1 数据集统计 | 每 dataset 1 份 |
| `codeql_alerts.sarif` | Phase 2 CodeQL 原始输出 | 每 dataset 1 份 |
| `codeql_baseline.csv` | Phase 2 CodeQL baseline 指标 | 每 dataset 1 份 |
| `alert_results_{tool}.csv` | Phase 3 逐告警原始结果 | 每 (tool, dataset) 1 份 |
| `metrics_overall.json` | Phase 4 所有 tool 整体指标 | 每 dataset 1 份 |
| `metrics_per_cwe.csv` | Phase 4 所有 tool Per-CWE 指标 | 每 dataset 1 份 |
| `metrics_runtime.json` | Phase 4 所有 tool 运行时统计 | 每 dataset 1 份 |
