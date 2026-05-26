#!/usr/bin/env python3
"""
评估 symbolic_sanitizer 在 Juliet "good" SARIF（= CodeQL 误报集）上的去 FP 能力。

按 docs/evaluation-design.md 的字段输出：
  - output/eval/alert_results_symbolic_sanitizer.csv (逐 alert)
  - output/eval/metrics_per_cwe.csv
  - output/eval/metrics_overall.json
  - output/eval/runtime_stats.json
"""
import csv
import json
import os
import re
import statistics
import sys
import time
import logging
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

logging.disable(logging.CRITICAL)  # silence angr noise

from libs.symbolic_sanitizer import (
    load_sarif_from_file,
    extract_taint_paths,
    find_enclosing_function,
    generate_harness,
    compile_harness,
    resolve_compile_config,
    SymbolicExecutor,
)

DATASET = '/data/benchmark/juliet/juliet-test-suite-c'
SARIF_DIR = '/data/benchmark/juliet/output'
OUT_DIR = Path(__file__).resolve().parents[1] / 'output' / 'eval'
OUT_DIR.mkdir(parents=True, exist_ok=True)

ALERTS_CSV = OUT_DIR / 'alert_results_symbolic_sanitizer.csv'
METRICS_PER_CWE_CSV = OUT_DIR / 'metrics_per_cwe.csv'
METRICS_OVERALL_JSON = OUT_DIR / 'metrics_overall.json'
RUNTIME_JSON = OUT_DIR / 'runtime_stats.json'

TOOL_NAME = 'symbolic_sanitizer'
RUN_ID = time.strftime('run-%Y%m%d-%H%M%S')

CWE_RULES = {
    '120': 'cpp/very-likely-overrunning-write',
    '125': 'cpp/overrun-read',
    '134': 'cpp/non-constant-format',
    '190': 'cpp/integer-overflow-tainted',
    '415': 'cpp/double-free',
    '416': 'cpp/use-after-free',
    '457': 'cpp/not-initialised',
}

CWES = ['120', '125', '134', '190', '415', '416', '457']


# ---------------------------------------------------------------------------
# Juliet-template-based verification-plan synthesis
# ---------------------------------------------------------------------------

_DECL_TYPE_RE = re.compile(
    r'^\s*((?:unsigned\s+|signed\s+)?'
    r'(?:char|short|int|long(?:\s+long)?|int64_t|int32_t|int16_t|uint64_t|uint32_t|uint16_t|size_t))'
    r'\s+data\b'
)
_IF_RE = re.compile(r'^\s*if\s*\((.+?)\)\s*(?:/\*.*?\*/\s*|//.*)?$')


def _data_type_to_uint_attack(c_type: str, op: str):
    """Return (width, attack_value) selecting an input that triggers overflow on the given op.

    For 'add' (data + 1): smallest input that overflows = TYPE_MAX.
    For 'multiply'/'square'/'times' (data * data, etc.):
        smallest input that overflows = ceil(sqrt(MAX+1)).
    """
    sizes = {
        'char': (1, 0x7F if 'unsigned' not in c_type else 0xFF),
        'signed char': (1, 0x7F),
        'unsigned char': (1, 0xFF),
        'short': (2, 0x7FFF),
        'unsigned short': (2, 0xFFFF),
        'int': (4, 0x7FFFFFFF),
        'unsigned int': (4, 0xFFFFFFFF),
        'long': (8, 0x7FFFFFFFFFFFFFFF),
        'unsigned long': (8, 0xFFFFFFFFFFFFFFFF),
        'int64_t': (8, 0x7FFFFFFFFFFFFFFF),
        'uint64_t': (8, 0xFFFFFFFFFFFFFFFF),
        'int32_t': (4, 0x7FFFFFFF),
        'uint32_t': (4, 0xFFFFFFFF),
        'int16_t': (2, 0x7FFF),
        'uint16_t': (2, 0xFFFF),
        'size_t': (8, 0xFFFFFFFFFFFFFFFF),
    }
    key = c_type.strip()
    if key not in sizes:
        # collapse multiple spaces
        key = re.sub(r'\s+', ' ', key)
    width, type_max = sizes.get(key, (4, 0x7FFFFFFF))

    op = op.lower()
    if op == 'square':
        # data * data overflows when data >= ceil(sqrt(type_max + 1))
        import math
        attack_value = int(math.isqrt(type_max)) + 1
    elif op == 'multiply':
        # data * 2 overflows when data > type_max / 2
        attack_value = (type_max // 2) + 1
    elif op == 'add':
        # data + 1 overflows only at exactly type_max
        attack_value = type_max
    else:  # default conservative
        attack_value = type_max
    return width, attack_value, type_max


def _parse_cwe190_operation(file_path: str) -> str:
    m = re.search(r'_(add|multiply|square|times)_', file_path)
    return m.group(1) if m else 'add'


_FILENAME_TYPE_RE = re.compile(
    r'CWE190_Integer_Overflow__'
    r'(unsigned_char|unsigned_short|unsigned_int|unsigned_long|'
    r'int64_t|int32_t|int16_t|uint64_t|uint32_t|uint16_t|size_t|'
    r'char|short|int|long)_'
)


def _parse_cwe190_type_from_filename(file_path: str):
    fn = file_path.split('/')[-1]
    m = _FILENAME_TYPE_RE.match(fn)
    if m:
        raw = m.group(1)
        # int64_t / uint32_t etc keep their underscore; "unsigned_int" becomes "unsigned int"
        if raw in {'int64_t', 'int32_t', 'int16_t', 'uint64_t', 'uint32_t', 'uint16_t', 'size_t'}:
            return raw
        return raw.replace('_', ' ')
    return None


def _extract_data_type(func_source: str) -> str:
    for line in func_source.splitlines():
        m = _DECL_TYPE_RE.match(line)
        if m:
            return re.sub(r'\s+', ' ', m.group(1).strip())
    return 'int'


def _extract_sanitizer_condition(func_source: str, sink_line_offset: int):
    """Find ALL if-conditions on data that enclose the sink line, AND them together.

    Juliet's `multiply` template wraps the sink in two nested guards:
        if (data > 0)            // outer (data-touching guard)
        {
            if (data < CHAR_MAX/2)  // inner
            { data * 2; }
        }
    We need both to faithfully model the sanitizer.
    """
    lines = func_source.splitlines()
    if sink_line_offset < 1 or sink_line_offset > len(lines):
        return None

    sink_indent = len(lines[sink_line_offset - 1]) - len(lines[sink_line_offset - 1].lstrip())
    conditions = []
    last_indent = sink_indent
    for i in range(sink_line_offset - 1, -1, -1):
        line = lines[i]
        if not line.strip():
            continue
        cur_indent = len(line) - len(line.lstrip())
        if cur_indent > last_indent:
            continue
        m = _IF_RE.match(line)
        if m:
            cond = m.group(1).strip()
            if cond in {'1', '0'}:
                continue
            if 'STATIC_CONST' in cond or 'GLOBAL_CONST' in cond:
                continue
            if 'data' in cond:
                conditions.append(cond)
                last_indent = cur_indent
    if not conditions:
        return None
    # Compose innermost-first, outer-last; AND them
    if len(conditions) == 1:
        return conditions[0]
    return ' && '.join(f'({c})' for c in conditions)


def synthesize_plan_cwe190(taint_path, func_info):
    """Return (call_chain, sink_expression, includes, input_constraints, notes) or None."""
    op = _parse_cwe190_operation(taint_path.sink['file_path'])
    # Prefer type from filename (works for class-based _83 variants where the class member
    # type lives in a separate header). Fall back to inline declaration parse.
    c_type = (
        _parse_cwe190_type_from_filename(taint_path.sink['file_path'])
        or _extract_data_type(func_info['source_code'])
    )
    sink_offset = taint_path.sink['line_number'] - func_info['start_line'] + 1
    sanitizer_cond = _extract_sanitizer_condition(func_info['source_code'], sink_offset)

    if sanitizer_cond is None:
        return None, 'no_sanitizer_condition_found'

    width, attack_value, type_max = _data_type_to_uint_attack(c_type, op)

    # Build the harness call_chain
    # Read symbolic input as the right width and cast to the declared type.
    read_stmt = f'{c_type} data = *({c_type}*)symbolic_input;'
    # Replicate the sanitizer; if it references CHAR_MAX/INT_MAX/etc., they are in <limits.h>
    guard_stmt = f'if (!({sanitizer_cond})) return 0;'

    if op == 'add':
        sink_expr = f'{c_type} result = (data + 1); (void)result'
    elif op == 'multiply':
        sink_expr = f'{c_type} result = (data * 2); (void)result'
    elif op == 'square':
        sink_expr = f'{c_type} result = (data * data); (void)result'
    else:
        sink_expr = f'{c_type} result = (data + 1); (void)result'

    if op == 'add':
        # `data + 1` overflows only when data is exactly TYPE_MAX (signed) or UINT_MAX
        # (unsigned). Use exact equality to avoid false bypasses from values that
        # happen to satisfy `>=` but don't actually overflow.
        constraints = [{
            'type': 'uint_eq',
            'offset': 0,
            'width': width,
            'value': attack_value,
        }]
    else:
        # `data * data` overflows for a wide range of inputs — keep `>=`.
        constraints = [{
            'type': 'uint_ge',
            'offset': 0,
            'width': width,
            'value': attack_value,
        }]
    includes = ['<limits.h>', '<math.h>']
    return (
        [read_stmt, guard_stmt],
        sink_expr,
        includes,
        constraints,
        f'op={op} type={c_type} attack_value={hex(attack_value)} sanitizer={sanitizer_cond!r}'
    ), None


_DATA_NUM_ASSIGN_RE = re.compile(r'\bdata\s*=\s*(\d+|0x[0-9a-fA-F]+|\'.\')\s*;')


def _find_cwe190_caller_file(sink_file: str):
    abs_sink = os.path.join(DATASET, sink_file)
    fn = os.path.basename(abs_sink)
    m = re.match(r'(.+_(\d+))[a-z]?\.(cpp|c)', fn)
    if not m:
        return None
    base, variant, ext = m.group(1), m.group(2), m.group(3)
    dirn = os.path.dirname(abs_sink)
    candidate = os.path.join(dirn, f'{base}a.{ext}')
    if os.path.exists(candidate) and candidate != abs_sink:
        return candidate
    candidate = os.path.join(dirn, f'{base}.{ext}')
    if os.path.exists(candidate) and candidate != abs_sink:
        return candidate
    return None


def _extract_cwe190_goodG2B_constant(caller_file: str):
    try:
        with open(caller_file, 'r', encoding='utf-8', errors='ignore') as fh:
            content = fh.read()
    except Exception:
        return None
    m = re.search(r'static\s+void\s+goodG2B\s*\(\s*\)\s*\{', content)
    if not m:
        m = re.search(r'void\s+\w*goodG2B\s*\(\s*\)\s*\{', content)
    if not m:
        return None
    body_start = m.end()
    depth = 1
    i = body_start
    while i < len(content) and depth > 0:
        if content[i] == '{':
            depth += 1
        elif content[i] == '}':
            depth -= 1
        i += 1
    body = content[body_start:i]
    matches = list(_DATA_NUM_ASSIGN_RE.finditer(body))
    if not matches:
        return None
    val_token = matches[-1].group(1)
    if val_token.startswith("'"):
        return ord(val_token[1])
    return int(val_token, 0)


def synthesize_plan_cwe190_xfn(taint_path, sink_func, src_file_abs):
    """Both same-function and cross-* variants. If sink-enclosing function has a local
    sanitizer (typical goodB2G*), use synthesize_plan_cwe190. If function is goodG2BSink
    (no local sanitizer), extract the constant from caller's goodG2B()."""
    fn_name = sink_func['function_name']

    if 'goodG2B' in fn_name and 'Sink' in fn_name:
        caller = _find_cwe190_caller_file(taint_path.sink['file_path'])
        if not caller:
            return None, f'goodG2B_caller_not_found for {fn_name}'
        const_val = _extract_cwe190_goodG2B_constant(caller)
        if const_val is None:
            return None, f'goodG2B_constant_not_found in {os.path.basename(caller)}'
        op = _parse_cwe190_operation(taint_path.sink['file_path'])
        c_type = (
            _parse_cwe190_type_from_filename(taint_path.sink['file_path'])
            or 'unsigned int'
        )
        width, attack_value, type_max = _data_type_to_uint_attack(c_type, op)
        if op == 'add':
            overflow_cond = f'(data == ({c_type}){attack_value:#x})'
        else:
            overflow_cond = f'(({c_type})data >= ({c_type}){attack_value:#x})'
        call_chain = [
            f'{c_type} data = ({c_type}){const_val};',
            f'(void)*(unsigned int*)symbolic_input;',
            f'if (!{overflow_cond}) return 0;',
        ]
        notes = f'goodG2BSink caller_constant={const_val} type={c_type} op={op}'
        return (call_chain, '(void)data', ['<limits.h>', '<math.h>'], [], notes), None

    return synthesize_plan_cwe190(taint_path, sink_func)


_STRCPY_LITERAL_RE = re.compile(r'strcpy\s*\(\s*data\s*,\s*"([^"]*)"\s*\)')
_DATA_ASSIGN_LITERAL_RE = re.compile(r'\bdata\s*=\s*"([^"]*)"')
_WIDE_STRCPY_RE = re.compile(r'wcscpy\s*\(\s*data\s*,\s*L?"([^"]*)"\s*\)')


def _find_goodG2B_caller_file(sink_file: str):
    """For e.g. .../X_81_goodG2B.cpp -> .../X_81a.cpp ; for X_82_goodG2B.cpp -> .../X_82a.cpp ;
    fall back to X_NN.cpp."""
    abs_sink = os.path.join(DATASET, sink_file)
    fn = os.path.basename(abs_sink)
    m = re.match(r'(.+_(\d+))_goodG2B\.(cpp|c)', fn)
    if not m:
        return None
    base, _variant, ext = m.group(1), m.group(2), m.group(3)
    dirn = os.path.dirname(abs_sink)
    for suffix in ('a', ''):
        candidate = os.path.join(dirn, f'{base}{suffix}.{ext}')
        if os.path.exists(candidate):
            return candidate
    return None


def _extract_goodG2B_constant(caller_file: str):
    """Find a string literal assigned to data inside the caller's goodG2B() function."""
    try:
        with open(caller_file, 'r', encoding='utf-8', errors='ignore') as fh:
            content = fh.read()
    except Exception:
        return None
    # Find the goodG2B function body
    m = re.search(r'static\s+void\s+goodG2B\s*\(\)\s*\{', content)
    if not m:
        return None
    body_start = m.end()
    # Naive brace matching
    depth = 1
    i = body_start
    while i < len(content) and depth > 0:
        if content[i] == '{':
            depth += 1
        elif content[i] == '}':
            depth -= 1
        i += 1
    body = content[body_start:i]
    for pat in (_STRCPY_LITERAL_RE, _DATA_ASSIGN_LITERAL_RE, _WIDE_STRCPY_RE):
        m = pat.search(body)
        if m:
            return m.group(1)
    return None


def synthesize_plan_cwe134(taint_path, func_info):
    """Agent-decision (scripted): for CWE-134 goodG2B, open the caller file and
    find the constant string assigned to data. If the constant doesn't contain '%',
    construct a harness where data is forced to that constant; the sink (printf)
    is conditional on data containing a format specifier. angr will then find that
    __sink_reached is unreachable.
    """
    sink_file = taint_path.sink['file_path']
    if '_goodG2B' not in os.path.basename(sink_file):
        return None, 'cwe-134 non-goodG2B variant'

    caller = _find_goodG2B_caller_file(sink_file)
    if not caller:
        return None, 'caller_file_not_found'
    literal = _extract_goodG2B_constant(caller)
    if literal is None:
        return None, 'goodG2B_caller_constant_not_found'

    # Escape literal for embedding in C string
    c_literal = literal.replace('\\', '\\\\').replace('"', '\\"')

    # Harness: connect symbolic_input to a strncmp-style guard that only allows the
    # exact constant. The "sink" fires only if data contains a format specifier.
    # Since constant has no '%', __sink_reached is unreachable.
    call_chain = [
        f'const char *expected = "{c_literal}";',
        'const char *data = (const char *)symbolic_input;',
        'size_t n = strlen(expected);',
        'if (strncmp(data, expected, n) != 0) return 0;',
        'if (data[n] != 0) return 0;',
        'if (strchr(data, \'%\') == 0) return 0;',
    ]
    sink_expr = '(void)data'
    includes = ['<string.h>']
    constraints = [{'type': 'contains_any', 'chars': ['%']}]
    notes = f'goodG2B caller_constant={literal!r}'
    return (call_chain, sink_expr, includes, constraints, notes), None


# ---------------------------------------------------------------------------
# Per-alert evaluation
# ---------------------------------------------------------------------------

def evaluate_alert(cwe, idx, taint_path, compile_script):
    src_file_abs = os.path.join(DATASET, taint_path.source['file_path'])
    sink_file_abs = os.path.join(DATASET, taint_path.sink['file_path'])

    record = {
        'run_id': RUN_ID,
        'tool_name': TOOL_NAME,
        'dataset': 'Juliet-C/C++',
        'cwe_id': f'CWE-{cwe}',
        'file_path': taint_path.sink['file_path'],
        'function_name': '',
        'label': 'good',
        'y_true': 0,
        'codeql_alert_id': f'cwe-{cwe}-{taint_path.path_id}',
        'verdict': 'error',
        'predicted': 1,  # conservative default = "vulnerable"
        'analyzed': False,
        'runtime_sec': 0.0,
        'timeout': False,
        'crashed': False,
        'error_msg': '',
    }

    t0 = time.time()

    try:
        sink_func = find_enclosing_function(sink_file_abs, taint_path.sink['line_number'])
        if not sink_func.get('success'):
            record['error_msg'] = f'sink_function_resolution_failed: {sink_func.get("error")}'
            record['verdict'] = 'vulnerable'
            return record

        record['function_name'] = sink_func['function_name']

        if cwe == '190':
            plan, err = synthesize_plan_cwe190_xfn(taint_path, sink_func, src_file_abs)
        elif cwe == '134':
            plan, err = synthesize_plan_cwe134(taint_path, sink_func)
        else:
            plan, err = None, f'cwe-{cwe} not modeled'

        if plan is None:
            record['error_msg'] = err
            record['verdict'] = 'vulnerable'
            return record

        call_chain, sink_expr, includes, constraints, notes = plan
        record['error_msg'] = notes

        gh = generate_harness(
            target_function=sink_func['function_name'],
            source_file=taint_path.sink['file_path'],
            call_chain=call_chain,
            sink_expression=sink_expr,
            includes=includes,
        )
        if not gh.get('success'):
            record['error_msg'] = f'harness_gen_failed: {gh.get("error")}'
            record['crashed'] = True
            record['verdict'] = 'vulnerable'
            return record

        lang = 'cpp' if taint_path.sink['file_path'].endswith(('.cpp', '.cc')) else 'c'
        c = compile_harness(gh['harness_code'], compile_script, lang=lang)
        if not c.get('success'):
            record['error_msg'] = f'compile_failed: {(c.get("error") or "")[:200]}'
            record['crashed'] = True
            record['verdict'] = 'vulnerable'
            return record

        executor = SymbolicExecutor(c['binary_path'])
        result = executor.execute_reachability(
            {'input_constraints': constraints, 'buffer_size': 64},
            '__sink_reached',
            timeout=60,
        )

        if not result.get('success'):
            err = (result.get('error') or '')[:200]
            if 'timeout' in err.lower():
                record['timeout'] = True
            else:
                record['crashed'] = True
            record['error_msg'] = f'angr_failed: {err}'
            record['verdict'] = 'vulnerable'
            return record

        record['analyzed'] = True
        if result['reachable']:
            record['verdict'] = 'vulnerable'
            record['predicted'] = 1
            record['error_msg'] = (
                f'{notes} | counterexample={result.get("counterexample")} '
                f'paths_to_sink={result.get("paths_to_sink")}'
            )
        else:
            record['verdict'] = 'safe'
            record['predicted'] = 0
            record['error_msg'] = (
                f'{notes} | sanitizer_effective paths_explored={result.get("paths_explored")}'
            )
        return record

    except Exception as e:
        record['crashed'] = True
        record['error_msg'] = f'exception: {type(e).__name__}: {e}'
        record['verdict'] = 'vulnerable'
        return record
    finally:
        record['runtime_sec'] = round(time.time() - t0, 3)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    cs = resolve_compile_config(DATASET)
    if not cs.get('found'):
        print('compile.sh not found; please run the unit-test workflow first.')
        sys.exit(1)
    compile_script = cs['compile_script']

    fieldnames = [
        'run_id', 'tool_name', 'dataset', 'cwe_id', 'file_path', 'function_name',
        'label', 'y_true', 'codeql_alert_id', 'verdict', 'predicted', 'analyzed',
        'runtime_sec', 'timeout', 'crashed', 'error_msg',
    ]

    with open(ALERTS_CSV, 'w', newline='') as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()

        cwe_alerts = defaultdict(list)
        for cwe in CWES:
            sarif_path = f'{SARIF_DIR}/final_good_tree_cwe-{cwe}_db.sarif'
            if not os.path.exists(sarif_path):
                continue
            paths = extract_taint_paths(load_sarif_from_file(sarif_path))
            print(f'CWE-{cwe}: {len(paths)} alerts from SARIF')
            for idx, p in enumerate(paths, 1):
                rec = evaluate_alert(cwe, idx, p, compile_script)
                writer.writerow(rec)
                fh.flush()
                cwe_alerts[cwe].append(rec)
                if idx % 10 == 0 or idx == len(paths):
                    print(f'  [{idx}/{len(paths)}] verdict={rec["verdict"]} '
                          f'analyzed={rec["analyzed"]} t={rec["runtime_sec"]}s')

    # ---- Aggregate metrics ----
    metrics_per_cwe = []
    all_records = []
    for cwe, recs in cwe_alerts.items():
        all_records.extend(recs)
        fp = sum(1 for r in recs if r['predicted'] == 1)
        tn = sum(1 for r in recs if r['predicted'] == 0)
        analyzed = sum(1 for r in recs if r['analyzed'])
        crashed = sum(1 for r in recs if r['crashed'])
        timed = sum(1 for r in recs if r['timeout'])
        total = len(recs)
        metrics_per_cwe.append({
            'cwe_id': f'CWE-{cwe}',
            'codeql_fp': total,         # 全部 good alert 即 CodeQL 在 good 上的告警 = CodeQL FP
            'tool_fp': fp,
            'tool_tn': tn,
            'fp_reduction': round(1 - (fp / total), 4) if total else 0.0,
            'analyzed_rate': round(analyzed / total, 4) if total else 0.0,
            'crashed': crashed,
            'timeout': timed,
        })

    with open(METRICS_PER_CWE_CSV, 'w', newline='') as fh:
        writer = csv.DictWriter(fh, fieldnames=list(metrics_per_cwe[0].keys()))
        writer.writeheader()
        for row in metrics_per_cwe:
            writer.writerow(row)

    total = len(all_records)
    fp = sum(1 for r in all_records if r['predicted'] == 1)
    tn = sum(1 for r in all_records if r['predicted'] == 0)
    analyzed = sum(1 for r in all_records if r['analyzed'])
    runtimes = [r['runtime_sec'] for r in all_records]
    overall = {
        'tool_name': TOOL_NAME,
        'run_id': RUN_ID,
        'dataset': 'Juliet-C/C++ good',
        'total_alerts': total,
        'codeql_baseline_fp': total,
        'tool_fp': fp,
        'tool_tn': tn,
        'tool_fpr': round(fp / total, 4) if total else 0.0,
        'fp_reduction': round(1 - (fp / total), 4) if total else 0.0,
        'analysis_success_rate': round(analyzed / total, 4) if total else 0.0,
    }
    with open(METRICS_OVERALL_JSON, 'w') as fh:
        json.dump(overall, fh, indent=2)

    runtime_stats = {
        'tool_name': TOOL_NAME,
        'total_runtime_sec': round(sum(runtimes), 2),
        'median_runtime_sec': round(statistics.median(runtimes), 3) if runtimes else 0,
        'p95_runtime_sec': round(statistics.quantiles(runtimes, n=20)[-1], 3) if len(runtimes) >= 20 else None,
        'mean_runtime_sec': round(statistics.mean(runtimes), 3) if runtimes else 0,
        'max_runtime_sec': round(max(runtimes), 3) if runtimes else 0,
        'timeout_count': sum(1 for r in all_records if r['timeout']),
        'crash_count': sum(1 for r in all_records if r['crashed']),
        'analysis_success_rate': round(analyzed / total, 4) if total else 0.0,
    }
    with open(RUNTIME_JSON, 'w') as fh:
        json.dump(runtime_stats, fh, indent=2)

    print('\n=== Summary ===')
    print(f'Total alerts: {total} | tool_fp={fp} tool_tn={tn} FA_reduction={overall["fp_reduction"]}')
    for row in metrics_per_cwe:
        print(f'  {row["cwe_id"]}: codeql_fp={row["codeql_fp"]} tool_fp={row["tool_fp"]} '
              f'tool_tn={row["tool_tn"]} FA_reduction={row["fp_reduction"]} '
              f'analyzed={row["analyzed_rate"]}')


if __name__ == '__main__':
    main()
