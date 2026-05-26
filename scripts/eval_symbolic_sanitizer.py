#!/usr/bin/env python3
"""
Evaluate symbolic_sanitizer on Juliet "good" SARIF (CodeQL FP set) using
the 4-tool path-guided selective symbolic execution flow.

Output (per docs/evaluation-design.md):
  - output/eval/alert_results_symbolic_sanitizer.csv
  - output/eval/metrics_per_cwe.csv
  - output/eval/metrics_overall.json
  - output/eval/runtime_stats.json
"""
import csv
import json
import math
import os
import re
import statistics
import sys
import time
import logging
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

logging.disable(logging.CRITICAL)

from libs.symbolic_sanitizer import (
    parse_sarif,
    build_harness,
    scan_path_branches,
    verify_with_decisions,
    resolve_compile_config,
    write_compile_config,
    DEFAULT_COMPILE_SH,
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

CWES = ['120', '125', '134', '190', '415', '416', '457']

# ---------------------------------------------------------------------------
# Attack-predicate synthesis (heuristic — no LLM in the loop)
# ---------------------------------------------------------------------------

_FILENAME_TYPE_RE = re.compile(
    r'CWE190_Integer_Overflow__'
    r'(unsigned_char|unsigned_short|unsigned_int|unsigned_long|'
    r'int64_t|int32_t|int16_t|uint64_t|uint32_t|uint16_t|size_t|'
    r'char|short|int|long)_'
)

_SIZES = {
    'char': (1, 0x7F), 'unsigned char': (1, 0xFF),
    'short': (2, 0x7FFF), 'unsigned short': (2, 0xFFFF),
    'int': (4, 0x7FFFFFFF), 'unsigned int': (4, 0xFFFFFFFF),
    'long': (8, 0x7FFFFFFFFFFFFFFF), 'unsigned long': (8, 0xFFFFFFFFFFFFFFFF),
    'int64_t': (8, 0x7FFFFFFFFFFFFFFF), 'uint64_t': (8, 0xFFFFFFFFFFFFFFFF),
    'int32_t': (4, 0x7FFFFFFF), 'uint32_t': (4, 0xFFFFFFFF),
    'int16_t': (2, 0x7FFF), 'uint16_t': (2, 0xFFFF),
    'size_t': (8, 0xFFFFFFFFFFFFFFFF),
}


def _parse_cwe190_type(file_path):
    fn = os.path.basename(file_path)
    m = _FILENAME_TYPE_RE.match(fn)
    if m:
        raw = m.group(1)
        if raw in _SIZES:
            return raw
        return raw.replace('_', ' ')
    return None


def _parse_cwe190_op(file_path):
    m = re.search(r'_(add|multiply|square|times)_', file_path)
    return m.group(1) if m else 'add'


def _attack_predicate_cwe190(file_path):
    c_type = _parse_cwe190_type(file_path) or 'unsigned int'
    c_type = re.sub(r'\s+', ' ', c_type.strip())
    width, type_max = _SIZES.get(c_type, (4, 0x7FFFFFFF))
    op = _parse_cwe190_op(file_path)
    if op == 'square':
        value = int(math.isqrt(type_max)) + 1
    elif op == 'multiply':
        value = (type_max // 2) + 1
    else:
        value = type_max
    return {
        'byte_offset': 0,
        'width': width,
        'op': '>=',
        'value': value,
        'signed': False,
    }


# ---------------------------------------------------------------------------
# Per-alert evaluation
# ---------------------------------------------------------------------------

def _ensure_compile_script(dataset_path):
    cs = resolve_compile_config(dataset_path)
    if cs.get('found'):
        return cs['compile_script']
    juliet_root = dataset_path
    template = DEFAULT_COMPILE_SH.replace(
        '"$HARNESS" "$ORIG"',
        f'-I"{juliet_root}/testcasesupport" '
        f'"{juliet_root}/testcasesupport/io.c" '
        '"$HARNESS" "$ORIG"',
    )
    r = write_compile_config(dataset_path, template)
    return r.get('compile_script')


def _heuristic_branch_decisions(branches):
    """Include branches whose condition_src contains a taint variable name or
    looks like a range/validation check."""
    decisions = {}
    for b in branches:
        cond = b.get('condition_src', '')
        tvars = b.get('taint_vars', [])
        # Include if condition mentions data or has taint vars and looks like a comparison
        if tvars and any(kw in cond for kw in ('>=', '<=', '>', '<', '==', '!=', 'abs', 'sqrt', 'sizeof')):
            decisions[b['branch_id']] = True
        else:
            decisions[b['branch_id']] = False
    return decisions


def evaluate_alert(cwe, idx, path_dict, compile_script):
    record = {
        'run_id': RUN_ID,
        'tool_name': TOOL_NAME,
        'dataset': 'Juliet-C/C++',
        'cwe_id': f'CWE-{cwe}',
        'file_path': path_dict.get('sink', {}).get('file_path', ''),
        'function_name': '',
        'label': 'good',
        'y_true': 0,
        'codeql_alert_id': f'cwe-{cwe}-{path_dict.get("path_id", idx)}',
        'verdict': 'error',
        'predicted': 1,
        'analyzed': False,
        'runtime_sec': 0.0,
        'timeout': False,
        'crashed': False,
        'error_msg': '',
    }

    t0 = time.time()

    try:
        source_node = path_dict.get('source', {})
        sink_node = path_dict.get('sink', {})
        source_file = source_node.get('file_path', '')
        func_name = source_node.get('function_name') or sink_node.get('function_name') or 'main'

        record['function_name'] = func_name

        if not source_file or not os.path.exists(source_file):
            record['error_msg'] = f'source_file_missing: {source_file}'
            record['verdict'] = 'vulnerable'
            return record

        # Step 1: build harness
        source_api = 'fscanf'  # default for Juliet
        bh = build_harness(
            source_file=source_file,
            vuln_entry=func_name,
            source_api=source_api,
            compile_script=compile_script,
        )
        if not bh.get('success'):
            record['error_msg'] = f'build_harness_failed: {bh.get("error", "")[:200]}'
            record['crashed'] = True
            record['verdict'] = 'vulnerable'
            return record

        binary_path = bh['binary_path']
        source_mode = bh['source_mode']

        # Step 2: scan branches
        scan = scan_path_branches(
            binary_path=binary_path,
            path=path_dict,
            source_mode=source_mode,
            timeout=120,
        )
        if not scan.get('success'):
            record['error_msg'] = f'scan_failed: {scan.get("error", "")[:200]}'
            record['crashed'] = True
            record['verdict'] = 'vulnerable'
            return record

        branches = scan.get('tainted_branches', [])

        # Step 3: heuristic decisions
        branch_decisions = _heuristic_branch_decisions(branches)

        # Step 4: attack predicate
        attack_predicate = None
        if cwe == '190':
            attack_predicate = _attack_predicate_cwe190(sink_node.get('file_path', ''))

        # Step 5: verify
        result = verify_with_decisions(
            binary_path=binary_path,
            path=path_dict,
            source_mode=source_mode,
            branch_decisions=branch_decisions,
            attack_predicate=attack_predicate,
            timeout=120,
        )

        if not result.get('success'):
            err = (result.get('error') or '')[:200]
            if 'timeout' in err.lower():
                record['timeout'] = True
            else:
                record['crashed'] = True
            record['error_msg'] = f'verify_failed: {err}'
            record['verdict'] = 'vulnerable'
            return record

        record['analyzed'] = True
        if result.get('reachable'):
            record['verdict'] = 'vulnerable'
            record['predicted'] = 1
            record['error_msg'] = (
                f'branches={len(branches)} included={sum(v for v in branch_decisions.values() if v)} '
                f'counterexample={result.get("counterexample", "")} '
                f'degraded={result.get("degraded")}'
            )
        else:
            record['verdict'] = 'safe'
            record['predicted'] = 0
            record['error_msg'] = (
                f'branches={len(branches)} included={sum(v for v in branch_decisions.values() if v)} '
                f'paths_explored={result.get("paths_explored")} '
                f'degraded={result.get("degraded")}'
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
    compile_script = _ensure_compile_script(DATASET)
    if not compile_script:
        print('compile.sh not found and could not be written.')
        sys.exit(1)

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

            parsed = parse_sarif(sarif_path, dataset_root=DATASET)
            if not parsed.get('success'):
                print(f'CWE-{cwe}: parse_sarif failed: {parsed.get("error")}')
                continue

            paths = parsed.get('paths', [])
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
            'codeql_fp': total,
            'tool_fp': fp,
            'tool_tn': tn,
            'fp_reduction': round(1 - (fp / total), 4) if total else 0.0,
            'analyzed_rate': round(analyzed / total, 4) if total else 0.0,
            'crashed': crashed,
            'timeout': timed,
        })

    if metrics_per_cwe:
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
