#!/usr/bin/env python3
"""
双向 QL 文件替换脚本。

输入：一个 JSON 文件，记录 original_ql -> patched_ql 的映射关系。

JSON 格式示例：
{
    "mappings": [
        {
            "original_ql": "/abs/path/to/original.ql",
            "patched_ql": "/abs/path/to/scripts/.CODEQL-AI/patched-ql/patched.ql"
        }
    ]
}

操作模式：
  apply   — 备份 original_ql 到 old-ql/，用 patched_ql 覆盖 original_ql
  restore — 将 old-ql/ 中的备份写回 original_ql
"""

import argparse
import json
import shutil
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
CODEQL_AI_DIR = SCRIPT_DIR / ".CODEQL-AI"
OLD_QL_DIR = CODEQL_AI_DIR / "old-ql"
PATCHED_QL_DIR = CODEQL_AI_DIR / "patched-ql"


def backup_key(original_ql: str) -> str:
    """将绝对路径转成扁平的备份文件名，避免冲突。"""
    return original_ql.strip("/").replace("/", "__")


def ensure_dirs():
    OLD_QL_DIR.mkdir(parents=True, exist_ok=True)
    PATCHED_QL_DIR.mkdir(parents=True, exist_ok=True)


def load_mappings(json_path: str) -> list:
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    mappings = data.get("mappings", [])
    if not mappings:
        print("错误：JSON 中没有 mappings 或为空", file=sys.stderr)
        sys.exit(1)
    return mappings


def apply_patches(mappings: list, force: bool = False):
    """备份原始 QL，用 patched QL 覆盖。"""
    ensure_dirs()
    for entry in mappings:
        original = Path(entry["original_ql"])
        patched = Path(entry["patched_ql"])

        if not original.exists():
            print(f"跳过：原始文件不存在 {original}")
            continue
        if not patched.exists():
            print(f"跳过：patched 文件不存在 {patched}")
            continue

        backup_path = OLD_QL_DIR / backup_key(str(original))

        if backup_path.exists() and not force:
            print(f"备份已存在，跳过备份（使用 --force 覆盖）：{backup_path.name}")
        else:
            shutil.copy2(str(original), str(backup_path))
            print(f"已备份：{original} -> {backup_path.name}")

        shutil.copy2(str(patched), str(original))
        print(f"已应用：{patched} -> {original}")


def restore_originals(mappings: list):
    """将备份还原到原始位置。"""
    for entry in mappings:
        original = Path(entry["original_ql"])
        backup_path = OLD_QL_DIR / backup_key(str(original))

        if not backup_path.exists():
            print(f"跳过：备份不存在 {backup_path.name}")
            continue

        shutil.copy2(str(backup_path), str(original))
        print(f"已还原：{backup_path.name} -> {original}")


def show_status(mappings: list):
    """显示当前映射的状态。"""
    for entry in mappings:
        original = Path(entry["original_ql"])
        patched = Path(entry["patched_ql"])
        backup_path = OLD_QL_DIR / backup_key(str(original))

        status_parts = []
        if backup_path.exists():
            status_parts.append("有备份")
        else:
            status_parts.append("无备份")
        if not original.exists():
            status_parts.append("原始文件缺失")
        if not patched.exists():
            status_parts.append("patched文件缺失")

        status = ", ".join(status_parts)
        print(f"  [{status}] {original.name}")
        print(f"    原始: {original}")
        print(f"    补丁: {patched}")
        print()


def main():
    parser = argparse.ArgumentParser(description="双向 QL 文件替换工具")
    parser.add_argument("action", choices=["apply", "restore", "status"],
                        help="apply=用patched覆盖原始, restore=还原备份, status=查看状态")
    parser.add_argument("json_file", help="映射关系 JSON 文件路径")
    parser.add_argument("--force", action="store_true",
                        help="apply 时强制覆盖已有备份")

    args = parser.parse_args()
    mappings = load_mappings(args.json_file)

    if args.action == "apply":
        apply_patches(mappings, force=args.force)
    elif args.action == "restore":
        restore_originals(mappings)
    elif args.action == "status":
        show_status(mappings)


if __name__ == "__main__":
    main()
