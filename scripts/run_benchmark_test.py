#!/usr/bin/env python3
import subprocess
import json
import re
import os
import argparse
import shutil
from tabulate import tabulate
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import multiprocessing
from typing import List, Optional


###################################################################
#
#           CodeQL CWE 树结构和对应的 QL 文件映射
#
###################################################################
CODEQL_CWE_TREE_OLD = {
    '134': ["134"],
    '190': ["190", "680"],
    '191': ["191"],
    '253': ['253'],
    '319': ['319', "5", "614", "1428"],
    '327': ["327", "328", "780", "1240", "916"],
    '367': ["367", "363"],
    '416': ["416"],
    '676': ["676", "785"]
}
CODEQL_CWE_ENTRIES_OLD = {
    "134": [
        "Likely Bugs/Format/NonConstantFormat.ql",
        "Security/CWE/CWE-134/UncontrolledFormatString.ql"
    ],
    "190": [
        "Likely Bugs/AmbiguouslySignedBitField.ql",
        "Likely Bugs/Arithmetic/BadAdditionOverflowCheck.ql",
        "Likely Bugs/Arithmetic/IntMultToLong.ql",
        "Likely Bugs/Arithmetic/SignedOverflowCheck.ql",
        "Likely Bugs/Format/SnprintfOverflow.ql",
        "Security/CWE/CWE-190/ArithmeticTainted.ql",
        "Security/CWE/CWE-190/ArithmeticUncontrolled.ql",
        "Security/CWE/CWE-190/ArithmeticWithExtremeValues.ql",
        "Security/CWE/CWE-190/ComparisonWithWiderType.ql",
        "Security/CWE/CWE-190/IntegerOverflowTainted.ql",
        "Security/CWE/CWE-190/TaintedAllocationSize.ql",
        "experimental/Security/CWE/CWE-190/AllocMultiplicationOverflow.ql",
        "experimental/Security/CWE/CWE-190/DangerousUseOfTransformationAfterOperation.ql",
        "experimental/Security/CWE/CWE-190/IfStatementAdditionOverflow.ql",
        "jsf/4.20 Unions and Bit Fields/AV Rule 154.ql"
    ],
    "680": [],
    "191": [
        "Security/CWE/CWE-190/ArithmeticTainted.ql",
        "Security/CWE/CWE-190/ArithmeticUncontrolled.ql",
        "Security/CWE/CWE-190/ArithmeticWithExtremeValues.ql",
        "Security/CWE/CWE-191/UnsignedDifferenceExpressionComparedZero.ql"
    ],
    "253": [
        "Critical/IncorrectCheckScanf.ql",
        "Critical/MissingCheckScanf.ql",
        "Likely Bugs/Format/SnprintfOverflow.ql",
        "Security/CWE/CWE-253/HResultBooleanConversion.ql"
    ],
    "319": [
        "Security/CWE/CWE-311/CleartextTransmission.ql",
        "Security/CWE/CWE-319/UseOfHttp.ql"
    ],
    "5": [
        "Best Practices/Unused Entities/UnusedLocals.ql",
        "Best Practices/Unused Entities/UnusedStaticFunctions.ql",
        "Best Practices/Unused Entities/UnusedStaticVariables.ql",
        "Critical/DeadCodeCondition.ql",
        "Critical/DeadCodeFunction.ql",
        "Critical/DeadCodeGoto.ql",
        "Critical/ReturnStackAllocatedObject.ql",
        "Critical/Unused.ql",
        "Documentation/FixmeComments.ql",
        "Documentation/TodoComments.ql",
        "Likely Bugs/Likely Typos/ExprHasNoEffect.ql",
        "Microsoft/IgnoreReturnValueSAL.ql",
        "Security/CWE/CWE-570/IncorrectAllocationErrorHandling.ql",
        "experimental/Security/CWE/CWE-266/IncorrectPrivilegeAssignment.ql",
        "experimental/Security/CWE/CWE-561/FindIncorrectlyUsedSwitch.ql"
    ],
    "614": [],
    "1428": [],
    "327": [
        "Likely Bugs/Protocols/UseOfDeprecatedHardcodedProtocol.ql",
        "Security/CWE/CWE-327/BrokenCryptoAlgorithm.ql",
        "Security/CWE/CWE-327/OpenSslHeartbleed.ql",
        "experimental/cryptography/example_alerts/WeakBlockMode.ql",
        "experimental/cryptography/example_alerts/WeakEllipticCurve.ql",
        "experimental/cryptography/example_alerts/WeakEncryption.ql",
        "experimental/cryptography/example_alerts/WeakHashes.ql"
    ],
    "328": [],
    "780": [],
    "1240": [
        "experimental/Security/CWE/CWE-1240/CustomCryptographicPrimitive.ql"
    ],
    "916": [],
    "367": [
        "Security/CWE/CWE-367/TOCTOUFilesystemRace.ql"
    ],
    "363": [],
    "416": [
        "Critical/UseAfterFree.ql",
        "Security/CWE/CWE-416/IteratorToExpiredContainer.ql",
        "Security/CWE/CWE-416/UseOfStringAfterLifetimeEnds.ql",
        "Security/CWE/CWE-416/UseOfUniquePointerAfterLifetimeEnds.ql",
        "experimental/Security/CWE/CWE-416/UseAfterExpiredLifetime.ql"
    ],
    "676": [
        "Likely Bugs/Memory Management/PotentialBufferOverflow.ql",
        "Likely Bugs/Memory Management/StrncpyFlippedArgs.ql",
        "Likely Bugs/Memory Management/SuspiciousCallToMemset.ql",
        "Likely Bugs/Memory Management/SuspiciousCallToStrncat.ql",
        "Likely Bugs/Memory Management/UnsafeUseOfStrcat.ql",
        "Security/CWE/CWE-676/DangerousFunctionOverflow.ql",
        "Security/CWE/CWE-676/DangerousUseOfCin.ql",
        "Security/CWE/CWE-676/PotentiallyDangerousFunction.ql"
    ],
    "785": []
}

CODEQL_CWE_TREE = {
    "134": ["134"],
    "119": ["119", "466", "786", "787", "788", "805"],
    "120": ["120", "785"],
    "125": ["125", "126", "127"],
    "190": ["190"],
    "457": ["457"],
    "415": ["415", "825", "1341"],
    "416": ["416"],
}

CODEQL_CWE_ENTRIES = {
    "134": [
        "Likely Bugs/Format/NonConstantFormat.ql",
        "Security/CWE/CWE-134/UncontrolledFormatString.ql",
    ],
    "119": [
        "Critical/OverflowDestination.ql",
        "Critical/OverflowStatic.ql",
        "Likely Bugs/Conversion/CastArrayPointerArithmetic.ql",
        "Likely Bugs/Memory Management/StrncpyFlippedArgs.ql",
        "Likely Bugs/Memory Management/SuspiciousCallToStrncat.ql",
        "Security/CWE/CWE-119/OverflowBuffer.ql",
        "Security/CWE/CWE-119/OverrunWriteProductFlow.ql",
        "Security/CWE/CWE-193/InvalidPointerDeref.ql",
    ],
    "466": [],
    "786": [],
    "787": [
        "Security/CWE/CWE-120/BadlyBoundedWrite.ql",
        "Security/CWE/CWE-120/OverrunWrite.ql",
        "Security/CWE/CWE-120/OverrunWriteFloat.ql",
        "Security/CWE/CWE-120/UnboundedWrite.ql",
        "Security/CWE/CWE-120/VeryLikelyOverrunWrite.ql",
        "Security/CWE/CWE-193/InvalidPointerDeref.ql",
        "experimental/Security/CWE/CWE-787/UnsignedToSignedPointerArith.ql",
    ],
    "788": [
        "Likely Bugs/Memory Management/SuspiciousCallToStrncat.ql",
        "Security/CWE/CWE-327/OpenSslHeartbleed.ql",
        "experimental/Security/CWE/CWE-788/AccessOfMemoryLocationAfterEndOfBufferUsingStrlen.ql",
    ],
    "805": [
        "Security/CWE/CWE-120/BadlyBoundedWrite.ql",
        "Security/CWE/CWE-120/OverrunWrite.ql",
        "Security/CWE/CWE-120/OverrunWriteFloat.ql",
        "Security/CWE/CWE-120/UnboundedWrite.ql",
        "Security/CWE/CWE-120/VeryLikelyOverrunWrite.ql",
        "experimental/Security/CWE/CWE-805/BufferAccessWithIncorrectLengthValue.ql",
    ],
    "120": [
        "Best Practices/Likely Errors/OffsetUseBeforeRangeCheck.ql",
        "Critical/OverflowCalculated.ql",
        "Likely Bugs/Memory Management/UnsafeUseOfStrcat.ql",
        "Security/CWE/CWE-120/BadlyBoundedWrite.ql",
        "Security/CWE/CWE-120/OverrunWrite.ql",
        "Security/CWE/CWE-120/OverrunWriteFloat.ql",
        "Security/CWE/CWE-120/UnboundedWrite.ql",
        "Security/CWE/CWE-120/VeryLikelyOverrunWrite.ql",
        "Security/CWE/CWE-131/NoSpaceForZeroTerminator.ql",
        "experimental/Security/CWE/CWE-120/MemoryUnsafeFunctionScan.ql",
    ],
    "785": [],
    "125": [
        "Best Practices/Likely Errors/OffsetUseBeforeRangeCheck.ql",
        "Security/CWE/CWE-193/InvalidPointerDeref.ql",
        "experimental/Security/CWE/CWE-125/DangerousWorksWithMultibyteOrWideCharacters.ql",
    ],
    "126": [
        "Security/CWE/CWE-119/OverflowBuffer.ql",
    ],
    "127": [],
    "190": [
        "Likely Bugs/AmbiguouslySignedBitField.ql",
        "Likely Bugs/Arithmetic/BadAdditionOverflowCheck.ql",
        "Likely Bugs/Arithmetic/IntMultToLong.ql",
        "Likely Bugs/Arithmetic/SignedOverflowCheck.ql",
        "Likely Bugs/Format/SnprintfOverflow.ql",
        "Security/CWE/CWE-190/ArithmeticTainted.ql",
        "Security/CWE/CWE-190/ArithmeticUncontrolled.ql",
        "Security/CWE/CWE-190/ArithmeticWithExtremeValues.ql",
        "Security/CWE/CWE-190/ComparisonWithWiderType.ql",
        "Security/CWE/CWE-190/IntegerOverflowTainted.ql",
        "Security/CWE/CWE-190/TaintedAllocationSize.ql",
        "experimental/Security/CWE/CWE-190/AllocMultiplicationOverflow.ql",
        "experimental/Security/CWE/CWE-190/DangerousUseOfTransformationAfterOperation.ql",
        "experimental/Security/CWE/CWE-190/IfStatementAdditionOverflow.ql",
        "jsf/4.20 Unions and Bit Fields/AV Rule 154.ql",
    ],
    "457": [
        "Critical/GlobalUseBeforeInit.ql",
        "Critical/NotInitialised.ql",
        "Likely Bugs/Memory Management/UninitializedLocal.ql",
        "Security/CWE/CWE-457/ConditionallyUninitializedVariable.ql",
    ],
    "415": [
        "Critical/DoubleFree.ql",
        "experimental/Security/CWE/CWE-415/DoubleFree.ql",
        "experimental/Security/CWE/CWE-476/DangerousUseOfExceptionBlocks.ql",
    ],
    "825": [
        "Likely Bugs/Memory Management/ReturnStackAllocatedMemory.ql",
        "Likely Bugs/Memory Management/UsingExpiredStackAddress.ql",
    ],
    "1341": [],
    "416": [
        "Critical/UseAfterFree.ql",
        "Security/CWE/CWE-416/IteratorToExpiredContainer.ql",
        "Security/CWE/CWE-416/UseOfStringAfterLifetimeEnds.ql",
        "Security/CWE/CWE-416/UseOfUniquePointerAfterLifetimeEnds.ql",
        "experimental/Security/CWE/CWE-416/UseAfterExpiredLifetime.ql",
    ],
}


#################################################################
#           全局路径和并行参数配置
#################################################################
PROJECT_ROOT = Path(__file__).resolve().parent.parent   # 指向 CodeQL-AI 根目录

# === 当前容器专用路径（已修改）===
WORKSPACE_BASE = Path("/data/benchmark/juliet")
DB_BASE_PATH = WORKSPACE_BASE / "databases"          # 容器里已有 databases 目录
OUTPUT_BASE_PATH = WORKSPACE_BASE / "output"         # 容器里已有 output 目录

# Juliet 测试集路径（根据你 ls 结果适配）
JULIET_CASES_BASE = Path("/data/benchmark/juliet/juliet-test-suite-c/testcases")
JULIET_SCRIPT = Path("/data/benchmark/juliet/juliet-test-suite-c/juliet.py")   # ← 如果 juliet.py 不在这个位置，下面告诉我

# CodeQL 查询库（当前容器是 /home/tingji/my-codeql-repo）
QL_BASE_PATH = Path("/opt/codeql-lib/cpp/ql/src")

SARIF_URI_PREFIX = Path("/data/benchmark/juliet/juliet-test-suite-c")


def detect_ql_base_path(default_path: Path) -> Path:
    """自动探测可用的 CodeQL ql/src 目录（已适配当前容器）"""
    candidates = [
        Path("/opt/codeql-lib/cpp/ql/src"),           # ← 当前容器实际路径（最高优先级）
        default_path,
    ]
    for path in candidates:
        if (path / "Security" / "CWE").exists() or (path / "Likely Bugs" / "Format" / "NonConstantFormat.ql").exists():
            if path != default_path:
                print(f"[✅] 使用当前容器 QL 路径: {path}")
            return path
    print(f"[⚠️] 未找到完整 QL 库，继续使用默认: {default_path}")
    return default_path


QL_BASE_PATH = detect_ql_base_path(QL_BASE_PATH)

# ================= 并行参数优化（保持你原来的）=================
TOTAL_THREADS = multiprocessing.cpu_count()
EXTERNAL_TASKS = 4
INTERNAL_THREADS = TOTAL_THREADS // EXTERNAL_TASKS

# 把 juliet.py 所在的目录作为强制根目录
JULIET_ROOT_DIR = Path(JULIET_SCRIPT).resolve().parent

CODEQL_DB_CREATE = [
    "codeql", "database", "create",   
    "--language=cpp",
    f"--source-root={JULIET_ROOT_DIR}",   # <--- 新增这一行：强制锁定源码目录
    "-j", str(TOTAL_THREADS),
    "--overwrite",          
    "--command",
]

# 修改后：去掉最后的 "--output"
CODEQL_DB_ANALYZE = [
    "codeql", "database", "analyze",
    "-j", str(INTERNAL_THREADS),
    "--format=sarif-latest"
]

def run_subprocess(command, cwd=None):
    """运行子进程命令并捕获输出"""
    result = subprocess.run(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result.stdout, result.stderr, result.returncode


def resolve_cmake_file(build_type: str) -> Optional[Path]:
    """解析 good/bad 对应的 CMakeLists 文件，兼容点号和下划线命名。"""
    juliet_root = Path(JULIET_SCRIPT).resolve().parent
    candidates = [
        juliet_root / f"CMakeLists.{build_type}.txt",
        juliet_root / f"CMakeLists_{build_type}.txt",
        PROJECT_ROOT / "juliet-test-suite-c" / f"CMakeLists.{build_type}.txt",
        PROJECT_ROOT / "juliet-test-suite-c" / f"CMakeLists_{build_type}.txt",
    ]
    for item in candidates:
        if item.exists():
            return item
    return None

def build_full_db(path_prefix: str="", force_rebuild: bool=False) -> bool:
    """使用 Juliet 脚本构建完整的 CodeQL 数据库（包含所有 CWE）

    args:
        path_prefix: db路径前缀
        force_rebuild: 是否强制覆盖重建数据库
    return:
        构建成功返回 True, output_path，否则返回 False, None
    """
    output_path = DB_BASE_PATH / Path(path_prefix + "juliet_full_db")
    
    if output_path.exists() and not force_rebuild:
        print(f"[⚠️] CodeQL 数据库已存在，跳过构建: {output_path}")
        return True, output_path
    command = CODEQL_DB_CREATE + [
        f"python3 {JULIET_SCRIPT} -a -c -g -m -o build_tmp",
        str(output_path)
    ]
    print(f"[🚀] 开始构建 CodeQL 数据库: {output_path}")
    stdout, stderr, returncode = run_subprocess(command)
    if returncode != 0:
        print(f"[❌] 构建 CodeQL 数据库失败:\n{stderr}")
        return False, None

    print(f"[✅] 成功构建 CodeQL 数据库: {output_path}")
    return True, output_path

def build_tree_cwe_db(path_prefix: str="", cwe_id: str="", build_type: str="good", force_rebuild: bool=False) -> bool:
    """使用 Juliet 脚本构建指定 CWE 树的 CodeQL 数据库

    args:
        path_prefix: db路径前缀
        cwe_id: CWE 编号
        build_type: 构建类型，good 或 bad
        force_rebuild: 是否强制覆盖重建数据库
    return:
        构建成功返回 True，否则返回 False
    """
    if cwe_id not in CODEQL_CWE_TREE:
        print(f"[❌] 未知的 CWE 编号: {cwe_id}")
        return False
    output_path = DB_BASE_PATH / Path(f"{path_prefix}_{build_type}_tree_cwe-{cwe_id}_db")
    
    if output_path.exists() and not force_rebuild:
        print(f"[⚠️] CodeQL 数据库已存在，跳过构建: {output_path}")
        return True

    entities = CODEQL_CWE_TREE.get(cwe_id, [])
    if entities:
        print(f"[ℹ️] CWE {cwe_id} 包含子 CWE: {entities}")
        cmake_variant = resolve_cmake_file(build_type)
        juliet_root = Path(JULIET_SCRIPT).resolve().parent
        default_cmake = juliet_root / "CMakeLists.txt"
        backup_cmake = juliet_root / "CMakeLists.txt.benchmark_backup"

        command = CODEQL_DB_CREATE + [
            f"python3 {JULIET_SCRIPT} -c -g -m -o build_tmp " + " ".join(entities),
            str(output_path)
        ]
        print(f"[ℹ️] 构建包含 CWE {cwe_id} 及其子 CWE 的数据库，子 CWE 列表: {entities}")

        if cmake_variant is not None and default_cmake.exists():
            print(f"[ℹ️] 使用 {cmake_variant.name} 进行 {build_type} 构建")
            shutil.copy2(default_cmake, backup_cmake)
            shutil.copy2(cmake_variant, default_cmake)
        elif cmake_variant is None:
            print(f"[⚠️] 未找到 {build_type} 对应 CMakeLists，使用默认 CMakeLists.txt")

        print(f"[🚀] 开始构建 CWE {cwe_id} (type: {build_type}) 的数据库")
        try:
            stdout, stderr, returncode = run_subprocess(command)
        finally:
            if backup_cmake.exists():
                shutil.move(str(backup_cmake), str(default_cmake))
        if returncode != 0:
            print(f"[❌] 构建 CWE {cwe_id} 数据库失败:\n{stderr}")
            return False
        else:
            print(f"[✅] 成功构建 CWE {cwe_id}(type: {build_type}) 数据库: {output_path}")
            return True
    else:
        print(f"[ℹ️] CWE {cwe_id} 无子 CWE")
        return False

def generate_cwe_ql_file(cwe_id: str, output_path: Path) -> bool:
    """生成包含指定 CWE 及其子 CWE 查询的 QL 文件

    args:
        cwe_id: CWE 编号
        output_path: 生成的 QL 文件路径
    return:
        生成成功返回 True，否则返回 False
    """
    if cwe_id not in CODEQL_CWE_TREE:
        print(f"[❌] 未知的 CWE 编号: {cwe_id}")
        return False

    entries = []
    for sub_cwe in CODEQL_CWE_TREE[cwe_id]:
        ql_files = CODEQL_CWE_ENTRIES.get(sub_cwe, [])
        entries.extend(ql_files)

    if not entries:
        print(f"[❌] 未找到 CWE {cwe_id} 及其子 CWE 的 QL 文件")
        return False

    qls_file = output_path / Path(f"llm_benchmark/parent-cwe-{cwe_id}-queries.qls")
    qls_file.parent.mkdir(parents=True, exist_ok=True)
    valid_queries = []
    missing_queries = []
    for ql_file in entries:
        query_path = Path(ql_file) if Path(ql_file).is_absolute() else (QL_BASE_PATH / ql_file)
        if query_path.exists():
            valid_queries.append(query_path)
        else:
            missing_queries.append(str(query_path))

    if missing_queries:
        print(f"[⚠️] 以下 QL 文件不存在，已跳过 ({len(missing_queries)}):")
        for item in missing_queries:
            print(f"    - {item}")

    if not valid_queries:
        if qls_file.exists():
            qls_file.unlink()
        print(f"[❌] CWE {cwe_id} 没有可用的 QL 文件，无法生成查询套件")
        return False

    with open(qls_file, "w", encoding="utf-8") as f:
        f.write(f"# 自动生成的 CWE-{cwe_id} 查询文件\n")
        for query_path in valid_queries:
            f.write(f"- query: \"{query_path.as_posix()}\"\n")

    print(f"[✅] 成功生成 CWE {cwe_id} 的 QL 文件: {qls_file}")
    return True


def analyze_db(ql_path: Path, db_path: Path, output_path: Path, rerun: bool = False) -> bool:
    """使用指定的 QL 文件分析 CodeQL 数据库

    args:
        ql_path: QL 文件路径
        db_path: CodeQL 数据库路径
        output_path: 分析结果输出路径
        rerun: 是否强制重新分析（CodeQL --rerun 标志）
    """
    command = CODEQL_DB_ANALYZE.copy()

    if rerun:
        command.append("--rerun")
        print(f"[🔄] --rerun 模式已启用：强制重新评估查询（忽略缓存）")

    command += [
        "--output", str(output_path),   # 刚才从全局变量拿下来的 --output 放这里
        str(db_path),
        str(ql_path)
    ]

    print(f"[🚀] 开始分析数据库: {db_path} 使用 QL 文件: {ql_path}")
    print(f"[ℹ️] command: {' '.join(command)}")
    
    stdout, stderr, returncode = run_subprocess(command)

    if returncode != 0:
        print(f"[❌] 分析失败:\n{stderr}")
        return False

    print(f"[✅] 成功分析数据库，结果存储在: {output_path}")
    return True

def analyze_sarif_file(file_path: Path) -> set:
    """分析单个 SARIF 文件，返回报告涉及文件集合
    
    Args:
        file_path (Path): SARIF 文件路径
        Returns: Set[Path]: 报告中涉及的文件路径集合
    """
    if file_path.exists() is False:
        print(f"[❌] SARIF 文件不存在: {file_path}")
        return set()
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    files_in_report = set()
    for run in data.get("runs", []):
        for result in run.get("results", []):
            for loc in result.get("locations", []):
                phys = loc.get("physicalLocation", {})
                artifact = phys.get("artifactLocation", {})
                uri = artifact.get("uri")
                if uri:
                    files_in_report.add(SARIF_URI_PREFIX / uri)
    return files_in_report

def find_cases_in_juliet(filter_good: bool=True, filter_cwe: bool=True, cwe_list: list=None) -> set:
    """统计 Juliet 测试用例数量，支持过滤良性/缺陷用例和指定 CWE 列表（当前函数框架，具体实现需要根据实际目录结构适配）

    args:
        filter_good: 是否只统计良性用例
        filter_cwe: 是否根据 CWE 列表过滤
        cwe_list: 指定的 CWE 列表
    return:
        set 样例的集合
    """
    total = set()
    if cwe_list is not None:
        for d in JULIET_CASES_BASE.glob('*'):
            if d.is_dir() and any([x in d.name for x in cwe_list]):
                for file in d.rglob('*'):
                    if file.is_file():
                        pass
            else:
                # d is not a directory or does not match CWE filter
                pass
                
            
    for cwe_dir in JULIET_CASES_BASE.iterdir():
        if cwe_dir.is_dir():
            if True:
                pass
                
    return total

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CodeQL CWE build/analyze runner")
    parser.add_argument("--cwes", default="", help="逗号分隔 CWE 列表，例如 134,190")
    parser.add_argument("--build-types", default="good,bad", help="逗号分隔构建类型：good,bad")
    parser.add_argument("--stages", default="build,analyze,report", help="逗号分隔阶段：build,analyze,report")
    parser.add_argument("--rerun", action="store_true",
                        help="强制重新运行 CodeQL 分析（使用官方 --rerun 标志），适用于修改 QL 文件后需要绕过缓存的情况")
    # 👇 新增这一行 👇
    parser.add_argument("--rebuild", action="store_true",
                        help="强制重新构建 CodeQL 数据库（覆盖旧数据库），适用于修改了测试集源码或需清理环境的情况")
    args = parser.parse_args()

    def parse_csv_arg(raw: str) -> List[str]:
        if not raw:
            return []
        return [x.strip() for x in raw.split(",") if x.strip()]

    def validate_build_types(types: List[str]) -> List[str]:
        if not types:
            return ["good", "bad"]
        normalized = [x.lower() for x in types]
        invalid = [x for x in normalized if x not in {"good", "bad"}]
        if invalid:
            raise ValueError(f"不支持的 build_type: {invalid}，仅支持 good/bad")
        return normalized

    selected_cwes = parse_csv_arg(args.cwes)
    if not selected_cwes:
        selected_cwes = list(CODEQL_CWE_TREE.keys())
    unknown_cwes = [x for x in selected_cwes if x not in CODEQL_CWE_TREE]
    if unknown_cwes:
        raise ValueError(f"未知的 CWE 编号: {unknown_cwes}，可选: {sorted(CODEQL_CWE_TREE.keys())}")

    selected_build_types = validate_build_types(parse_csv_arg(args.build_types))
    selected_stages = set(parse_csv_arg(args.stages))
    if not selected_stages:
        selected_stages = {"build", "analyze", "report"}

    runnable_cwes = []
    for cwe in selected_cwes:
        if generate_cwe_ql_file(cwe_id=cwe, output_path=QL_BASE_PATH):
            runnable_cwes.append(cwe)

    if not runnable_cwes:
        raise RuntimeError("没有可运行的 CWE：对应 QL 文件均不可用，请检查 CODEQL_QL_SRC")

    if "build" in selected_stages:
        for build_type in selected_build_types:
            with ThreadPoolExecutor(max_workers=1) as executor:
                futures = {
                    executor.submit(
                        build_tree_cwe_db,
                        path_prefix="final",
                        cwe_id=cwe,
                        build_type=build_type,
                        force_rebuild=args.rebuild
                    ): cwe for cwe in runnable_cwes
                }
                for future in as_completed(futures):
                    result = future.result()
                    cwe = futures[future]
                    print(f"[ℹ️] CWE-{cwe} {build_type} 构建任务完成，结果: {result}")

    if "analyze" in selected_stages:
        for build_type in selected_build_types:
            with ThreadPoolExecutor(max_workers=EXTERNAL_TASKS) as executor:
                futures = {
                    executor.submit(
                        analyze_db,
                        ql_path=QL_BASE_PATH / Path(f"llm_benchmark/parent-cwe-{cwe}-queries.qls"),
                        db_path=DB_BASE_PATH / Path(f"final_{build_type}_tree_cwe-{cwe}_db"),
                        output_path=OUTPUT_BASE_PATH / Path(f"final_{build_type}_tree_cwe-{cwe}_db.sarif"),
                        rerun=args.rerun   # ← 新增：支持 --rerun 选项
                    ): cwe for cwe in runnable_cwes
                }
                for future in as_completed(futures):
                    result = future.result()
                    cwe = futures[future]
                    print(f"[ℹ️] CWE-{cwe} {build_type} 分析任务完成，结果: {result}")

    if "report" in selected_stages:
        header = ["CWE 编号"] + [f"{x} 用例涉及文件数量" for x in selected_build_types]
        tab = []
        for cwe in runnable_cwes:
            row = [f"CWE-{cwe}"]
            for build_type in selected_build_types:
                row.append(len(analyze_sarif_file(
                    OUTPUT_BASE_PATH / Path(f"final_{build_type}_tree_cwe-{cwe}_db.sarif")
                )))
            tab.append(row)
        print(tabulate(tab, headers=header, tablefmt="grid"))
