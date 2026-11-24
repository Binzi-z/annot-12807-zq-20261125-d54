"""独立验证工具的进程入口（只读磁盘，不与网关共享任何内存状态）。

用法
====
    python tools/verify_disk.py --data-dir <演练数据目录> \\
        [--sides side-a,side-b] [--out report.json]

退出码：0 = PASS，1 = FAIL，2 = 工具自身错误。
该入口刻意保持极薄：所有逻辑在 drill.verifier，且本进程以 "r" 模式
打开全部演练数据，可在网关进程完全退出后单独运行。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# 允许在未安装包的情况下从仓库根直接运行
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from drill.verifier import verify_run  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="离线演练独立磁盘验证器（只读，无网络）")
    parser.add_argument("--data-dir", required=True,
                        help="包含 trust_manifest.json 与各侧目录的演练目录")
    parser.add_argument("--sides", default="side-a,side-b",
                        help="逗号分隔的侧目录名")
    parser.add_argument("--out", default=None,
                        help="验证报告输出路径；缺省打印到标准输出")
    args = parser.parse_args(argv)

    try:
        sides = tuple(s.strip() for s in args.sides.split(",") if s.strip())
        report = verify_run(Path(args.data_dir), sides=sides)
    except FileNotFoundError as exc:
        print(json.dumps({"verdict": "ERROR", "error": str(exc)},
                         ensure_ascii=False, indent=2),
              file=sys.stderr)
        return 2

    text = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
