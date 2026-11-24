"""总装运行器：串联离线演练的全部步骤并落盘汇总报告。

步骤
====
0. 离线守卫静态扫描（任何联网模块导入直接失败）；
1. 三场景双真实线程屏障复测（各含确定性与竞争变体）；
2. 事故复现（修复/旧版/混合三种引擎组合）；
3. 六万封包大规模演练 + 三个远距离故障分区的局部修订；
4. 以独立子进程运行只读磁盘验证器，复核大规模演练与事故目录；
5. 汇总全部结论到 artifacts/summary.json 并打印中文摘要。

用法：python run_all.py [--base artifacts] [--skip-large]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from drill import incident, large_drill, scenarios, synthesize  # noqa: E402
from drill.offline_guard import assert_offline  # noqa: E402
from drill.trust import make_synthetic_manifest  # noqa: E402


def _run_verifier_subprocess(data_dir: Path, out: Path) -> dict:
    """以独立进程拉起只读验证器，返回其 JSON 报告。"""
    cmd = [sys.executable, str(ROOT / "tools" / "verify_disk.py"),
           "--data-dir", str(data_dir), "--out", str(out)]
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          cwd=str(ROOT), timeout=300)
    if not out.exists():
        raise RuntimeError(
            f"验证子进程未产出报告\nstdout={proc.stdout}\nstderr={proc.stderr}")
    return json.loads(out.read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="离线演练总装运行器")
    parser.add_argument("--base", default=str(ROOT / "artifacts"))
    parser.add_argument("--skip-large", action="store_true",
                        help="跳过六万封包大规模演练（快速冒烟）")
    args = parser.parse_args(argv)

    base = Path(args.base)
    base.mkdir(parents=True, exist_ok=True)
    summary: dict = {"steps": [], "verdict": "PASS"}

    def record(step: str, ok: bool, payload: dict) -> None:
        summary["steps"].append({"step": step, "ok": ok, "payload": payload})
        if not ok:
            summary["verdict"] = "FAIL"
        print(f"[{'PASS' if ok else 'FAIL'}] {step}")

    # 0. 离线守卫
    guard = assert_offline(ROOT)
    record("offline-guard", True, guard)
    print(f"    静态扫描 {guard['scanned_files']} 个 Python 文件，"
          "无任何联网模块导入")

    # 1. 三场景双线程屏障复测
    scenario_manifest = make_synthetic_manifest()
    scenario_dir = base / "scenarios"
    scenario_report = scenarios.run_all(scenario_dir, scenario_manifest)
    (base / "scenario_report.json").write_text(
        json.dumps(scenario_report, ensure_ascii=False, indent=2,
                   sort_keys=True), encoding="utf-8")
    record("thread-barrier-scenarios", scenario_report["all_passed"],
           {"scenarios": [s["name"] for s in scenario_report["scenarios"]],
            "details": [d for s in scenario_report["scenarios"]
                        for d in s["details"]]})

    # 2. 事故复现
    inc_manifest = make_synthetic_manifest()
    inc_dir = base / "incident"
    inc = incident.reproduce(inc_dir, inc_manifest)
    inc_payload = inc.as_dict()
    inc_ok = (
        not inc_payload["fixed_fixed"]["ghost_present_a"]
        and not inc_payload["fixed_fixed"]["ghost_present_b"]
        and inc_payload["fixed_fixed"]["heads_equal"]
        and inc_payload["legacy_legacy"]["ghost_present_a"]
        and inc_payload["legacy_legacy"]["ghost_present_b"]
        and inc_payload["legacy_legacy"]["heads_equal_but_both_wrong"]
        and not inc_payload["mixed"]["heads_equal"]
    )
    (base / "incident_report.json").write_text(
        json.dumps(inc_payload, ensure_ascii=False, indent=2,
                   sort_keys=True), encoding="utf-8")
    record("incident-replay", inc_ok, {
        "fixed_side_rejects_ghost":
            inc_payload["fixed_fixed"]["old_generation_rejected_a"],
        "legacy_both_wrong_but_equal":
            inc_payload["legacy_legacy"]["heads_equal_but_both_wrong"],
        "mixed_differing_segments":
            inc_payload["mixed"]["differing_segments"],
    })

    # 3. 六万封包大规模演练
    if not args.skip_large:
        large_dir = base / "large"
        large_report = large_drill.run(large_dir)
        record("large-60000-drill", large_report.verdict == "PASS",
               large_report.as_dict())

        # 4. 独立子进程只读验证（大规模演练目录）
        verify_report = _run_verifier_subprocess(
            large_dir, base / "large_verification.json")
        record("independent-disk-verifier-large",
               verify_report["verdict"] == "PASS", {
                   "verdict": verify_report["verdict"],
                   "issues": verify_report["issues"],
                   "sides": [{"side": s["side"],
                              "chain_records": s["chain_records"],
                              "reconstructed": s["reconstructed_count"],
                              "head_match":
                                  s["head_recomputed"] == s["head_published"]}
                             for s in verify_report["sides"]],
                   "reconciliation": verify_report["reconciliation"],
               })
    else:
        print("[SKIP] large-60000-drill（--skip-large）")

    # 4b. 独立子进程验证事故目录中的“修复/修复”一侧（应 PASS），
    #     以及“旧版/旧版”一侧（验证器用正确规则重放，应抓出幽灵 -> FAIL）
    fixed_verify = _run_verifier_subprocess(
        base / "incident" / "fixed-fixed",
        base / "incident_fixed_verification.json")
    record("independent-verifier-incident-fixed",
           fixed_verify["verdict"] == "PASS",
           {"verdict": fixed_verify["verdict"],
            "issues": fixed_verify["issues"]})

    legacy_verify = _run_verifier_subprocess(
        base / "incident" / "legacy-legacy",
        base / "incident_legacy_verification.json")
    # 旧版发布物与正确重放不一致，验证器必须判 FAIL
    record("independent-verifier-catches-legacy-ghost",
           legacy_verify["verdict"] == "FAIL",
           {"verdict": legacy_verify["verdict"],
            "issues": legacy_verify["issues"][:4]})

    (base / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8")
    print("\n==== 汇总 ====")
    print(json.dumps({s["step"]: s["ok"] for s in summary["steps"]},
                     ensure_ascii=False, indent=2))
    print(f"总体结论: {summary['verdict']}（报告目录 {base}）")
    return 0 if summary["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
