"""单元测试：python -m unittest discover -s tests -v"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from drill import digest as digest_mod
from drill.model import (
    O_COMMIT, O_REJECT_CANCEL, O_REJECT_CONFLICT, O_REJECT_OLD_GEN,
    T_APPROVAL, T_CANCEL, T_CANDIDATE, T_COMMIT, T_EPOCH, T_RECEIPT,
    batch_digest, canonical, envelope,
)
from drill.offline_guard import assert_offline
from drill.rules import LegacyRuleEngine, RuleEngine
from drill.scenarios import make_bundle, run_all
from drill.store import DurableLog
from drill.trust import (
    ApprovalPolicy, TrustManifest, TrustRoot, make_synthetic_manifest,
)

ROOT = Path(__file__).resolve().parent.parent


class CanonicalTests(unittest.TestCase):
    def test_key_order_independent(self) -> None:
        a = canonical({"x": 1, "y": [1, 2, {"z": 3}]})
        b = canonical({"y": [1, 2, {"z": 3}], "x": 1})
        self.assertEqual(a, b)

    def test_digest_binding_changes(self) -> None:
        d1 = batch_digest("B", "p", 0, {"v": 1})
        d2 = batch_digest("B", "p", 1, {"v": 1})
        d3 = batch_digest("B", "p", 0, {"v": 2})
        self.assertNotEqual(d1, d2)
        self.assertNotEqual(d1, d3)


class HashChainTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_chain_reopen_and_tamper(self) -> None:
        log = DurableLog(self.tmp / "in.jsonl")
        for i in range(5):
            log.append(envelope(T_EPOCH, generation=i))
        log.close()
        reopened = DurableLog(self.tmp / "in.jsonl")
        self.assertEqual(reopened.seq, 5)
        reopened.close()
        rows = self.tmp.joinpath("in.jsonl").read_text(encoding="utf-8").splitlines()
        rec = json.loads(rows[2])
        rec["env"]["generation"] = 999
        rows[2] = json.dumps(rec, sort_keys=True)
        self.tmp.joinpath("in.jsonl").write_text("\n".join(rows) + "\n",
                                                 encoding="utf-8")
        with self.assertRaises(ValueError):
            DurableLog(self.tmp / "in.jsonl")


class ApprovalPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = TrustManifest([
            TrustRoot("r1", "chain-a", b"k1" * 8),
            TrustRoot("r2", "chain-a", b"k2" * 8),   # 同链
            TrustRoot("r3", "chain-b", b"k3" * 8),
        ])
        self.b = batch_digest("B1", "part", 2, {"v": 1})

    def _apr(self, root: TrustRoot) -> dict:
        return envelope(T_APPROVAL, batch_id="B1", root_id=root.root_id,
                        generation=2, batch_digest=self.b, partition="part",
                        signature=root.sign(self.b, "part", 2))

    def test_same_chain_counts_once(self) -> None:
        policy = ApprovalPolicy(self.manifest)
        r1, r2, r3 = self.manifest.roots
        decision = policy.evaluate(self.b, "part", 2,
                                   [self._apr(r1), self._apr(r2)])
        self.assertFalse(decision.satisfied)
        self.assertEqual(decision.distinct_chains, ("chain-a",))

        decision = policy.evaluate(self.b, "part", 2,
                                   [self._apr(r1), self._apr(r3)])
        self.assertTrue(decision.satisfied)
        self.assertEqual(decision.distinct_chains, ("chain-a", "chain-b"))

    def test_duplicate_root_single_vote_and_bad_binding(self) -> None:
        policy = ApprovalPolicy(self.manifest)
        r1, r3 = self.manifest.roots[0], self.manifest.roots[2]
        decision = policy.evaluate(self.b, "part", 2,
                                   [self._apr(r1), self._apr(r1),
                                    self._apr(r3)])
        self.assertTrue(decision.satisfied)
        self.assertTrue(any(v["reason"] == "duplicate_root_single_vote"
                            for v in decision.rejected))

        # 链路代被替换 -> 签名校验失败
        bad = self._apr(r1)
        decision = policy.evaluate(self.b, "part", 3, [bad])
        self.assertFalse(decision.satisfied)
        self.assertTrue(any(v["reason"] == "bad_signature_or_binding"
                            for v in decision.rejected))


class RuleEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = make_synthetic_manifest()

    def test_generation_fence_blocks_old_redelivery(self) -> None:
        eng = RuleEngine(self.manifest, side="t")
        bundle = make_bundle(self.manifest, "B", "p", 0, {"v": 1})
        seq = 1
        for env in [bundle["cand"], *bundle["approvals"], bundle["commit"]]:
            eng.process(seq, env); seq += 1
        self.assertIn("B", eng.committed)
        eng.process(seq, envelope(T_EPOCH, generation=1)); seq += 1
        eng.process(seq, bundle["commit"]); seq += 1   # 旧代重投
        self.assertEqual(eng.counts.get(O_REJECT_OLD_GEN, 0), 1)
        self.assertEqual(len(eng.committed), 1)

        legacy = LegacyRuleEngine(self.manifest, side="t")
        s = 1
        for env in [bundle["cand"], *bundle["approvals"], bundle["commit"]]:
            legacy.process(s, env); s += 1
        legacy.process(s, envelope(T_EPOCH, generation=1)); s += 1
        legacy.process(s, bundle["commit"])              # 旧引擎照单全收
        self.assertEqual(legacy.counts.get(O_REJECT_OLD_GEN, 0), 0)

    def test_cancel_first_and_conflict(self) -> None:
        eng = RuleEngine(self.manifest, side="t")
        b1 = make_bundle(self.manifest, "X", "p", 0, {"v": 1})
        seq = 1
        eng.process(seq, b1["cand"]); seq += 1
        eng.process(seq, envelope(T_CANCEL, batch_id="X", generation=0,
                                  partition="p")); seq += 1
        eng.process(seq, b1["commit"]); seq += 1
        self.assertEqual(eng.batches["X"].outcome, O_REJECT_CANCEL)

        b2a = make_bundle(self.manifest, "Y", "p", 0, {"v": "a"})
        b2b = make_bundle(self.manifest, "Y", "p", 0, {"v": "b"})
        eng.process(seq, b2a["cand"]); seq += 1
        eng.process(seq, b2b["cand"]); seq += 1
        for apr in b2a["approvals"]:
            eng.process(seq, apr); seq += 1
        eng.process(seq, b2a["commit"]); seq += 1
        self.assertEqual(eng.batches["Y"].outcome, O_COMMIT)
        self.assertGreaterEqual(eng.counts.get(O_REJECT_CONFLICT, 0), 1)

    def test_receipt_dedup(self) -> None:
        eng = RuleEngine(self.manifest, side="t")
        bundle = make_bundle(self.manifest, "R", "p", 0, {"v": 1})
        seq = 1
        for env in [bundle["cand"], *bundle["approvals"], bundle["commit"]]:
            eng.process(seq, env); seq += 1
        rec = envelope(T_RECEIPT, receipt_id="R1", batch_id="R", generation=0)
        eng.process(seq, rec); seq += 1
        eng.process(seq, rec)
        self.assertEqual(eng.batches["R"].receipt_ids, ["R1"])


class SegmentDigestTests(unittest.TestCase):
    def test_segment_locality_and_head(self) -> None:
        commitments = [
            {"batch_id": f"B{i}", "partition": f"P{i % 8:04d}",
             "generation": 0, "batch_digest": f"d{i}"}
            for i in range(200)
        ]
        pub = digest_mod.build_published(
            commitments, segment_count=16, generation=0,
            trust_fingerprint="fp", logical_clock=1)
        self.assertEqual(pub["entry_count"], 200)
        self.assertEqual(len(pub["segment_roots"]), 16)

        touched = {"P0001"}
        report = digest_mod.revise_commitments(
            commitments, segment_count=16, touched_partitions=touched,
            transform=lambda entries: [e for e in entries
                                       if e["partition"] != "P0001"])
        self.assertEqual(report.segments_recomputed, 1)
        self.assertLess(report.entries_rehashed, 200)
        self.assertTrue(report.changed)


class ScenarioThreadTests(unittest.TestCase):
    def test_all_three_scenarios(self) -> None:
        tmp = Path(tempfile.mkdtemp())
        try:
            report = run_all(tmp, make_synthetic_manifest())
            self.assertTrue(report["all_passed"])
            for sc in report["scenarios"]:
                self.assertTrue(sc["passed"], sc["name"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class OfflineGuardTests(unittest.TestCase):
    def test_project_is_offline_clean(self) -> None:
        info = assert_offline(ROOT)
        self.assertGreaterEqual(info["scanned_files"], 8)


class WireSpoolTests(unittest.TestCase):
    def test_pending_confirm_redeliver_and_shuffle(self) -> None:
        import random
        from drill.network import FileLink

        tmp = Path(tempfile.mkdtemp())
        try:
            link = FileLink.open(tmp / "link")
            for i in range(6):
                link.send_a_to_b(envelope(T_EPOCH, generation=i))
            pending = link.deliver_to_b(random.Random(1))
            self.assertEqual(len(pending), 6)
            # 未确认前重投：同样 6 条，偏移冻结
            redelivered = link.a_to_b.redeliver()
            self.assertEqual(len(redelivered), 6)
            link.confirm_to_b(4)
            self.assertEqual(len(link.a_to_b.pending()), 2)
            # 乱序只改变顺序，不改变多重集
            shuffled = link.deliver_to_b(random.Random(7))
            self.assertEqual(
                sorted(e["generation"] for e in shuffled), [4, 5])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class SynthesisTests(unittest.TestCase):
    def test_stream_totals_and_fault_spread(self) -> None:
        from drill.synthesize import (
            TARGET_TOTAL, build_stream, new_manifest,
        )
        from drill.digest import segment_key

        manifest = new_manifest()
        stream = build_stream(manifest, segment_count=64)
        self.assertEqual(len(stream.packets), TARGET_TOTAL)
        self.assertEqual(
            sum(len(w) for w in stream.side_windows["side-a"]),
            TARGET_TOTAL)
        self.assertEqual(
            sum(len(w) for w in stream.side_windows["side-b"]),
            TARGET_TOTAL)
        self.assertEqual(len(stream.fault_partitions), 3)
        segs = {segment_key(p, 64) for p in stream.fault_partitions}
        self.assertEqual(len(segs), 3, "三个故障分区必须落在不同分段")
        # 三个故障分区编号相距很远
        nums = sorted(int(p.removeprefix("P"))
                      for p in stream.fault_partitions)
        self.assertGreater(nums[1] - nums[0], 30)
        self.assertGreater(nums[2] - nums[1], 30)


class LargeDrillTests(unittest.TestCase):
    def test_full_60000_drill_and_independent_verifier(self) -> None:
        import subprocess
        import sys
        from drill import large_drill
        from drill.verifier import verify_run

        # 持久化产物落在仓库 artifacts/（已被 .gitignore 忽略），
        # 便于事后用 tools/verify_disk.py 独立复核。
        art = ROOT / "artifacts" / "large"
        report = large_drill.run(art, fsync_every=128)
        try:
            self.assertEqual(report.verdict, "PASS", report.issues)
            self.assertEqual(report.packets_per_side, 60000)
            self.assertTrue(report.reconciliation["equal"])
            # 局部修订只触碰 3 个分段，对账逐条范围远小于全量
            self.assertEqual(
                report.local_revision["segments_recomputed"], 3)
            self.assertLess(
                report.local_revision[
                    "fault_vs_full_entries_compared_in_diff"],
                report.local_revision["entries_total"])
            # 独立验证器（同库、只读磁盘入口）复核通过
            verify = verify_run(art)
            self.assertEqual(verify["verdict"], "PASS", verify["issues"])
            for side in verify["sides"]:
                self.assertEqual(side["chain_records"], 60000)
                self.assertTrue(side["ok"])
            # 独立子进程 CLI 复核，报告持久化到 artifacts/
            out = ROOT / "artifacts" / "large_verification.json"
            proc = subprocess.run(
                [sys.executable, str(ROOT / "tools" / "verify_disk.py"),
                 "--data-dir", str(art), "--out", str(out)],
                capture_output=True, text=True, timeout=300)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(
                json.loads(out.read_text(encoding="utf-8"))["verdict"],
                "PASS")
        except Exception:
            shutil.rmtree(art, ignore_errors=True)
            raise


class SubprocessVerifierTests(unittest.TestCase):
    """独立进程 CLI 验证器：退出码 0=PASS，1=FAIL。"""

    def _invoke(self, data_dir: Path, out: Path) -> tuple[int, dict]:
        import subprocess
        import sys
        cli = ROOT / "tools" / "verify_disk.py"
        proc = subprocess.run(
            [sys.executable, str(cli), "--data-dir", str(data_dir),
             "--out", str(out)], capture_output=True, text=True, timeout=300)
        report = json.loads(out.read_text(encoding="utf-8"))
        return proc.returncode, report

    def test_cli_on_large_and_incident(self) -> None:
        from drill import incident, large_drill
        from drill.trust import make_synthetic_manifest

        # 复用 LargeDrillTests 已持久化的六万封包产物；缺失则现场构建
        large_dir = ROOT / "artifacts" / "large"
        if not (large_dir / "large_drill_report.json").exists():
            large_drill.run(large_dir, fsync_every=128)
        code, report = self._invoke(
            large_dir, ROOT / "artifacts" / "large_verification.json")
        self.assertEqual(code, 0)
        self.assertEqual(report["verdict"], "PASS")
        self.assertTrue(report["reconciliation"]["equal"])

        # 事故复现产物持久化，便于独立工具事后抓“幽灵承诺”
        inc_dir = ROOT / "artifacts" / "incident"
        inc = incident.reproduce(inc_dir, make_synthetic_manifest())
        # 修复/修复：独立验证 PASS
        code_fixed, fixed = self._invoke(
            inc_dir / "fixed-fixed",
            ROOT / "artifacts" / "incident_fixed_verification.json")
        self.assertEqual(code_fixed, 0)
        self.assertEqual(fixed["verdict"], "PASS")
        # 旧版/旧版：正确规则重放抓出幽灵承诺，必须 FAIL
        code_legacy, legacy = self._invoke(
            inc_dir / "legacy-legacy",
            ROOT / "artifacts" / "incident_legacy_verification.json")
        self.assertEqual(code_legacy, 1)
        self.assertEqual(legacy["verdict"], "FAIL")
        self.assertTrue(legacy["issues"])
        # 混合：差异段被定位，幽灵批次只在旧版一侧
        self.assertFalse(inc.mixed["heads_equal"])
        self.assertTrue(inc.mixed["only_in_legacy_side"])
        self.assertIn(inc.ghost_batch_id,
                      inc.mixed["only_in_legacy_side"])


class TamperDetectionTests(unittest.TestCase):
    def test_verifier_catches_on_disk_tamper(self) -> None:
        from drill.gateway import SideGateway
        from drill.trust import make_synthetic_manifest
        from drill.verifier import verify_run

        tmp = Path(tempfile.mkdtemp())
        try:
            manifest = make_synthetic_manifest()
            d = tmp / "run"
            d.mkdir(parents=True)
            manifest.save(d / "trust_manifest.json")
            gw = SideGateway("side-a", d / "side-a", manifest,
                             segment_count=8)
            bundle = make_bundle(manifest, "B1", "p", 0, {"v": 1})
            gw.ingest_many([bundle["cand"], *bundle["approvals"],
                            bundle["commit"]])
            gw.publish()
            gw.close()

            # 篡改磁盘上的入站日志（改载荷但不重算哈希链）
            log_path = d / "side-a" / "inbound.jsonl"
            rows = log_path.read_text(encoding="utf-8").splitlines()
            rec = json.loads(rows[0])
            rec["env"]["payload"] = {"v": "tampered"}
            rows[0] = json.dumps(rec, sort_keys=True)
            log_path.write_text("\n".join(rows) + "\n", encoding="utf-8")

            report = verify_run(d, sides=("side-a",))
            self.assertEqual(report["verdict"], "FAIL")
            self.assertTrue(
                any("哈希" in i or "断链" in i or "篡改" in i
                    for i in report["issues"]))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class OrchestratorSmokeTests(unittest.TestCase):
    def test_run_all_skip_large_passes(self) -> None:
        import run_all

        tmp = Path(tempfile.mkdtemp())
        try:
            code = run_all.main(["--base", str(tmp), "--skip-large"])
            self.assertEqual(code, 0)
            summary = json.loads(
                (tmp / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual(summary["verdict"], "PASS")
            steps = {s["step"]: s["ok"] for s in summary["steps"]}
            self.assertTrue(steps["offline-guard"])
            self.assertTrue(steps["thread-barrier-scenarios"])
            self.assertTrue(steps["incident-replay"])
            self.assertTrue(
                steps["independent-verifier-incident-fixed"])
            self.assertTrue(
                steps["independent-verifier-catches-legacy-ghost"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
