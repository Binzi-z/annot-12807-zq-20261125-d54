"""六万封包大规模离线演练编排。

流程
====
1. 确定性生成 60000 条合成封包，选出三个相隔很远的故障分区；
2. 两侧网关以不同乱序种子各自完整落盘（窗口间按代际顺序），
   发布承诺摘要；fsync 按批提交以兼顾 Windows 吞吐，顺序语义不变；
3. 独立验证器在两侧磁盘上重放复核，两侧头摘要必须相等；
4. 针对三个故障分区做局部修订演练，报告“实际比对范围”：
   重算段数、重哈希条目数、对账时逐条比对条目数 vs 全量条目数；
5. 全量结果（各类裁决计数、承诺条目、耗时）写入报告。
"""

from __future__ import annotations

import json
import shutil
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import digest as digest_mod
from .gateway import SideGateway
from .model import (
    O_COMMIT, O_DUP_CANDIDATE, O_DUP_RECEIPT, O_REJECT_BAD_SIG,
    O_REJECT_CANCEL, O_REJECT_CONFLICT, O_REJECT_OLD_GEN,
)
from .store import atomic_write_text
from .synthesize import (
    N_BAD_BINDING_APR, N_BATCHES, N_CANCEL_FIRST, N_CONFLICT_PAIRS,
    N_DUP_CANDIDATE, N_DUP_RECEIPTS, N_OLD_COMMITS, N_OLD_RECEIPTS,
    N_UNKNOWN_ROOT_APR, TARGET_TOTAL, build_stream, new_manifest,
)
from .trust import manifest_fingerprint

SEGMENT_COUNT = 64


@dataclass
class LargeDrillReport:
    target_packets: int
    packets_per_side: int
    segment_count: int
    fault_partitions: list[str]
    fault_segments: list[int]
    side_a: dict = field(default_factory=dict)
    side_b: dict = field(default_factory=dict)
    reconciliation: dict = field(default_factory=dict)
    local_revision: dict = field(default_factory=dict)
    timing: dict = field(default_factory=dict)
    verdict: str = "PASS"
    issues: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return asdict(self)


def _ingest_side(side: str, side_dir: Path, manifest, windows,
                 fsync_every: int) -> SideGateway:
    gw = SideGateway(side, side_dir, manifest,
                     segment_count=SEGMENT_COUNT,
                     fsync_every=fsync_every)
    n = 0
    for win in windows:
        for env in win:
            gw.ingest(env)
            n += 1
    gw.publish()
    gw._packets = n  # type: ignore[attr-defined]
    return gw


def _segment_of(partition: str) -> int:
    return digest_mod.segment_key(partition, SEGMENT_COUNT)


def run(base: Path, *, fsync_every: int = 64) -> LargeDrillReport:
    base = Path(base)
    # 入站日志是追加式哈希链，重跑前必须清空旧产物，否则记录会翻倍
    shutil.rmtree(base, ignore_errors=True)
    base.mkdir(parents=True, exist_ok=True)
    timing: dict[str, float] = {}

    t0 = time.perf_counter()
    manifest = new_manifest()
    manifest.save(base / "trust_manifest.json")
    stream = build_stream(manifest, segment_count=SEGMENT_COUNT)
    timing["synthesize_sec"] = round(time.perf_counter() - t0, 3)

    fault_segments = sorted({_segment_of(p) for p in stream.fault_partitions})
    report = LargeDrillReport(
        target_packets=TARGET_TOTAL,
        packets_per_side=sum(len(w) for w in stream.side_windows["side-a"]),
        segment_count=SEGMENT_COUNT,
        fault_partitions=stream.fault_partitions,
        fault_segments=fault_segments,
    )

    # ---- 两侧落盘 + 发布 -------------------------------------------
    t0 = time.perf_counter()
    gwa = _ingest_side("side-a", base / "side-a", manifest,
                       stream.side_windows["side-a"], fsync_every)
    gwb = _ingest_side("side-b", base / "side-b", manifest,
                       stream.side_windows["side-b"], fsync_every)
    timing["ingest_publish_sec"] = round(time.perf_counter() - t0, 3)

    for gw, key in ((gwa, "side_a"), (gwb, "side_b")):
        eng = gw.engine
        setattr(report, key, {
            "packets": getattr(gw, "_packets"),
            "generation": eng.generation,
            "committed": len(eng.committed),
            "counts": dict(eng.counts),
            "head_digest": digest_mod.load_published(
                gw.dir / "published.json")["head_digest"],
        })

    # ---- 两侧对账（独立重算，不共享内存）--------------------------
    t0 = time.perf_counter()
    ca, cb = gwa.engine.commitment_set(), gwb.engine.commitment_set()
    pub_a = digest_mod.load_published(gwa.dir / "published.json")
    pub_b = digest_mod.load_published(gwb.dir / "published.json")
    rec = digest_mod.reconcile(pub_a, pub_b, ca, cb,
                               segment_count=SEGMENT_COUNT)
    timing["reconcile_sec"] = round(time.perf_counter() - t0, 3)
    report.reconciliation = {
        "equal": rec.equal,
        "head_a": rec.head_a,
        "head_b": rec.head_b,
        "differing_segments": rec.differing_segments,
        "segments_compared": rec.segments_compared,
        "entries_compared_in_diff": rec.entries_compared_in_diff,
        "entries_total": rec.entries_total,
        "detail": rec.detail,
    }

    # ---- 局部修订演练 ----------------------------------------------
    t0 = time.perf_counter()
    full = list(ca)
    touched = set(stream.fault_partitions)
    touched_segments = sorted({_segment_of(p) for p in touched})

    # 步骤 1：模拟三个故障分区的条目被摘除（故障视图）
    fault_view = [e for e in full if e["partition"] not in touched]
    fault_pub = digest_mod.build_published(
        fault_view, segment_count=SEGMENT_COUNT, generation=4,
        trust_fingerprint=manifest_fingerprint(manifest), logical_clock=1)

    # 步骤 2：按真正磁盘状态做局部修复——只重算受影响分段
    def restore(entries: list[dict]) -> list[dict]:
        disk_entries = [e for e in full if e["partition"] in touched]
        return entries + disk_entries

    rev = digest_mod.revise_commitments(
        fault_view, segment_count=SEGMENT_COUNT,
        touched_partitions=touched, transform=restore)
    timing["local_revision_sec"] = round(time.perf_counter() - t0, 3)

    # 步骤 3：修复后与全量重建逐字节核对
    full_pub = digest_mod.build_published(
        full, segment_count=SEGMENT_COUNT, generation=4,
        trust_fingerprint=manifest_fingerprint(manifest), logical_clock=2)

    # 步骤 4：对账“实际比对范围”——只在差异段逐条比对
    rec_fault = digest_mod.reconcile(
        full_pub, fault_pub, full, fault_view,
        segment_count=SEGMENT_COUNT)
    entries_in_touched = sum(
        1 for e in full if _segment_of(e["partition"]) in touched_segments)

    report.local_revision = {
        "touched_partitions": stream.fault_partitions,
        "touched_segments": touched_segments,
        "segments_total": SEGMENT_COUNT,
        "segments_recomputed": rev.segments_recomputed,
        "segments_untouched": rev.segments_untouched,
        "entries_rehashed": rev.entries_rehashed,
        "entries_in_touched_segments": entries_in_touched,
        "entries_total": rev.entries_total,
        "rehash_ratio": round(rev.entries_rehashed / max(1, rev.entries_total),
                              6),
        "head_changed_by_fault": rev.changed,
        "head_after_revision_matches_full":
            rev.head_after == full_pub["head_digest"],
        "fault_vs_full_entries_compared_in_diff":
            rec_fault.entries_compared_in_diff,
        "fault_vs_full_differing_segments": rec_fault.differing_segments,
        "full_rebuild_entries": len(full),
    }

    # ---- 关键断言 --------------------------------------------------
    if report.packets_per_side != TARGET_TOTAL:
        report.issues.append(
            f"每侧封包数 {report.packets_per_side} != {TARGET_TOTAL}")
    if not rec.equal:
        report.issues.append("两侧承诺集合不一致")
    if not report.local_revision["head_after_revision_matches_full"]:
        report.issues.append("局部修复后头摘要与全量重建不一致")
    if rev.segments_recomputed != len(touched_segments):
        report.issues.append("局部修订重算段数与故障分段数不符")
    if rec_fault.entries_compared_in_diff >= len(full):
        report.issues.append("局部对账退化为全量逐条比对，未体现局部性")

    # 裁决计数精确核对（各类合成注入量与引擎结论一一对应）
    ca_counts = gwa.engine.counts
    cb_counts = gwb.engine.counts
    exact_expectations = {
        # 只有“取消先落盘”的批次不生效；同编号冲突中先落盘的原候选
        # 仍正常提交，被拒的是 200 个篡改候选（计入 ID_CONFLICT）。
        O_COMMIT: N_BATCHES - N_CANCEL_FIRST,
        O_REJECT_CANCEL: N_CANCEL_FIRST,
        O_REJECT_CONFLICT: N_CONFLICT_PAIRS,
        O_REJECT_BAD_SIG: N_UNKNOWN_ROOT_APR + N_BAD_BINDING_APR,
        O_REJECT_OLD_GEN: N_OLD_COMMITS + N_OLD_RECEIPTS,
        O_DUP_CANDIDATE: N_DUP_CANDIDATE,
        O_DUP_RECEIPT: N_DUP_RECEIPTS,
    }
    for code, expected in exact_expectations.items():
        if ca_counts.get(code, 0) != expected:
            report.issues.append(
                f"侧 A 裁决 {code} 实际 {ca_counts.get(code, 0)} "
                f"!= 预期 {expected}")
        if cb_counts.get(code, 0) != expected:
            report.issues.append(
                f"侧 B 裁决 {code} 实际 {cb_counts.get(code, 0)} "
                f"!= 预期 {expected}")

    gwa.close(); gwb.close()
    if report.issues:
        report.verdict = "FAIL"
    report.timing = timing

    atomic_write_text(
        base / "large_drill_report.json",
        json.dumps(report.as_dict(), ensure_ascii=False, indent=2,
                   sort_keys=True))
    return report
