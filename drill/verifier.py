"""独立磁盘验证器：在独立进程里只凭磁盘文件还原并复核承诺集合。

验证器不 import 网关的任何运行期状态，只读取：

- ``trust_manifest.json``      信任根清单（含合成 HMAC 密钥）
- ``<side>/inbound.jsonl``     追加式哈希链入站日志
- ``<side>/published.json``    网关原子发布的摘要

复核项
======
1. 入站日志哈希链：seq 连续、prev 衔接、逐行重算哈希；
2. 用修复版 ``RuleEngine`` 从磁盘完整重放，独立还原承诺集合；
3. 按还原结果重算分段段根与头摘要，与 published.json 逐段比对；
4. 独立复核每个生效批次的批准：HMAC 绑定（批次摘要+分区+代际）、
   双根异链法定人数；
5. 两侧模式下对账头摘要与差异段；
6. 给出明确的整体结论 ``verdict: PASS/FAIL`` 与逐条问题清单。

全程以只读方式打开数据文件，验证器本身不写演练数据目录。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from . import digest as digest_mod
from .model import (
    GENESIS_PREV, canonical, sha256_hex,
)
from .rules import RuleEngine
from .trust import ApprovalPolicy, TrustManifest


@dataclass
class SideVerification:
    side: str
    ok: bool
    issues: list[str] = field(default_factory=list)
    chain_records: int = 0
    reconstructed_count: int = 0
    published_entry_count: int | None = None
    head_recomputed: str = ""
    head_published: str = ""
    generation: int = 0
    segment_count: int = 16
    decision_counts: dict = field(default_factory=dict)
    commitments: list[dict] = field(default_factory=list)
    approval_audit: list[dict] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "side": self.side, "ok": self.ok, "issues": self.issues,
            "chain_records": self.chain_records,
            "reconstructed_count": self.reconstructed_count,
            "published_entry_count": self.published_entry_count,
            "head_recomputed": self.head_recomputed,
            "head_published": self.head_published,
            "generation": self.generation,
            "segment_count": self.segment_count,
            "decision_counts": self.decision_counts,
            "commitments": self.commitments,
            "approval_audit": self.approval_audit,
        }


def _read_json(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as fh:   # 显式只读
        return json.load(fh)


def _read_jsonl_ro(path: Path) -> list[dict]:
    out: list[dict] = []
    with open(path, "r", encoding="utf-8") as fh:   # 显式只读
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def verify_hash_chain(records: list[dict]) -> list[str]:
    """逐行重算哈希链，返回问题列表（空即完好）。"""
    issues: list[str] = []
    prev = GENESIS_PREV
    expected_seq = 1
    for rec in records:
        if rec.get("seq") != expected_seq:
            issues.append(
                f"seq 不连续：第 {expected_seq} 行实际为 {rec.get('seq')}")
        if rec.get("prev") != prev:
            issues.append(
                f"seq {rec.get('seq')} prev 断链：期望 {prev[:12]}…，"
                f"实际 {str(rec.get('prev'))[:12]}…")
        recomputed = sha256_hex(
            canonical({"prev": rec.get("prev"), "env": rec.get("env")}))
        if rec.get("hash") != recomputed:
            issues.append(
                f"seq {rec.get('seq')} 记录哈希不匹配（封包可能被篡改）")
        prev = rec.get("hash", prev)
        expected_seq += 1
    return issues


def audit_approvals(engine: RuleEngine) -> list[dict]:
    """对每个生效批次独立复核双根异链批准。"""
    policy = ApprovalPolicy(engine.policy.manifest)
    audit: list[dict] = []
    for bid, st in engine.committed.items():
        decision = policy.evaluate(st.b_digest, st.partition,
                                   st.generation, st.approvals)
        audit.append({
            "batch_id": bid,
            "quorum_satisfied": decision.satisfied,
            "distinct_control_chains": list(decision.distinct_chains),
            "distinct_roots": list(decision.distinct_roots),
            "rejected_votes": decision.rejected,
        })
    return audit


def verify_side(side_dir: Path, manifest: TrustManifest,
                side_name: str) -> SideVerification:
    side_dir = Path(side_dir)
    v = SideVerification(side=side_name, ok=True)

    inbound = side_dir / "inbound.jsonl"
    published_path = side_dir / "published.json"
    if not inbound.exists():
        v.ok = False
        v.issues.append(f"缺少入站日志 {inbound}")
        return v

    # 1) 哈希链
    records = _read_jsonl_ro(inbound)
    v.chain_records = len(records)
    chain_issues = verify_hash_chain(records)
    if chain_issues:
        v.ok = False
        v.issues.extend(chain_issues)

    # 2) 独立重放还原承诺集合
    engine = RuleEngine(manifest, side=f"{side_name}-verifier")
    engine.process_records(records)
    v.commitments = engine.commitment_set()
    v.reconstructed_count = len(v.commitments)
    v.generation = engine.generation
    v.decision_counts = dict(engine.counts)

    # 3) 重算摘要并与发布物逐段比对
    segment_count = 16
    published_present = published_path.exists()
    if published_present:
        published = _read_json(published_path)
        segment_count = int(published["segment_count"])
        v.segment_count = segment_count
        v.published_entry_count = published["entry_count"]
        v.head_published = published["head_digest"]
        rebuilt = digest_mod.build_published(
            v.commitments, segment_count=segment_count,
            generation=engine.generation,
            trust_fingerprint=published["trust_fingerprint"],
            logical_clock=int(published["logical_clock"]))
        v.head_recomputed = rebuilt["head_digest"]
        if rebuilt["head_digest"] != published["head_digest"]:
            v.ok = False
            v.issues.append("头摘要与发布物不一致：发布摘要未忠实反映磁盘日志")
        if rebuilt["entry_count"] != published["entry_count"]:
            v.ok = False
            v.issues.append(
                f"承诺条目数不一致：还原 {rebuilt['entry_count']} vs "
                f"发布 {published['entry_count']}")
        pub_roots = {r["segment"]: r["root"]
                     for r in published["segment_roots"]}
        new_roots = {r["segment"]: r["root"]
                     for r in rebuilt["segment_roots"]}
        for idx, root in new_roots.items():
            if pub_roots.get(idx) != root:
                v.ok = False
                v.issues.append(f"段 {idx} 段根与发布物不一致")
    else:
        v.ok = False
        v.issues.append("缺少 published.json")

    # 4) 双根异链批准独立复核
    v.approval_audit = audit_approvals(engine)
    for item in v.approval_audit:
        if not item["quorum_satisfied"]:
            v.ok = False
            v.issues.append(
                f"生效批次 {item['batch_id']} 复核时双根异链批准不成立")

    return v


def verify_run(data_dir: Path, sides: tuple[str, ...] = ("side-a", "side-b")
               ) -> dict:
    """验证一次完整演练：每侧独立复核 + 两侧对账。"""
    data_dir = Path(data_dir)
    manifest = TrustManifest.load(data_dir / "trust_manifest.json")
    side_reports: list[SideVerification] = []
    for side in sides:
        side_dir = data_dir / side
        if side_dir.exists():
            side_reports.append(verify_side(side_dir, manifest, side))

    report: dict = {
        "verifier": "drill.verifier (read-only, independent process capable)",
        "data_dir": str(data_dir),
        "sides": [r.as_dict() for r in side_reports],
        "reconciliation": None,
        "issues": [],
        "verdict": "PASS",
    }
    for r in side_reports:
        report["issues"].extend(f"[{r.side}] {i}" for i in r.issues)

    if len(side_reports) == 2:
        ra, rb = side_reports
        if ra.head_recomputed and rb.head_recomputed:
            seg_count = max(ra.segment_count, rb.segment_count)
            pub_a = digest_mod.build_published(
                ra.commitments, segment_count=seg_count,
                generation=ra.generation,
                trust_fingerprint="recompute", logical_clock=0)
            pub_b = digest_mod.build_published(
                rb.commitments, segment_count=seg_count,
                generation=rb.generation,
                trust_fingerprint="recompute", logical_clock=0)
            rec = digest_mod.reconcile(
                pub_a, pub_b, ra.commitments, rb.commitments,
                segment_count=seg_count)
            report["reconciliation"] = {
                "equal": rec.equal,
                "differing_segments": rec.differing_segments,
                "segments_compared": rec.segments_compared,
                "entries_compared_in_diff": rec.entries_compared_in_diff,
                "entries_total": rec.entries_total,
                "detail": rec.detail,
            }
            if not rec.equal:
                report["issues"].append(
                    "两侧承诺集合不一致：差异段 "
                    f"{rec.differing_segments}")

    if report["issues"]:
        report["verdict"] = "FAIL"
    return report
