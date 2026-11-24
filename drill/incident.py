"""事故复现：换班断链后旧代提交重投，两侧发布摘要双双“声称已生效”。

叙事时间线
==========
1. 链路代 0：批次 B-OK 完整走完候选/双根批准/提交/回执；另一批次
   B-INFLIGHT 已完成候选与双根批准，提交封包尚在链路上。
2. 换班断链：EPOCH 把链路代推进到 1；旧代提交仍滞留在文件 spool 中，
   偏移未确认。
3. 重连重投：旧代（gen=0）COMMIT 被重新投递给两侧网关。

对照三种引擎组合
================
- 修复版/修复版：代际围栏拒绝旧代重投，两侧承诺集都不含幽灵批次，
  头摘要相等且正确。
- 旧版/旧版（``LegacyRuleEngine``，无代际围栏）：两侧都接受旧代提交，
  头摘要竟然相等——“两侧一致”却同时是错的，独立验证工具用正确规则
  重放才能抓出幽灵承诺。
- 修复版/旧版：对账直接定位差异段，幽灵批次仅出现在旧版一侧。
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from . import digest as digest_mod
from .gateway import SideGateway
from .model import T_EPOCH, T_RECEIPT, envelope
from .rules import LegacyRuleEngine, RuleEngine
from .scenarios import make_bundle
from .trust import TrustManifest


@dataclass
class IncidentResult:
    fixed_fixed: dict
    legacy_legacy: dict
    mixed: dict
    ghost_batch_id: str

    def as_dict(self) -> dict:
        return {
            "ghost_batch_id": self.ghost_batch_id,
            "fixed_fixed": self.fixed_fixed,
            "legacy_legacy": self.legacy_legacy,
            "mixed": self.mixed,
        }


def _build_traffic(manifest: TrustManifest) -> list[dict]:
    """构造事故封包序列（不含投递顺序，顺序由编排器控制）。"""
    ok = make_bundle(manifest, "B-OK", "part-normal", 0, {"v": 1})
    inflight = make_bundle(manifest, "B-INFLIGHT", "part-flap", 0,
                           {"v": 2})
    traffic: list[dict] = []
    # 代 0：B-OK 全流程；B-INFLIGHT 只到批准，COMMIT 滞留链路
    traffic += [ok["cand"], *ok["approvals"], ok["commit"]]
    traffic.append(envelope(T_RECEIPT, receipt_id="R-OK",
                            batch_id="B-OK", generation=0))
    traffic += [inflight["cand"], *inflight["approvals"]]
    # 换班
    traffic.append(envelope(T_EPOCH, generation=1, reason="shift-change"))
    # 重连后重投的旧代提交（事故封包）
    traffic.append(inflight["commit"])
    # 以及一条旧代回执重投
    traffic.append(envelope(T_RECEIPT, receipt_id="R-OLD",
                            batch_id="B-INFLIGHT", generation=0))
    return traffic


def _drive(side_dir: Path, manifest: TrustManifest, side: str,
           traffic: list[dict], engine_factory) -> SideGateway:
    gw = SideGateway(side, side_dir, manifest, segment_count=16,
                     engine_factory=engine_factory)
    gw.ingest_many(traffic)
    gw.publish()
    return gw


def reproduce(base: Path, manifest: TrustManifest) -> IncidentResult:
    base = Path(base)
    shutil.rmtree(base, ignore_errors=True)
    base.mkdir(parents=True, exist_ok=True)
    # 独立验证器只认磁盘上的信任清单，因此每个引擎组合目录都落一份
    traffic = _build_traffic(manifest)
    ghost = "B-INFLIGHT"

    # ---- 修复版双侧 ------------------------------------------------
    d = base / "fixed-fixed"
    d.mkdir(parents=True, exist_ok=True)
    manifest.save(d / "trust_manifest.json")
    gwa = _drive(d / "side-a", manifest, "A-fixed", traffic, RuleEngine)
    gwb = _drive(d / "side-b", manifest, "B-fixed", traffic, RuleEngine)
    ca, cb = gwa.engine.commitment_set(), gwb.engine.commitment_set()
    pub_a, pub_b = digest_mod.load_published(
        gwa.dir / "published.json"), digest_mod.load_published(
        gwb.dir / "published.json")
    rec = digest_mod.reconcile(pub_a, pub_b, ca, cb, segment_count=16)
    fixed_fixed = {
        "heads_equal": rec.equal,
        "ghost_present_a": ghost in gwa.engine.committed,
        "ghost_present_b": ghost in gwb.engine.committed,
        "old_generation_rejected_a":
            gwa.engine.counts.get("REJECTED_OLD_GENERATION", 0),
        "old_generation_rejected_b":
            gwb.engine.counts.get("REJECTED_OLD_GENERATION", 0),
        "committed_a": gwa.engine.commitment_ids(),
        "committed_b": gwb.engine.commitment_ids(),
    }
    gwa.close(); gwb.close()

    # ---- 旧版双侧（无代际围栏）------------------------------------
    d = base / "legacy-legacy"
    d.mkdir(parents=True, exist_ok=True)
    manifest.save(d / "trust_manifest.json")
    gwa = _drive(d / "side-a", manifest, "A-legacy", traffic,
                 LegacyRuleEngine)
    gwb = _drive(d / "side-b", manifest, "B-legacy", traffic,
                 LegacyRuleEngine)
    ca, cb = gwa.engine.commitment_set(), gwb.engine.commitment_set()
    pub_a = digest_mod.load_published(gwa.dir / "published.json")
    pub_b = digest_mod.load_published(gwb.dir / "published.json")
    rec_ll = digest_mod.reconcile(pub_a, pub_b, ca, cb, segment_count=16)
    legacy_legacy = {
        "heads_equal_but_both_wrong": rec_ll.equal,
        "ghost_present_a": ghost in gwa.engine.committed,
        "ghost_present_b": ghost in gwb.engine.committed,
        "committed_a": gwa.engine.commitment_ids(),
        "committed_b": gwb.engine.commitment_ids(),
        "note": "两侧头摘要相等却同时包含旧代幽灵承诺，等价性不能代替正确性",
    }
    gwa.close(); gwb.close()

    # ---- 混合：A 修复，B 旧版 --------------------------------------
    d = base / "mixed"
    d.mkdir(parents=True, exist_ok=True)
    manifest.save(d / "trust_manifest.json")
    gwa = _drive(d / "side-a", manifest, "A-fixed", traffic, RuleEngine)
    gwb = _drive(d / "side-b", manifest, "B-legacy", traffic,
                 LegacyRuleEngine)
    ca, cb = gwa.engine.commitment_set(), gwb.engine.commitment_set()
    pub_a = digest_mod.load_published(gwa.dir / "published.json")
    pub_b = digest_mod.load_published(gwb.dir / "published.json")
    rec_mix = digest_mod.reconcile(pub_a, pub_b, ca, cb, segment_count=16)
    mixed = {
        "heads_equal": rec_mix.equal,
        "differing_segments": rec_mix.differing_segments,
        "entries_compared_in_diff": rec_mix.entries_compared_in_diff,
        "segments_compared": rec_mix.segments_compared,
        "only_in_legacy_side": [
            x for dseg in rec_mix.detail for x in dseg["only_in_b"]],
        "detail": rec_mix.detail,
    }
    gwa.close(); gwb.close()

    return IncidentResult(fixed_fixed, legacy_legacy, mixed, ghost)


def cleanup(base: Path) -> None:
    shutil.rmtree(base, ignore_errors=True)
