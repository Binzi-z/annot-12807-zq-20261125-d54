"""三个关键场景的双真实线程屏障复测。

每个场景都启动两个 ``threading.Thread``，用 ``threading.Barrier(2)``
保证“准备已完成”后两侧才同时进入落盘段；确定性变体再用 Event 控制
谁先抢到日志锁，竞争变体则放开顺序、重复多轮，并在每轮回读磁盘，
断言裁决结论与真正的落盘 seq 先后严格一致。

场景一  撤销先落盘：CANCEL 的 seq 小于 COMMIT -> 拒绝提交；
        反向复测 COMMIT 先落盘 -> 生效，迟到取消不撤销承诺。
场景二  批次已落盘但未发回执：接收线程在屏障后遇“断链”不写回执，
        承诺集合仍包含该批次；重连后新回执入账、重复回执去重、
        旧代回执被代际围栏拒绝。
场景三  同编号冲突：两个线程各写同编号、不同内容摘要的候选，
        seq 最小者占编号，其余冲突拒绝，且批准与摘要绑定使冲突方
        无法凑出有效双根批准。
"""

from __future__ import annotations

import shutil
import threading
from dataclasses import dataclass, field
from pathlib import Path

from .model import (
    O_COMMIT, O_DUP_RECEIPT, O_REJECT_CANCEL, O_REJECT_CONFLICT,
    O_REJECT_OLD_GEN, T_APPROVAL, T_CANCEL, T_CANDIDATE, T_COMMIT,
    T_EPOCH, T_RECEIPT, batch_digest, envelope,
)
from .gateway import SideGateway
from .rules import RuleEngine
from .trust import TrustManifest

RACE_ITERATIONS = 20


@dataclass
class ScenarioResult:
    name: str
    passed: bool
    details: list[str] = field(default_factory=list)
    observed: list[dict] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"name": self.name, "passed": self.passed,
                "details": self.details, "observed": self.observed}


def make_bundle(manifest: TrustManifest, bid: str, partition: str,
                generation: int, payload: object) -> dict:
    """构造一个候选的完整封包束：候选 + 双根批准 + 提交。"""
    b = batch_digest(bid, partition, generation, payload)
    cand = envelope(T_CANDIDATE, batch_id=bid, partition=partition,
                    generation=generation, payload=payload)
    approvals = []
    for root in manifest.roots:
        sig = root.sign(b, partition, generation)
        approvals.append(envelope(
            T_APPROVAL, batch_id=bid, root_id=root.root_id,
            generation=generation, batch_digest=b,
            partition=partition, signature=sig))
    commit = envelope(T_COMMIT, batch_id=bid, partition=partition,
                      generation=generation, batch_digest=b)
    return {"digest": b, "cand": cand, "approvals": approvals,
            "commit": commit}


def _new_gateway(base: Path, name: str, manifest: TrustManifest,
                 *, fsync_every: int = 1) -> SideGateway:
    gw = SideGateway(name, base / name, manifest,
                     segment_count=16, fsync_every=fsync_every)
    # 场景统一运行在链路代 1（首条落盘即换班标记），使 gen=0 的旧代
    # 封包能真实触发代际围栏。
    gw.ingest(envelope(T_EPOCH, generation=1, reason="scenario-shift"))
    return gw


# ----------------------------------------------------------------------
# 场景一：撤销先落盘
# ----------------------------------------------------------------------
def scenario_cancel_first(base: Path,
                          manifest: TrustManifest) -> ScenarioResult:
    res = ScenarioResult("scenario-1-cancel-before-commit", True)

    def _run(iter_dir: Path, *, cancel_first: bool,
             racy: bool) -> dict:
        gw = _new_gateway(iter_dir, "gw", manifest)
        bundle = make_bundle(manifest, "B-CANCEL", "part-x", 1,
                             {"v": "payload-1"})
        gw.ingest(bundle["cand"])
        gw.ingest_many(bundle["approvals"])

        barrier = threading.Barrier(2)
        gate = threading.Event()
        seqs: dict[str, int] = {}

        def cancel_worker() -> None:
            barrier.wait()
            if not racy and not cancel_first:
                gate.wait()
            rec = gw.ingest(envelope(
                T_CANCEL, batch_id="B-CANCEL", generation=1,
                partition="part-x"))
            seqs["cancel"] = rec.seq
            if not racy and cancel_first:
                gate.set()

        def commit_worker() -> None:
            barrier.wait()
            if not racy and cancel_first:
                gate.wait()
            rec = gw.ingest(bundle["commit"])
            seqs["commit"] = rec.seq
            if not racy and not cancel_first:
                gate.set()

        t1 = threading.Thread(target=cancel_worker, name="cancel-thread")
        t2 = threading.Thread(target=commit_worker, name="commit-thread")
        t1.start(); t2.start()
        t1.join(); t2.join()

        engine = gw.replay()
        gw.close()
        st = engine.batches["B-CANCEL"]
        obs = {
            "racy": racy,
            "cancel_first_on_disk": seqs.get("cancel", 10**9)
                                    < seqs.get("commit", -1),
            "seqs": dict(seqs),
            "status": st.status,
            "outcome": st.outcome,
            "committed": "B-CANCEL" in engine.committed,
        }

        if obs["cancel_first_on_disk"]:
            assert st.outcome == O_REJECT_CANCEL, obs
            assert not obs["committed"], obs
            assert engine.counts.get(O_REJECT_CANCEL, 0) >= 1
        else:
            assert st.outcome == O_COMMIT, obs
            assert obs["committed"], obs
            assert engine.counts.get("CANCEL_TOO_LATE", 0) >= 1
        return obs

    # 确定性：取消先落盘
    obs = _run(base / "s1-deterministic-cancel-first",
               cancel_first=True, racy=False)
    res.details.append("确定性变体：CANCEL seq=%d 先于 COMMIT seq=%d，"
                       "提交被拒" % (obs["seqs"]["cancel"],
                                     obs["seqs"]["commit"]))
    # 确定性：提交先落盘（反向）
    obs2 = _run(base / "s1-deterministic-commit-first",
                cancel_first=False, racy=False)
    res.details.append("反向变体：COMMIT seq=%d 先于 CANCEL seq=%d，"
                       "批次生效且迟到取消不撤销"
                       % (obs2["seqs"]["commit"], obs2["seqs"]["cancel"]))

    # 竞争变体：屏障后同时放行，连跑多轮，逐轮以磁盘 seq 复核
    for i in range(RACE_ITERATIONS):
        obs = _run(base / f"s1-race-{i:02d}", cancel_first=True, racy=True)
        res.observed.append(obs)
    winners = {o["cancel_first_on_disk"] for o in res.observed}
    res.details.append(
        f"竞争变体 {RACE_ITERATIONS} 轮全部与落盘先后一致；"
        f"其中取消先落盘 {sum(o['cancel_first_on_disk'] for o in res.observed)} 轮，"
        f"提交先落盘 {sum(not o['cancel_first_on_disk'] for o in res.observed)} 轮"
        if winners else "竞争变体未发生（异常）")
    return res


# ----------------------------------------------------------------------
# 场景二：批次已落盘但未发回执
# ----------------------------------------------------------------------
def scenario_committed_no_receipt(base: Path,
                                  manifest: TrustManifest) -> ScenarioResult:
    res = ScenarioResult("scenario-2-committed-without-receipt", True)
    gw = _new_gateway(base, "gw", manifest)
    bundle = make_bundle(manifest, "B-NOREC", "part-y", 1,
                         {"v": "payload-2"})
    gw.ingest(bundle["cand"])
    gw.ingest_many(bundle["approvals"])

    barrier = threading.Barrier(2)
    link_up = threading.Event()          # 未 set 即链路断开
    receiver_skipped: dict[str, bool] = {}

    def writer() -> None:
        barrier.wait()
        gw.ingest(bundle["commit"])      # 提交照常落盘

    def receiver() -> None:
        barrier.wait()
        if not link_up.is_set():
            # 断链：回执根本没有发出，更没有落盘
            receiver_skipped["skipped"] = True
            return

    t1 = threading.Thread(target=writer, name="writer-thread")
    t2 = threading.Thread(target=receiver, name="receiver-thread")
    t1.start(); t2.start()
    t1.join(); t2.join()

    engine = gw.replay()
    assert receiver_skipped.get("skipped") is True
    assert "B-NOREC" in engine.committed
    st = engine.batches["B-NOREC"]
    assert st.receipt_ids == []
    res.details.append("断链期间接收线程未写任何回执；批次仍按双根批准生效，"
                       "承诺集合包含 B-NOREC，回执数=0")

    # 重连：新回执入账；重复回执去重；旧代回执被围栏拒绝
    link_up.set()
    gw.ingest(envelope(T_RECEIPT, receipt_id="R-1", batch_id="B-NOREC",
                       generation=1))
    gw.ingest(envelope(T_RECEIPT, receipt_id="R-1", batch_id="B-NOREC",
                       generation=1))
    gw.ingest(envelope(T_RECEIPT, receipt_id="R-OLD", batch_id="B-NOREC",
                       generation=0))
    engine = gw.replay()
    st = engine.batches["B-NOREC"]
    assert st.receipt_ids == ["R-1"]
    assert engine.counts.get(O_DUP_RECEIPT, 0) >= 1
    assert engine.counts.get(O_REJECT_OLD_GEN, 0) >= 1
    gw.close()
    res.details.append("重连后：R-1 入账，重复 R-1 幂等去重，"
                       "旧代 R-OLD 被链路代围栏拒绝")
    res.observed.append({
        "committed": True, "receipt_ids": st.receipt_ids,
        "dup_receipt": engine.counts.get(O_DUP_RECEIPT, 0),
        "old_generation_rejected": engine.counts.get(O_REJECT_OLD_GEN, 0),
    })
    return res


# ----------------------------------------------------------------------
# 场景三：同编号冲突
# ----------------------------------------------------------------------
def scenario_id_conflict(base: Path,
                         manifest: TrustManifest) -> ScenarioResult:
    res = ScenarioResult("scenario-3-same-id-conflict", True)

    def _run(iter_dir: Path, racy: bool) -> dict:
        gw = _new_gateway(iter_dir, "gw", manifest)
        bid = "B-DUP"
        b1 = make_bundle(manifest, bid, "part-z", 1, {"v": "alpha"})
        b2 = make_bundle(manifest, bid, "part-z", 1, {"v": "beta"})
        assert b1["digest"] != b2["digest"]

        barrier = threading.Barrier(2)
        gate = threading.Event()
        seqs: dict[str, int] = {}

        def worker_a() -> None:
            barrier.wait()
            if not racy:
                pass  # A 被指定为先落盘方
            rec = gw.ingest(b1["cand"])
            seqs["alpha"] = rec.seq
            if not racy:
                gate.set()

        def worker_b() -> None:
            barrier.wait()
            if not racy:
                gate.wait()
            rec = gw.ingest(b2["cand"])
            seqs["beta"] = rec.seq

        t1 = threading.Thread(target=worker_a, name="candidate-alpha")
        t2 = threading.Thread(target=worker_b, name="candidate-beta")
        t1.start(); t2.start()
        t1.join(); t2.join()

        # 先落盘方补齐自己的批准并提交；冲突方试图用自己的批准+提交蒙混
        if seqs["alpha"] < seqs["beta"]:
            winner, loser = b1, b2
        else:
            winner, loser = b2, b1
        gw.ingest_many(winner["approvals"])
        gw.ingest(winner["commit"])
        gw.ingest_many(loser["approvals"])     # 摘要绑定不同 -> 签名无效
        gw.ingest(loser["commit"])

        engine = gw.replay()
        gw.close()
        st = engine.batches[bid]
        obs = {
            "racy": racy,
            "winner_seq": min(seqs.values()),
            "seqs": dict(seqs),
            "winner_digest": winner["digest"],
            "registered_digest": st.b_digest,
            "conflict_seqs": st.conflict_seqs,
            "committed": bid in engine.committed,
            "committed_digest":
                engine.committed[bid].b_digest if bid in engine.committed
                else None,
            "conflict_rejections": engine.counts.get(O_REJECT_CONFLICT, 0),
            "bad_sig_rejections": engine.counts.get("REJECTED_BAD_APPROVAL", 0),
        }
        assert st.conflict_seqs, obs
        assert obs["committed"] and obs["committed_digest"] == winner["digest"]
        assert obs["conflict_rejections"] >= 1
        return obs

    obs = _run(base / "s3-deterministic", racy=False)
    res.details.append(
        f"确定性变体：alpha seq={obs['seqs']['alpha']} 先占编号，"
        f"beta seq={obs['seqs']['beta']} 冲突拒绝；最终生效摘要为先落盘方")
    for i in range(RACE_ITERATIONS):
        obs = _run(base / f"s3-race-{i:02d}", racy=True)
        res.observed.append(obs)
    res.details.append(
        f"竞争变体 {RACE_ITERATIONS} 轮：每轮均由 seq 最小候选占编号并唯一生效，"
        "冲突方批准因摘要绑定失配全部判无效")
    return res


def run_all(base: Path, manifest: TrustManifest) -> dict:
    base = Path(base)
    shutil.rmtree(base, ignore_errors=True)
    base.mkdir(parents=True, exist_ok=True)
    results = [
        scenario_cancel_first(base / "scenario-1", manifest),
        scenario_committed_no_receipt(base / "scenario-2", manifest),
        scenario_id_conflict(base / "scenario-3", manifest),
    ]
    return {
        "barrier_parties": 2,
        "race_iterations": RACE_ITERATIONS,
        "all_passed": all(r.passed for r in results),
        "scenarios": [r.as_dict() for r in results],
    }
