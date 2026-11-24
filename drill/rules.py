"""按真正落盘顺序裁决的回放规则引擎。

引擎输入是 ``DurableLog`` 的记录序列（seq 即落盘先后），输出包括：

- 承诺集合（实际生效的批次，按首次提交顺序）；
- 每个批次/封包的裁决结论与依据 seq；
- 各类拒绝原因计数；
- 当前链路代与代际围栏事件。

关键裁决规则
============
1. **链路代围栏**：换班 EPOCH 单调推进 generation；旧代封包（含断链后
   重投的旧代 COMMIT/RECEIPT）一律拒绝，绝不进入承诺集合。
2. **取消先落盘者胜**：若 CANCEL 的 seq 早于 COMMIT，则提交被拒绝；
   反之 COMMIT 已落盘后到达的取消只作过期记录，不撤销承诺。
3. **同编号冲突**：同一 batch_id 出现内容摘要不同的候选时，seq 最小者
   占编号，其余标记冲突拒绝；同摘要重复候选按重投递去重。
4. **双根异链批准**：COMMIT 时复核该批次全部有效批准，必须覆盖两条
   独立控制链；同链/同根重复只算一票。
5. **回执幂等**：以 receipt_id 去重，且只接受已生效批次、当前代的回执。
"""

from __future__ import annotations

from collections import OrderedDict, Counter
from dataclasses import dataclass, field
from typing import Iterable

from .model import (
    T_APPROVAL, T_CANCEL, T_CANDIDATE, T_COMMIT, T_EPOCH, T_RECEIPT,
    O_COMMIT, O_DUP_CANDIDATE, O_DUP_COMMIT, O_DUP_EPOCH, O_DUP_RECEIPT,
    O_GEN_ADVANCE, O_REJECT_BAD_SIG, O_REJECT_CANCEL, O_REJECT_CONFLICT,
    O_REJECT_FUTURE_GEN, O_REJECT_OLD_GEN, O_REJECT_QUORUM, batch_digest,
)
from .trust import ApprovalPolicy, TrustManifest


@dataclass
class BatchState:
    batch_id: str
    first_seq: int
    generation: int
    partition: str
    b_digest: str
    payload: object
    approvals: list[dict] = field(default_factory=list)
    status: str = "open"                 # open / committed / rejected / canceled
    outcome: str | None = None
    outcome_seq: int | None = None
    conflict_seqs: list[int] = field(default_factory=list)
    cancel_seq: int | None = None
    receipt_ids: list[str] = field(default_factory=list)


@dataclass
class Decision:
    seq: int
    env_type: str
    code: str
    detail: str
    batch_id: str | None = None


class RuleEngine:
    """发送侧/接收侧共用的同一套裁决逻辑（对称引擎）。"""

    def __init__(self, manifest: TrustManifest, *, side: str,
                 enforce_generation: bool = True) -> None:
        self.side = side
        self.policy = ApprovalPolicy(manifest)
        self.enforce_generation = enforce_generation
        self.generation = 0
        self.batches: dict[str, BatchState] = {}
        self.committed: OrderedDict[str, BatchState] = OrderedDict()
        self.decisions: list[Decision] = []
        self.counts: Counter[str] = Counter()
        self._receipt_seen: set[str] = set()

    # ------------------------------------------------------------------
    def _decide(self, seq: int, env_type: str, code: str, detail: str,
                batch_id: str | None = None) -> None:
        self.decisions.append(Decision(seq, env_type, code, detail, batch_id))
        self.counts[code] += 1

    # ------------------------------------------------------------------
    def process_records(self, records: Iterable[dict]) -> None:
        for rec in records:
            self.process(rec["seq"], rec["env"])

    def process(self, seq: int, env: dict) -> None:
        kind = env["type"]
        if kind == T_EPOCH:
            self._on_epoch(seq, env)
        elif kind == T_CANDIDATE:
            self._on_candidate(seq, env)
        elif kind == T_APPROVAL:
            self._on_approval(seq, env)
        elif kind == T_CANCEL:
            self._on_cancel(seq, env)
        elif kind == T_COMMIT:
            self._on_commit(seq, env)
        elif kind == T_RECEIPT:
            self._on_receipt(seq, env)
        else:
            self._decide(seq, kind, "REJECTED_UNKNOWN_TYPE",
                         f"未知封包类型 {kind}")

    # ------------------------------------------------------------------
    def _on_epoch(self, seq: int, env: dict) -> None:
        new_gen = int(env["generation"])
        if new_gen > self.generation:
            old = self.generation
            self.generation = new_gen
            self._decide(seq, T_EPOCH, O_GEN_ADVANCE,
                         f"{self.side} 链路代 {old} -> {new_gen}")
        elif new_gen == self.generation:
            self._decide(seq, T_EPOCH, O_DUP_EPOCH,
                         "重复代标记，忽略")
        else:
            # 旧代 EPOCH（断链恢复时迟到的旧标记）拒绝
            self._decide(seq, T_EPOCH, O_REJECT_OLD_GEN,
                         f"旧代标记 gen={new_gen} < 当前 {self.generation}")

    def _stale(self, env_gen: int) -> bool:
        return self.enforce_generation and env_gen < self.generation

    def _on_candidate(self, seq: int, env: dict) -> None:
        bid = env["batch_id"]
        gen = int(env["generation"])
        if self._stale(gen):
            self._decide(seq, T_CANDIDATE, O_REJECT_OLD_GEN,
                         f"旧代候选 {bid} gen={gen} < {self.generation}", bid)
            return
        if gen > self.generation:
            self._decide(seq, T_CANDIDATE, O_REJECT_FUTURE_GEN,
                         f"未来代候选 {bid} gen={gen} > {self.generation}", bid)
            return
        b_digest = batch_digest(bid, env["partition"], gen, env["payload"])
        existing = self.batches.get(bid)
        if existing is None:
            self.batches[bid] = BatchState(
                batch_id=bid, first_seq=seq, generation=gen,
                partition=env["partition"], b_digest=b_digest,
                payload=env["payload"])
            self._decide(seq, T_CANDIDATE, "CANDIDATE_ACCEPTED",
                         f"候选登记 {bid} 摘要 {b_digest[:12]}…", bid)
            return
        if existing.b_digest == b_digest:
            # 同摘要重投递：幂等忽略
            self._decide(seq, T_CANDIDATE, O_DUP_CANDIDATE,
                         f"候选 {bid} 重复投递，幂等忽略", bid)
            return
        # 同编号冲突：先落盘者占编号
        existing.conflict_seqs.append(seq)
        self._decide(seq, T_CANDIDATE, O_REJECT_CONFLICT,
                     f"同编号冲突 {bid}：seq {existing.first_seq} 已占用编号",
                     bid)

    def _on_approval(self, seq: int, env: dict) -> None:
        bid = env["batch_id"]
        gen = int(env["generation"])
        if self._stale(gen):
            self._decide(seq, T_APPROVAL, O_REJECT_OLD_GEN,
                         f"旧代批准 {bid}", bid)
            return
        st = self.batches.get(bid)
        if st is None:
            self._decide(seq, T_APPROVAL, O_REJECT_BAD_SIG,
                         f"批准指向未知批次 {bid}", bid)
            return
        if st.b_digest != env.get("batch_digest"):
            self._decide(seq, T_APPROVAL, O_REJECT_BAD_SIG,
                         f"批准绑定的批次摘要不符 {bid}", bid)
            return
        root = self.policy.manifest.root(env.get("root_id", ""))
        if root is None or not root.verify(st.b_digest, st.partition,
                                          st.generation, env.get("signature", "")):
            self._decide(seq, T_APPROVAL, O_REJECT_BAD_SIG,
                         f"批准签名无效或绑定被替换 {bid}", bid)
            return
        st.approvals.append(env)
        self._decide(seq, T_APPROVAL, "APPROVAL_ACCEPTED",
                     f"接受 {env['root_id']} 对 {bid} 的批准", bid)

    def _on_cancel(self, seq: int, env: dict) -> None:
        bid = env["batch_id"]
        gen = int(env["generation"])
        if self._stale(gen):
            self._decide(seq, T_CANCEL, O_REJECT_OLD_GEN,
                         f"旧代取消 {bid}", bid)
            return
        st = self.batches.get(bid)
        if st is None:
            self._decide(seq, T_CANCEL, "CANCEL_NO_TARGET",
                         f"取消指向未知批次 {bid}（仍登记为取消标记）", bid)
            self.batches[bid] = BatchState(
                batch_id=bid, first_seq=seq, generation=gen,
                partition=env.get("partition", "?"), b_digest="",
                payload=None, status="canceled", outcome="CANCELED_NO_TARGET",
                outcome_seq=seq, cancel_seq=seq)
            return
        if st.status == "committed":
            self._decide(seq, T_CANCEL, "CANCEL_TOO_LATE",
                         f"批次 {bid} 已在 seq {st.outcome_seq} 生效，"
                         "迟到取消不撤销承诺", bid)
            return
        st.cancel_seq = seq
        st.status = "canceled"
        st.outcome = "CANCELED"
        st.outcome_seq = seq
        self._decide(seq, T_CANCEL, "CANCELED_FIRST",
                     f"取消先落盘 {bid} @seq {seq}", bid)

    def _on_commit(self, seq: int, env: dict) -> None:
        bid = env["batch_id"]
        gen = int(env["generation"])
        if self._stale(gen):
            # 事故根因：断链后重投的旧代提交
            self._decide(seq, T_COMMIT, O_REJECT_OLD_GEN,
                         f"拒绝旧代重投提交 {bid} gen={gen} < {self.generation}",
                         bid)
            return
        st = self.batches.get(bid)
        if st is None:
            self._decide(seq, T_COMMIT, O_REJECT_CONFLICT,
                         f"提交指向未知批次 {bid}", bid)
            return
        if st.b_digest != env.get("batch_digest"):
            self._decide(seq, T_COMMIT, O_REJECT_CONFLICT,
                         f"提交摘要与登记候选不符 {bid}", bid)
            return
        if st.status == "committed":
            self._decide(seq, T_COMMIT, O_DUP_COMMIT,
                         f"批次 {bid} 已生效，重复提交幂等忽略", bid)
            return
        # 注意：同编号冲突的输家提交会在上面的摘要比对处被拒
        # （其 batch_digest 与先落盘候选不同），先落盘赢家不受影响。
        if st.cancel_seq is not None and st.cancel_seq < seq:
            st.status = "rejected"
            st.outcome = O_REJECT_CANCEL
            st.outcome_seq = seq
            self._decide(seq, T_COMMIT, O_REJECT_CANCEL,
                         f"取消 seq {st.cancel_seq} 先于提交 seq {seq}，"
                         f"拒绝 {bid}", bid)
            return
        # 双根异链批准复核（发送侧自身视角；接收侧随 COMMIT 携带批准快照）
        quorum = self.policy.evaluate(st.b_digest, st.partition,
                                      st.generation, st.approvals)
        if not quorum.satisfied:
            st.status = "rejected"
            st.outcome = O_REJECT_QUORUM
            st.outcome_seq = seq
            self._decide(seq, T_COMMIT, O_REJECT_QUORUM,
                         f"{bid} 批准不足：{quorum.reason}", bid)
            return
        st.status = "committed"
        st.outcome = O_COMMIT
        st.outcome_seq = seq
        self.committed[bid] = st
        self._decide(seq, T_COMMIT, O_COMMIT,
                     f"批次 {bid} 生效，控制链 {quorum.distinct_chains}", bid)

    def _on_receipt(self, seq: int, env: dict) -> None:
        rid = env["receipt_id"]
        bid = env["batch_id"]
        gen = int(env["generation"])
        if rid in self._receipt_seen:
            self._decide(seq, T_RECEIPT, O_DUP_RECEIPT,
                         f"回执 {rid} 重复，幂等去重", bid)
            return
        self._receipt_seen.add(rid)
        if self._stale(gen):
            self._decide(seq, T_RECEIPT, O_REJECT_OLD_GEN,
                         f"旧代回执 {rid}（批次 {bid}）拒绝", bid)
            return
        st = self.batches.get(bid)
        if st is None or st.status != "committed":
            self._decide(seq, T_RECEIPT, "RECEIPT_WITHOUT_COMMIT",
                         f"回执 {rid} 对应批次未生效，忽略", bid)
            return
        st.receipt_ids.append(rid)
        self._decide(seq, T_RECEIPT, "RECEIPT_ACCEPTED",
                     f"回执 {rid} 入账 {bid}", bid)

    # ------------------------------------------------------------------
    def commitment_set(self) -> list[dict]:
        """承诺集合：实际生效批次的确定性表示（按首次提交 seq 排序）。"""
        return [{
            "batch_id": st.batch_id,
            "partition": st.partition,
            "generation": st.generation,
            "batch_digest": st.b_digest,
            "commit_seq": st.outcome_seq,
        } for st in self.committed.values()]

    def commitment_ids(self) -> list[str]:
        return list(self.committed.keys())

    def stats(self) -> dict:
        return {
            "side": self.side,
            "generation": self.generation,
            "records_decided": len(self.decisions),
            "committed": len(self.committed),
            "counts": dict(self.counts),
        }


class LegacyRuleEngine(RuleEngine):
    """事故版本：不做链路代围栏（enforce_generation=False）。

    旧代 COMMIT 在断链重连后被重新接受，于是两侧都把早已轮换掉的
    批次重新计入承诺集合，发布摘要双双“声称已生效”——用于复现事故。
    """

    def __init__(self, manifest: TrustManifest, *, side: str) -> None:
        super().__init__(manifest, side=side, enforce_generation=False)
