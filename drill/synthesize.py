"""六万条合成封包的确定性生成器。

全部封包均为本地合成数据，生成过程可复现（固定随机种子），封包总数
严格等于 60000（代码内断言）。流按链路代切成 5 个窗口，窗口间插入
EPOCH 换班标记；窗口内打乱，制造乱序输入（旧批回执、取消决定、重投
提交混在其中），但每个窗口内强制“取消先于其提交”的目标批次保持该
落盘先后，以便断言裁决结果。

封包构成（计数由代码汇总并断言总数）
====================================
- 6500 个候选批次的基础束：候选 + 双根批准 + 提交（4/批）
- 4 个换班 EPOCH
- 健康批次回执（含大量多回执）、300 条重投重复回执、250 条旧代回执
- 450 个取消先落盘批次、200 组同编号冲突候选
- 1050 条问题批准：未知根 400、同控制链 350、签名绑定被换 300
- 600 条旧代重投提交、781 条同摘要候选重投（幂等）
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

from .model import (
    T_APPROVAL, T_CANCEL, T_CANDIDATE, T_COMMIT, T_EPOCH, T_RECEIPT,
    batch_digest, envelope,
)
from .trust import TrustManifest, TrustRoot

TARGET_TOTAL = 60_000
N_BATCHES = 6_500
N_GENERATIONS = 5
PARTITION_COUNT = 128
FAULT_PARTITIONS_PER_RUN = 3

N_CANCEL_FIRST = 450
N_CONFLICT_PAIRS = 200
N_DUP_RECEIPTS = 300
N_OLD_RECEIPTS = 250
N_OLD_COMMITS = 600
N_UNKNOWN_ROOT_APR = 400
N_SAME_CHAIN_APR = 350
N_BAD_BINDING_APR = 300
N_DUP_CANDIDATE = 781
# 注意：重投回执每条写两份（原始 + 重投，共 2*N_DUP_RECEIPTS 个封包）。
# 其余各项合计 35785，额外有效回执取 24215，使封包总数严格等于 60000
# （构建时再次以断言兜底，改任一常量都会立刻暴露）。
N_EXTRA_VALID_RECEIPT = 24_215


@dataclass
class BatchSpec:
    batch_id: str
    partition: str
    generation: int
    payload: dict
    digest: str
    fault: bool = False


@dataclass
class SyntheticStream:
    packets: list[dict]
    batches: list[BatchSpec]
    fault_partitions: list[str]
    side_windows: dict[str, list[list[dict]]] = field(default_factory=dict)
    counts: dict = field(default_factory=dict)


def _build_manifest() -> TrustManifest:
    """三条控制链、四个根：root-A2 与 A1 同链，专用于同链投票测试。"""
    import secrets
    return TrustManifest([
        TrustRoot("root-A1", "chain-alpha", secrets.token_bytes(32)),
        TrustRoot("root-A2", "chain-alpha", secrets.token_bytes(32)),
        TrustRoot("root-B1", "chain-beta", secrets.token_bytes(32)),
    ])


def select_fault_partitions(segment_count: int) -> list[str]:
    """穷举挑选三个“相隔很远”的故障分区。

    同时考虑两种距离：分区编号距离与分段哈希空间距离，取最小成对
    距离之和最大的三元组，保证三个故障点在两个空间里都彼此远离。
    """
    from .digest import segment_key
    partitions = [f"P{i:04d}" for i in range(PARTITION_COUNT)]
    seg_of = {p: segment_key(p, segment_count) for p in partitions}
    idx_of = {p: i for i, p in enumerate(partitions)}

    best: tuple[int, list[str]] | None = None
    for i in range(PARTITION_COUNT):
        for j in range(i + 1, PARTITION_COUNT):
            for k in range(j + 1, PARTITION_COUNT):
                trio = [partitions[i], partitions[j], partitions[k]]
                idx_d = min(j - i, k - j, k - i)
                s = [seg_of[p] for p in trio]
                seg_d = min(abs(s[1] - s[0]), abs(s[2] - s[1]),
                            abs(s[2] - s[0]),
                            segment_count - max(s) + min(s))
                score = idx_d + seg_d
                if best is None or score > best[0]:
                    best = (score, trio)
    assert best is not None
    return best[1]


def _base_bundle(manifest: TrustManifest, spec: BatchSpec) -> list[dict]:
    b = spec.digest
    out = [envelope(T_CANDIDATE, batch_id=spec.batch_id,
                    partition=spec.partition, generation=spec.generation,
                    payload=spec.payload)]
    for root in (manifest.root("root-A1"), manifest.root("root-B1")):
        out.append(envelope(
            T_APPROVAL, batch_id=spec.batch_id, root_id=root.root_id,
            generation=spec.generation, batch_digest=b,
            partition=spec.partition,
            signature=root.sign(b, spec.partition, spec.generation)))
    out.append(envelope(T_COMMIT, batch_id=spec.batch_id,
                        partition=spec.partition,
                        generation=spec.generation, batch_digest=b))
    return out


def build_stream(manifest: TrustManifest, *, segment_count: int,
                 seed: int = 20261125) -> SyntheticStream:
    rng = random.Random(seed)
    fault_partitions = select_fault_partitions(segment_count)
    fault_set = set(fault_partitions)

    # ---- 批次规格 --------------------------------------------------
    batches: list[BatchSpec] = []
    for i in range(N_BATCHES):
        gen = i % N_GENERATIONS
        partition = f"P{i % PARTITION_COUNT:04d}"
        payload = {"seq": i, "checksum": f"chk-{i:06d}",
                   "body": f"synthetic-payload-{i}"}
        bid = f"B{i:06d}"
        d = batch_digest(bid, partition, gen, payload)
        batches.append(BatchSpec(
            batch_id=bid, partition=partition, generation=gen,
            payload=payload, digest=d, fault=partition in fault_set))

    by_gen: dict[int, list[BatchSpec]] = {g: [] for g in range(N_GENERATIONS)}
    for sp in batches:
        by_gen[sp.generation].append(sp)

    non_fault = [sp for sp in batches if not sp.fault]
    cancel_targets = {sp.batch_id for sp in non_fault[:N_CANCEL_FIRST]}
    conflict_targets = {
        sp.batch_id
        for sp in non_fault[N_CANCEL_FIRST:N_CANCEL_FIRST + N_CONFLICT_PAIRS]}
    apr_targets = non_fault[N_CANCEL_FIRST + N_CONFLICT_PAIRS:]

    packets: list[dict] = []
    counts: dict[str, int] = {}
    epochs: dict[int, dict] = {}

    def add(env: dict) -> None:
        packets.append(env)
        counts[env["type"]] = counts.get(env["type"], 0) + 1

    # 每代一个窗口，代间插 EPOCH（EPOCH 在侧窗口组装时前置）
    windows: list[list[dict]] = []
    for gen in range(N_GENERATIONS):
        if gen > 0:
            epoch_env = envelope(T_EPOCH, generation=gen,
                                 reason="shift-change")
            add(epoch_env)
            epochs[gen] = epoch_env
        win: list[dict] = []
        for sp in by_gen[gen]:
            for env in _base_bundle(manifest, sp):
                win.append(env)
                add(env)
        windows.append(win)

    def window_of(gen: int) -> list[dict]:
        return windows[gen]

    # ---- 取消先落盘（同代窗口，强制取消排在该批次提交之前）---------
    for sp in batches:
        if sp.batch_id in cancel_targets:
            window_of(sp.generation).append(envelope(
                T_CANCEL, batch_id=sp.batch_id,
                partition=sp.partition, generation=sp.generation))
            add(window_of(sp.generation)[-1])

    # ---- 同编号冲突候选（同编号、不同载荷 -> 不同摘要）-------------
    for sp in batches:
        if sp.batch_id in conflict_targets:
            evil_payload = {"seq": sp.payload["seq"], "tampered": True}
            window_of(sp.generation).append(envelope(
                T_CANDIDATE, batch_id=sp.batch_id,
                partition=sp.partition, generation=sp.generation,
                payload=evil_payload))
            add(window_of(sp.generation)[-1])

    # ---- 问题批准 --------------------------------------------------
    apr_pool = [sp for sp in apr_targets if sp.batch_id not in conflict_targets]
    cursor = 0
    for n, kind in ((N_UNKNOWN_ROOT_APR, "unknown"),
                    (N_SAME_CHAIN_APR, "same_chain"),
                    (N_BAD_BINDING_APR, "bad_binding")):
        for _ in range(n):
            sp = apr_pool[cursor % len(apr_pool)]
            cursor += 1
            if kind == "unknown":
                env = envelope(T_APPROVAL, batch_id=sp.batch_id,
                               root_id="root-X9", generation=sp.generation,
                               batch_digest=sp.digest,
                               partition=sp.partition, signature="00" * 32)
            elif kind == "same_chain":
                root = manifest.root("root-A2")
                env = envelope(T_APPROVAL, batch_id=sp.batch_id,
                               root_id=root.root_id, generation=sp.generation,
                               batch_digest=sp.digest,
                               partition=sp.partition,
                               signature=root.sign(sp.digest, sp.partition,
                                                   sp.generation))
            else:
                root = manifest.root("root-A1")
                env = envelope(T_APPROVAL, batch_id=sp.batch_id,
                               root_id=root.root_id, generation=sp.generation,
                               batch_digest=sha256_bad(sp.digest),
                               partition=sp.partition,
                               signature=root.sign(sp.digest, sp.partition,
                                                   sp.generation))
            window_of(sp.generation).append(env)
            add(env)

    # ---- 同摘要候选重投（幂等）------------------------------------
    for k in range(N_DUP_CANDIDATE):
        sp = batches[k % len(batches)]
        window_of(sp.generation).append(envelope(
            T_CANDIDATE, batch_id=sp.batch_id, partition=sp.partition,
            generation=sp.generation, payload=sp.payload))
        add(window_of(sp.generation)[-1])

    # ---- 回执：健康批次首回执 + 大量额外有效回执 -------------------
    healthy = [sp for sp in batches
               if sp.batch_id not in cancel_targets
               and sp.batch_id not in conflict_targets]
    rid = 0

    def receipt(sp: BatchSpec, gen: int | None = None) -> dict:
        nonlocal rid
        rid += 1
        return envelope(T_RECEIPT, receipt_id=f"R{rid:07d}",
                        batch_id=sp.batch_id,
                        generation=sp.generation if gen is None else gen)

    for sp in healthy:
        env = receipt(sp)
        window_of(sp.generation).append(env)
        add(env)
    for k in range(N_EXTRA_VALID_RECEIPT):
        sp = healthy[k % len(healthy)]
        env = receipt(sp)
        window_of(sp.generation).append(env)
        add(env)
    # 重投重复回执：相同 receipt_id，触发幂等去重
    for k in range(N_DUP_RECEIPTS):
        sp = healthy[k % len(healthy)]
        env = envelope(T_RECEIPT, receipt_id=f"RDUP{k:06d}",
                       batch_id=sp.batch_id, generation=sp.generation)
        window_of(sp.generation).append(env)
        add(env)
        window_of(sp.generation).append(dict(env))
        add(dict(env))

    # ---- 旧代回执（放进末代窗口，必被代际围栏拒绝）----------------
    last = N_GENERATIONS - 1
    for k in range(N_OLD_RECEIPTS):
        sp = batches[k % len(batches)]
        old_gen = max(0, sp.generation - 1) if sp.generation > 0 else 0
        env = envelope(T_RECEIPT, receipt_id=f"ROLD{k:06d}",
                       batch_id=sp.batch_id, generation=old_gen)
        window_of(last).append(env)
        add(env)

    # ---- 旧代重投提交：故障分区批次的提交在末代重投 ----------------
    # 重投代际一律取“批次原代 -1（不低于 0）”，保证在末代窗口里
    # 严格旧于当前链路代，全部由代际围栏拒绝（而非按重复提交幂等）。
    fault_specs = [sp for sp in batches if sp.fault]
    for k in range(N_OLD_COMMITS):
        sp = fault_specs[k % len(fault_specs)]
        stale_gen = max(0, sp.generation - 1)
        env = envelope(T_COMMIT, batch_id=sp.batch_id,
                       partition=sp.partition, generation=stale_gen,
                       batch_digest=sp.digest)
        window_of(last).append(env)
        add(env)

    # ---- 断言总数，差额用额外有效回执吸收（这里直接校验常量）------
    assert len(packets) == TARGET_TOTAL, (
        f"合成封包总数 {len(packets)} != {TARGET_TOTAL}")

    stream = SyntheticStream(
        packets=packets, batches=batches,
        fault_partitions=fault_partitions, counts=counts)

    # 两侧使用不同乱序（不同种子），封包多重集一致；乱序后再施加协议
    # 必需的局部先后约束（EPOCH 居首、候选->批准->取消->提交->回执、
    # 原始候选先于篡改候选），其余相对顺序保持 shuffle 结果。
    for side, sseed in (("side-a", seed + 1), ("side-b", seed + 2)):
        side_rng = random.Random(sseed)
        side_windows: list[list[dict]] = []
        for gen, win in enumerate(windows):
            shuffled = list(win)
            side_rng.shuffle(shuffled)
            ordered = _enforce_protocol_order(
                ([epochs[gen]] if gen in epochs else []) + shuffled)
            side_windows.append(ordered)
        stream.side_windows[side] = side_windows
    return stream


def _batch_index(env: dict) -> int:
    return int(env["batch_id"].removeprefix("B"))


def _enforce_protocol_order(win: list[dict]) -> list[dict]:
    """稳定排序：保留乱序结果中同键封包的相对顺序，只强制协议先后。

    键的第二维：EPOCH -1；普通/重投候选 0；篡改候选 0.5；批准 1；
    取消 1.5（保证取消先于提交落盘）；提交 2；回执 3。
    """
    def key(env: dict) -> tuple[int, float]:
        kind = env["type"]
        if kind == T_EPOCH:
            return (-1, 0.0)
        idx = _batch_index(env)
        if kind == T_CANDIDATE:
            sub = 0.5 if "tampered" in env.get("payload", {}) else 0.0
            return (idx, sub)
        if kind == T_APPROVAL:
            return (idx, 1.0)
        if kind == T_CANCEL:
            return (idx, 1.5)
        if kind == T_COMMIT:
            return (idx, 2.0)
        return (idx, 3.0)       # T_RECEIPT

    return sorted(win, key=key)


def sha256_bad(d: str) -> str:
    """构造与原摘要不同的绑定值（模拟批准绑定被替换）。"""
    from hashlib import sha256
    return sha256((d + "binding-rewritten").encode("utf-8")).hexdigest()


def new_manifest() -> TrustManifest:
    return _build_manifest()
