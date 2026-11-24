"""封包与持久记录的数据模型、规范序列化、摘要算法。

设计要点
========
1. 所有对象都是普通 dict/list/str/int，不自定义 pickle，落盘即 JSON，
   方便独立工具只读磁盘即可理解。
2. 规范序列化（canonical JSON）对键排序、无多余空白，保证跨进程、
   跨侧（发送方/接收方）对同一逻辑对象算出完全一致的字节与哈希。
3. 批次摘要 ``batch_digest`` 绑定批次内容（编号、目的分区、链路代、载荷），
   信任根批准签名覆盖的就是这串字节。
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

# 封包类型常量（线网与入站日志共用同一词汇表）
T_EPOCH = "EPOCH"          # 链路代标记：换班/断链恢复时代际 +1
T_CANDIDATE = "CAND"       # 候选批次
T_APPROVAL = "APR"         # 某信任根对候选批次的批准
T_CANCEL = "CANCEL"        # 取消决定
T_COMMIT = "COMMIT"        # 发送方在拿到双根批准后发出的提交
T_RECEIPT = "REC"          # 接收方回执

ALL_TYPES = frozenset(
    {T_EPOCH, T_CANDIDATE, T_APPROVAL, T_CANCEL, T_COMMIT, T_RECEIPT}
)

# 裁决结论（仅存在于内存与发布报告，入站原始日志只保存收到的封包）
O_COMMIT = "COMMITTED"
O_REJECT_CANCEL = "REJECTED_CANCEL_FIRST"
O_REJECT_CONFLICT = "REJECTED_ID_CONFLICT"
O_REJECT_QUORUM = "REJECTED_APPROVAL_QUORUM"
O_REJECT_OLD_GEN = "REJECTED_OLD_GENERATION"
O_REJECT_BAD_SIG = "REJECTED_BAD_APPROVAL"
O_REJECT_FUTURE_GEN = "REJECTED_FUTURE_GENERATION"
O_DUP_RECEIPT = "RECEIPT_DEDUP"
O_DUP_CANDIDATE = "CANDIDATE_REDELIVERY"
O_DUP_COMMIT = "COMMIT_REDELIVERY"
O_DUP_EPOCH = "EPOCH_DUPLICATE"
O_GEN_ADVANCE = "GENERATION_ADVANCED"

# 哈希链创世前驱值
GENESIS_PREV = "00" * 32


def canonical(obj: Any) -> bytes:
    """规范 JSON 字节：sort_keys、分隔符紧凑、ASCII 安全、LF 换行。

    签名与哈希一律以此函数的输出为准，避免默认序列化在空白、键序、
    Unicode 转义上的实现差异。
    """
    return (json.dumps(obj, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False) + "\n").encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_obj(obj: Any) -> str:
    """对任意可 JSON 化对象求 SHA-256 摘要（十六进制）。"""
    return sha256_hex(canonical(obj))


def batch_digest(batch_id: str, partition: str, generation: int,
                 payload: Any) -> str:
    """候选批次内容摘要：绑定编号、目的分区、链路代、载荷四要素。

    批准签名覆盖该摘要，因此任何要素被替换都会导致签名校验失败。
    """
    return digest_obj({
        "batch_id": batch_id,
        "partition": partition,
        "generation": generation,
        "payload": payload,
    })


def approval_signing_payload(b_digest: str, partition: str,
                             generation: int) -> bytes:
    """批准签名的覆盖范围：批次摘要 + 目的分区 + 链路代。

    题面要求批准必须同时绑定这三项；信任根对该字节串做 HMAC。
    """
    return canonical({
        "batch_digest": b_digest,
        "partition": partition,
        "generation": generation,
        "op": "approve",
    })


def envelope(kind: str, **fields: Any) -> dict:
    """构造封包：统一带 type 字段，其余字段由调用方给出。"""
    if kind not in ALL_TYPES:
        raise ValueError(f"未知封包类型: {kind}")
    env: dict[str, Any] = {"type": kind}
    env.update(fields)
    return env
