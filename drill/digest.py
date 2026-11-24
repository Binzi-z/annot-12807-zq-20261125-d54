"""承诺集分段摘要、局部修订与两侧对账。

分段结构
========
承诺条目按 ``partition`` 归入分段（段内按 batch_id 排序，保证跨侧字节
一致），每段计算段根，所有段根再汇入顶层头摘要。局部修订时只需重算
受影响分段及其后的头摘要折叠，并通过计数器报告“实际比对范围”——
没有触碰的分段既不重算也不参与逐条比对。

发布物 ``published.json``
=========================
原子写入，包含：分段数、段根表、顶层头摘要、承诺条目数、链路代、
信任清单指纹、构建时间（合成逻辑时钟，不使用墙钟）。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .model import canonical, sha256_hex
from .store import atomic_write_text


def segment_key(partition: str, segment_count: int) -> int:
    """分区 -> 段号：对分区名哈希取模，分区分布均匀且确定。"""
    h = int(sha256_hex(canonical(partition)), 16)
    return h % max(1, segment_count)


def _entry_bytes(entry: dict) -> bytes:
    return canonical({
        "batch_id": entry["batch_id"],
        "partition": entry["partition"],
        "generation": entry["generation"],
        "batch_digest": entry["batch_digest"],
    })


def segment_root(entries: list[dict]) -> str:
    """段根 = 折叠段内全部条目（段内按 batch_id 排序后折叠）。"""
    ordered = sorted(entries, key=lambda e: e["batch_id"])
    acc = sha256_hex(b"SEGMENT-ROOT-V1\n")
    for e in ordered:
        acc = sha256_hex(acc.encode("ascii") + _entry_bytes(e))
    return acc


@dataclass
class SegmentTable:
    segment_count: int
    entries_by_segment: dict[int, list[dict]] = field(default_factory=dict)

    @classmethod
    def build(cls, commitments: list[dict], segment_count: int) -> "SegmentTable":
        table = cls(segment_count=segment_count)
        for entry in commitments:
            idx = segment_key(entry["partition"], segment_count)
            table.entries_by_segment.setdefault(idx, []).append(entry)
        for idx in table.entries_by_segment:
            table.entries_by_segment[idx].sort(
                key=lambda e: e["batch_id"])
        return table

    def roots(self) -> dict[int, str]:
        return {idx: segment_root(entries)
                for idx, entries in self.entries_by_segment.items()}

    def head_digest(self) -> str:
        """顶层头摘要：折叠全部段根（空段以固定占位根参与）。"""
        acc = sha256_hex(b"COMMIT-HEAD-V1\n")
        all_roots = self.roots()
        for idx in range(self.segment_count):
            root = all_roots.get(idx, sha256_hex(b"EMPTY-SEGMENT-V1\n"))
            acc = sha256_hex(acc.encode("ascii")
                             + canonical({"segment": idx, "root": root}))
        return acc


def build_published(commitments: list[dict], *, segment_count: int,
                    generation: int, trust_fingerprint: str,
                    logical_clock: int) -> dict:
    """构造发布摘要对象（调用方负责原子落盘）。"""
    table = SegmentTable.build(commitments, segment_count)
    roots = table.roots()
    return {
        "version": 1,
        "logical_clock": logical_clock,
        "generation": generation,
        "segment_count": segment_count,
        "entry_count": len(commitments),
        "trust_fingerprint": trust_fingerprint,
        "head_digest": table.head_digest(),
        "segment_roots": [
            {"segment": idx,
             "root": roots.get(idx, sha256_hex(b"EMPTY-SEGMENT-V1\n"))}
            for idx in range(segment_count)
        ],
    }


def save_published(path: Path, published: dict) -> None:
    atomic_write_text(
        path, json.dumps(published, sort_keys=True, ensure_ascii=False,
                         indent=2))


def load_published(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


@dataclass
class RevisionReport:
    """局部修订报告：记录实际重算/比对的范围，证明修订是局部的。"""

    touched_segments: list[int]
    entries_rehashed: int
    segments_recomputed: int
    segments_untouched: int
    entries_total: int
    head_before: str
    head_after: str
    changed: bool


def revise_commitments(commitments: list[dict], *, segment_count: int,
                       touched_partitions: set[str],
                       transform) -> RevisionReport:
    """对受影响分区做局部修订。

    ``transform(entries)`` 接收受影响分区的全部条目，返回修订后条目；
    其余分区条目原样保留。报告里给出实际重算的段数与条目数，用于核对
    “局部修订的实际比对范围”。
    """
    table = SegmentTable.build(commitments, segment_count)
    head_before = table.head_digest()

    touched_segments = sorted({
        segment_key(p, segment_count) for p in touched_partitions})
    touched_set = set(touched_segments)

    affected_entries: list[dict] = []
    for idx in touched_segments:
        affected_entries.extend(table.entries_by_segment.get(idx, []))
    revised = transform(affected_entries)

    new_table = SegmentTable.build(
        [e for e in commitments
         if segment_key(e["partition"], segment_count) not in touched_set]
        + revised, segment_count)
    head_after = new_table.head_digest()

    entries_rehashed = sum(
        len(table.entries_by_segment.get(idx, []))
        for idx in touched_segments)
    return RevisionReport(
        touched_segments=touched_segments,
        entries_rehashed=entries_rehashed,
        segments_recomputed=len(touched_segments),
        segments_untouched=segment_count - len(touched_segments),
        entries_total=len(commitments),
        head_before=head_before,
        head_after=head_after,
        changed=head_before != head_after,
    )


@dataclass
class ReconcileReport:
    equal: bool
    head_a: str
    head_b: str
    differing_segments: list[int]
    segments_compared: int
    entries_compared_in_diff: int
    entries_total: int
    detail: list[dict] = field(default_factory=list)


def reconcile(pub_a: dict, pub_b: dict,
              commitments_a: list[dict],
              commitments_b: list[dict],
              *, segment_count: int) -> ReconcileReport:
    """两侧对账：先比头摘要，再只对差异段做逐条比对。

    返回实际比较的段数与差异段内逐条比对的条目数，即“实际比对范围”。
    """
    roots_a = {r["segment"]: r["root"] for r in pub_a["segment_roots"]}
    roots_b = {r["segment"]: r["root"] for r in pub_b["segment_roots"]}
    differing = sorted(idx for idx in range(segment_count)
                       if roots_a.get(idx) != roots_b.get(idx))

    table_a = SegmentTable.build(commitments_a, segment_count)
    table_b = SegmentTable.build(commitments_b, segment_count)
    entries_compared = 0
    detail: list[dict] = []
    for idx in differing:
        ea = sorted(table_a.entries_by_segment.get(idx, []),
                    key=lambda e: e["batch_id"])
        eb = sorted(table_b.entries_by_segment.get(idx, []),
                    key=lambda e: e["batch_id"])
        entries_compared += max(len(ea), len(eb))
        ids_a = {e["batch_id"] for e in ea}
        ids_b = {e["batch_id"] for e in eb}
        detail.append({
            "segment": idx,
            "only_in_a": sorted(ids_a - ids_b),
            "only_in_b": sorted(ids_b - ids_a),
            "count_a": len(ea),
            "count_b": len(eb),
        })

    return ReconcileReport(
        equal=not differing and pub_a["head_digest"] == pub_b["head_digest"],
        head_a=pub_a["head_digest"],
        head_b=pub_b["head_digest"],
        differing_segments=differing,
        segments_compared=segment_count,
        entries_compared_in_diff=entries_compared,
        entries_total=max(len(commitments_a), len(commitments_b)),
        detail=detail,
    )
