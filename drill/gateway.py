"""单侧演练网关：入站封包先落盘，再按落盘顺序重放并原子发布摘要。

目录布局（每侧一个目录）::

    <side_dir>/inbound.jsonl     追加式哈希链入站日志（裁决唯一事实源）
    <side_dir>/published.json    原子发布的承诺摘要
    <side_dir>/engine_snapshot.json  引擎统计快照（供人工检查，不作信任根）

网关本身不做任何联网 I/O；封包由演练编排器从文件线网读出后调用
``ingest`` 落盘，``replay`` 再从磁盘读回重放，独立验证工具使用完全
相同的日志文件、却在独立进程里重算，二者结果必须逐字节一致。
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from . import digest as digest_mod
from .rules import RuleEngine
from .store import DurableLog, atomic_write_text
from .trust import TrustManifest, manifest_fingerprint


@dataclass
class IngestResult:
    seq: int
    hash: str


class SideGateway:
    def __init__(self, side: str, side_dir: Path,
                 manifest: TrustManifest, *, segment_count: int,
                 fsync_every: int = 1,
                 engine_factory=RuleEngine) -> None:
        self.side = side
        self.dir = Path(side_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.manifest = manifest
        self.segment_count = segment_count
        self.log = DurableLog(self.dir / "inbound.jsonl",
                              fsync_every=fsync_every)
        self._engine_factory = engine_factory
        self.engine: RuleEngine | None = None
        self.logical_clock = 0

    # ------------------------------------------------------------------
    def ingest(self, env: dict) -> IngestResult:
        """入站封包先持久化：seq 在锁内按真实先后分配。"""
        rec = self.log.append(env)
        return IngestResult(seq=rec["seq"], hash=rec["hash"])

    def ingest_many(self, envs: list[dict]) -> list[IngestResult]:
        return [self.ingest(e) for e in envs]

    # ------------------------------------------------------------------
    def replay(self) -> RuleEngine:
        """从磁盘完整读回入站记录，按 seq 重放裁决（不信任任何内存状态）。"""
        engine = self._engine_factory(self.manifest, side=self.side)
        engine.process_records(self.log.records())
        self.engine = engine
        return engine

    # ------------------------------------------------------------------
    def publish(self) -> dict:
        """重放 -> 构造承诺摘要 -> 原子落盘发布。"""
        engine = self.replay()
        self.logical_clock += 1
        published = digest_mod.build_published(
            engine.commitment_set(),
            segment_count=self.segment_count,
            generation=engine.generation,
            trust_fingerprint=manifest_fingerprint(self.manifest),
            logical_clock=self.logical_clock,
        )
        digest_mod.save_published(self.dir / "published.json", published)
        atomic_write_text(
            self.dir / "engine_snapshot.json",
            json.dumps(engine.stats(), sort_keys=True,
                       ensure_ascii=False, indent=2))
        return published

    def close(self) -> None:
        self.log.close()

    def __enter__(self) -> "SideGateway":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
