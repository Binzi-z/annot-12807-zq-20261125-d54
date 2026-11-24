"""文件线网：用目录里的 spool 文件模拟链路，全程无 socket。

一条双向链路由两个方向的 ``WireSpool`` 组成；“断开/重连”只改变投递
策略（是否推进偏移、是否重投），不删除任何已落盘封包，因此断链后
旧代封包的重投可以被忠实复现。
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from pathlib import Path

from .store import WireSpool


@dataclass
class FileLink:
    a_to_b: WireSpool
    b_to_a: WireSpool
    up: bool = True

    @classmethod
    def open(cls, root: Path) -> "FileLink":
        root = Path(root)
        root.mkdir(parents=True, exist_ok=True)
        return cls(
            a_to_b=WireSpool(root / "a_to_b.jsonl"),
            b_to_a=WireSpool(root / "b_to_a.jsonl"),
        )

    def send_a_to_b(self, env: dict) -> None:
        self.a_to_b.send(env)

    def send_b_to_a(self, env: dict) -> None:
        self.b_to_a.send(env)

    def deliver_to_b(self, rng: random.Random) -> list[dict]:
        items = self.a_to_b.deliver(shuffle=self.up, rng=rng)
        return items

    def deliver_to_a(self, rng: random.Random) -> list[dict]:
        items = self.b_to_a.deliver(shuffle=self.up, rng=rng)
        return items

    def confirm_to_b(self, count: int) -> None:
        self.a_to_b.confirm(count)

    def confirm_to_a(self, count: int) -> None:
        self.b_to_a.confirm(count)

    def disconnect(self) -> None:
        """断开：偏移冻结，之后重连会重投未确认封包。"""
        self.up = False

    def reconnect(self) -> None:
        self.up = True
