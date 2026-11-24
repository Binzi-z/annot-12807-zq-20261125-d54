"""磁盘存储：追加式哈希链持久日志与文件线网 spool。

持久日志 ``DurableLog``
=======================
- 每行一条 JSON 记录，记录结构为::

      {"seq": int, "prev": str, "hash": str, "env": <封包>}

- ``seq`` 从 1 开始，严格按真正执行 ``append`` 的系统调用先后分配；
  规则引擎只承认这个顺序，封包自带的逻辑时间戳不能改变裁决顺序。
- 每条记录的哈希覆盖 ``prev`` 与封包规范字节，形成链式结构，
  独立验证工具可逐行校验，任何插入、删除、篡改都会断链。
- Windows 上 ``os.replace`` 提供同卷原子替换，发布摘要时用它避免
  出现“写一半的摘要文件”。

文件线网 ``WireSpool``
======================
演练禁用真实联网，链路用一个 JSONL 文件模拟：发送方原子追加，
接收方按已确认偏移量顺序读取，偏移量单独落盘，重投即重复投递同一行。
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any, Iterator

from .model import GENESIS_PREV, canonical, sha256_hex


def _fsync_dir(path: Path) -> None:
    """目录 fsync：Windows 上不支持，静默跳过（文件级 flush+fsync 仍保留）。"""
    try:
        fd = os.open(str(path), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def atomic_write_text(path: Path, text: str, *, fsync: bool = True) -> None:
    """同目录临时文件 + os.replace 的原子写，保证读者不会看到半成品。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
        fh.flush()
        if fsync:
            os.fsync(fh.fileno())
    os.replace(tmp, path)
    _fsync_dir(path.parent)


def read_jsonl(path: Path) -> list[Any]:
    """读取 JSONL 文件为列表；文件不存在时返回空列表。"""
    if not path.exists():
        return []
    out: list[Any] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


class DurableLog:
    """线程安全的追加式哈希链日志。

    ``fsync_every`` 控制每条/每 N 条落盘一次：
    - 正确性场景（三线程场景、事故复现）用 1，严格逐条持久化；
    - 六万封包压力场景可调大，在同进程崩溃语义不参与裁决的前提下
      换取 Windows 上的吞吐，顺序语义（seq）不受影响。
    """

    def __init__(self, path: Path, *, fsync_every: int = 1) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._fsync_every = max(1, int(fsync_every))
        self._since_fsync = 0
        self._fh = open(self.path, "a", encoding="utf-8", newline="\n")
        try:
            self._seq, self._head = self._recover_head()
        except Exception:
            self._fh.close()
            raise

    def _recover_head(self) -> tuple[int, str]:
        """打开已有日志时恢复当前 seq 与链头；同时做一次完整链校验。"""
        seq = 0
        prev = GENESIS_PREV
        if not self.path.exists():
            return seq, prev
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                expected = sha256_hex(
                    canonical({"prev": rec["prev"], "env": rec["env"]}))
                if rec["prev"] != prev or rec["hash"] != expected:
                    raise ValueError(f"持久日志哈希链损坏: {self.path}")
                seq = rec["seq"]
                prev = rec["hash"]
        return seq, prev

    @property
    def head(self) -> str:
        with self._lock:
            return self._head

    @property
    def seq(self) -> int:
        with self._lock:
            return self._seq

    def append(self, env: dict) -> dict:
        """按真实调用先后追加一条入站封包，返回带 seq/hash 的记录。

        锁内同时完成 seq 分配、哈希计算与写入，因此两个真实线程谁先
        抢到锁，谁的记录 seq 更小——裁决完全以落盘先后为准。
        """
        with self._lock:
            rec = {
                "seq": self._seq + 1,
                "prev": self._head,
                "env": env,
            }
            rec["hash"] = sha256_hex(
                canonical({"prev": rec["prev"], "env": rec["env"]}))
            self._fh.write(json.dumps(rec, sort_keys=True,
                                      ensure_ascii=False) + "\n")
            self._fh.flush()
            self._since_fsync += 1
            if self._since_fsync >= self._fsync_every:
                os.fsync(self._fh.fileno())
                self._since_fsync = 0
            self._seq = rec["seq"]
            self._head = rec["hash"]
            return rec

    def flush(self) -> None:
        with self._lock:
            self._fh.flush()
            os.fsync(self._fh.fileno())
            self._since_fsync = 0

    def close(self) -> None:
        with self._lock:
            if not self._fh.closed:
                self._fh.flush()
                os.fsync(self._fh.fileno())
                self._fh.close()

    def __enter__(self) -> "DurableLog":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def records(self) -> list[dict]:
        """读盘返回全部记录（独立验证工具走这个入口，不共享内存）。"""
        return read_jsonl(self.path)

    def __len__(self) -> int:
        return self._seq


class WireSpool:
    """文件线网：模拟一条可断开、可重投、可乱序投递的链路。

    - 发送侧 ``send`` 原子追加一行封包；
    - 接收侧 ``deliver`` 返回当前尚未确认的封包子集，可乱序返回，
      确认偏移量持久化到 ``<spool>.offset``；
    - “重投”通过不推进偏移、再次 deliver 同一批行实现。
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.offset_path = self.path.with_suffix(".offset.json")
        self._lock = threading.Lock()
        # Windows 下追加句柄不可读，行数在构造时读一次后由锁内计数维护
        self._line_count = len(read_jsonl(self.path))

    def send(self, env: dict) -> int:
        """追加一个封包，返回它在线网上的行号（从 1 起）。"""
        with self._lock:
            with open(self.path, "a", encoding="utf-8", newline="\n") as fh:
                fh.write(json.dumps(env, sort_keys=True,
                                    ensure_ascii=False) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            self._line_count += 1
            return self._line_count

    def send_many(self, envs: list[dict]) -> None:
        with self._lock:
            with open(self.path, "a", encoding="utf-8", newline="\n") as fh:
                for env in envs:
                    fh.write(json.dumps(env, sort_keys=True,
                                        ensure_ascii=False) + "\n")
                fh.flush()
                os.fsync(fh.fileno())

    def _confirmed(self) -> int:
        data = read_jsonl(self.offset_path)
        return data[-1]["confirmed_lines"] if data else 0

    def pending(self) -> list[dict]:
        """返回尚未确认的全部封包（保持线网行序）。"""
        confirmed = self._confirmed()
        rows = read_jsonl(self.path)
        return rows[confirmed:]

    def deliver(self, *, shuffle: bool = False, rng=None) -> list[dict]:
        """投递未确认封包；shuffle=True 时乱序，但不跨代边界（由调用方保证）。"""
        items = list(self.pending())
        if shuffle and rng is not None and len(items) > 1:
            rng.shuffle(items)
        return items

    def confirm(self, count: int) -> None:
        """确认已消费前 count 个未读封包，偏移量原子落盘。"""
        new_confirmed = self._confirmed() + int(count)
        atomic_write_text(
            self.offset_path,
            json.dumps({"confirmed_lines": new_confirmed},
                       sort_keys=True) + "\n",
        )

    def redeliver(self) -> list[dict]:
        """链路断开重连后的重投：偏移不动，再次给出未确认封包。"""
        return self.pending()

    def all_rows(self) -> list[dict]:
        return read_jsonl(self.path)

    def __iter__(self) -> Iterator[dict]:
        return iter(read_jsonl(self.path))
