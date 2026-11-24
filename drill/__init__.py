"""演练网关离线回放与验证工具包。

仅使用 Python 3.12 标准库，全程不导入任何联网模块（见 offline_guard.py）。
模块划分：

- model    封包/记录类型、规范序列化与哈希
- store    仅靠文件交换的线网 spool、追加式哈希链持久日志
- trust    多信任根 HMAC 与“双根异控制链”批准策略
- rules    按真正落盘顺序裁决的回放规则引擎
- digest   承诺集分段摘要、局部修订与两侧对账
- gateway  单侧网关：入站落盘、重放、原子发布
- network  文件线网（spool 投递，无 socket）
"""

__all__ = [
    "model",
    "store",
    "trust",
    "rules",
    "digest",
    "gateway",
    "network",
]
