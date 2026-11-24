"""离线守卫：静态扫描全部源码的导入，确保演练禁用真实联网。

题面要求“只交换合成消息封包，禁用真实联网”。除了运行时不发起任何
连接外，这里再加一道静态闸门：用 AST 扫描本项目所有 .py 文件，
出现任何联网模块导入即抛错。测试与总装运行器都会调用该闸门。

注意：``subprocess`` 仅用于在本机拉起独立验证进程，不涉及网络，
不在禁止清单内。
"""

from __future__ import annotations

import ast
from pathlib import Path

FORBIDDEN_MODULES = frozenset({
    "socket", "ssl", "http", "urllib", "urllib.request", "urllib.response",
    "http.client", "http.server", "requests", "aiohttp", "httpx",
    "websockets", "websocket", "ftplib", "smtplib", "poplib", "imaplib",
    "telnetlib", "xmlrpc", "xmlrpc.client", "pika", "kafka",
    "grpc", "socketio", "engineio",
})

FORBIDDEN_TOP_LEVEL = frozenset({name.split(".")[0] for name in FORBIDDEN_MODULES})


class OfflineViolation(RuntimeError):
    pass


def scan_file(path: Path) -> list[str]:
    """返回该文件中违规的导入描述列表（空列表即通过）。"""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    violations: list[str] = []
    for node in ast.walk(tree):
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names = [node.module]
        for name in names:
            top = name.split(".")[0]
            if name in FORBIDDEN_MODULES or top in FORBIDDEN_TOP_LEVEL:
                violations.append(f"{path}: 禁止联网模块导入 {name}")
    return violations


def assert_offline(project_root: Path | None = None) -> dict:
    """扫描整个项目，返回统计；发现违规导入直接抛 OfflineViolation。"""
    if project_root is None:
        project_root = Path(__file__).resolve().parent.parent
    project_root = Path(project_root)
    violations: list[str] = []
    scanned = 0
    for py in sorted(project_root.rglob("*.py")):
        if any(part in {".venv", "__pycache__", ".pytest_cache"}
               for part in py.parts):
            continue
        scanned += 1
        violations.extend(scan_file(py))
    if violations:
        raise OfflineViolation("\n".join(violations))
    return {"scanned_files": scanned, "forbidden_modules": sorted(
        FORBIDDEN_MODULES), "status": "offline-clean"}
