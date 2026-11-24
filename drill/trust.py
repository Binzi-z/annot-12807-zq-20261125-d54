"""信任根与批准策略。

信任模型
========
- 演练里配置两个（可更多）相互独立的信任根，每个根属于一条独立
  ``control_chain``（控制链），各自持有独立 HMAC 密钥。
- 候选批次的发送必须取得 **两个不同信任根** 的批准；同一控制链上
  多个根（或同一根重复签名）只能算一票——“同控制链的批准只能算一个”。
- 批准签名覆盖：批次摘要、目的分区、链路代（见
  ``model.approval_signing_payload``），三者任一不匹配即视为无效批准。
- 密钥材料只写在本地演练目录的 trust_manifest 中，全部为合成数据，
  不接触任何真实密钥或网络。
"""

from __future__ import annotations

import hmac
import json
import secrets
from dataclasses import dataclass, field
from pathlib import Path

from .model import approval_signing_payload, digest_obj
from .store import atomic_write_text


@dataclass(frozen=True)
class TrustRoot:
    root_id: str
    control_chain: str
    key: bytes

    def sign(self, b_digest: str, partition: str, generation: int) -> str:
        msg = approval_signing_payload(b_digest, partition, generation)
        return hmac.new(self.key, msg, "sha256").hexdigest()

    def verify(self, b_digest: str, partition: str, generation: int,
               signature: str) -> bool:
        msg = approval_signing_payload(b_digest, partition, generation)
        expected = hmac.new(self.key, msg, "sha256").hexdigest()
        return hmac.compare_digest(expected, signature)


@dataclass
class TrustManifest:
    """信任根清单：独立工具只读此文件即可复核所有批准签名。"""

    roots: list[TrustRoot] = field(default_factory=list)

    def root(self, root_id: str) -> TrustRoot | None:
        for r in self.roots:
            if r.root_id == root_id:
                return r
        return None

    def to_jsonable(self) -> dict:
        return {
            "roots": [
                {"root_id": r.root_id,
                 "control_chain": r.control_chain,
                 "key_hex": r.key.hex()}
                for r in self.roots
            ],
            "manifest_digest": "",
        }

    def save(self, path: Path) -> None:
        obj = self.to_jsonable()
        obj["manifest_digest"] = digest_obj(
            [{"root_id": r.root_id, "control_chain": r.control_chain,
              "key_hex": r.key.hex()} for r in self.roots])
        atomic_write_text(path, json.dumps(obj, sort_keys=True,
                                           ensure_ascii=False, indent=2))

    @classmethod
    def load(cls, path: Path) -> "TrustManifest":
        with open(path, "r", encoding="utf-8") as fh:
            obj = json.load(fh)
        roots = [TrustRoot(r["root_id"], r["control_chain"],
                           bytes.fromhex(r["key_hex"]))
                 for r in obj["roots"]]
        return cls(roots)


def make_synthetic_manifest(chain_a: str = "chain-alpha",
                            chain_b: str = "chain-beta") -> TrustManifest:
    """生成两条独立控制链、各一个信任根的合成清单。"""
    return TrustManifest([
        TrustRoot("root-A1", chain_a, secrets.token_bytes(32)),
        TrustRoot("root-B1", chain_b, secrets.token_bytes(32)),
    ])


@dataclass
class ApprovalVote:
    root_id: str
    control_chain: str
    valid: bool


@dataclass
class QuorumDecision:
    """双根异链批准裁决结果。"""

    satisfied: bool
    distinct_chains: tuple[str, ...]
    distinct_roots: tuple[str, ...]
    rejected: list[dict]          # 无效/重复批准及原因
    reason: str = ""

    def as_dict(self) -> dict:
        return {
            "satisfied": self.satisfied,
            "distinct_chains": list(self.distinct_chains),
            "distinct_roots": list(self.distinct_roots),
            "rejected": self.rejected,
            "reason": self.reason,
        }


class ApprovalPolicy:
    """对某一批次收集到的全部批准封包做双根异链裁决。"""

    def __init__(self, manifest: TrustManifest, *,
                 required_chains: int = 2) -> None:
        self.manifest = manifest
        self.required_chains = required_chains

    def evaluate(self, b_digest: str, partition: str, generation: int,
                 approvals: list[dict]) -> QuorumDecision:
        seen_roots: set[str] = set()
        chains: set[str] = set()
        rejected: list[dict] = []

        for apr in approvals:
            root_id = apr.get("root_id", "")
            sig = apr.get("signature", "")
            root = self.manifest.root(root_id)

            if root is None:
                rejected.append({"root_id": root_id,
                                 "reason": "unknown_root"})
                continue
            # 签名必须同时绑定批次摘要、目的分区、链路代
            if not root.verify(b_digest, partition, generation, sig):
                rejected.append({"root_id": root_id,
                                 "reason": "bad_signature_or_binding"})
                continue
            if root_id in seen_roots:
                # 同一根重复批准：只算一票
                rejected.append({"root_id": root_id,
                                 "reason": "duplicate_root_single_vote"})
                continue
            seen_roots.add(root_id)
            before = len(chains)
            chains.add(root.control_chain)
            if len(chains) == before:
                # 同控制链的批准只能算一个
                rejected.append({
                    "root_id": root_id,
                    "control_chain": root.control_chain,
                    "reason": "same_control_chain_single_vote",
                })

        satisfied = len(chains) >= self.required_chains
        reason = "" if satisfied else (
            f"需要 {self.required_chains} 条独立控制链批准，"
            f"实际 {len(chains)} 条")
        return QuorumDecision(
            satisfied=satisfied,
            distinct_chains=tuple(sorted(chains)),
            distinct_roots=tuple(sorted(seen_roots)),
            rejected=rejected,
            reason=reason,
        )


def manifest_fingerprint(manifest: TrustManifest) -> str:
    """供发布摘要引用的信任清单指纹。"""
    return digest_obj([
        {"root_id": r.root_id, "control_chain": r.control_chain,
         "key_hex": r.key.hex()} for r in manifest.roots
    ])
