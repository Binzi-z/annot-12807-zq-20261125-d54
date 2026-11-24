# 密钥轮班期间的摊开发送证明（离线演练网关）

在 **完全离线、仅交换合成消息封包** 的前提下，复现并修复“换班断链后旧代
消息重投，两侧发布摘要双双声称已生效”的事故，并提供可由独立进程只读磁盘
复核的承诺集还原与对账工具。仅依赖 **Python 3.12 标准库**，在原生 Windows
上开发运行，不导入任何联网模块（有静态离线守卫生效）。

## 需求与实现对应

| 题面要求 | 实现位置 |
| --- | --- |
| 只交换合成封包、禁用真实联网 | `drill/network.py`（文件 spool 链路）、`drill/offline_guard.py`（AST 静态扫描联网导入） |
| 两个信任根独立批准，同控制链只算一票 | `drill/trust.py`（`ApprovalPolicy` 按控制链去重计票） |
| 批准绑定批次摘要、目的分区、链路代 | `drill/model.py`（`approval_signing_payload` + HMAC-SHA256） |
| 乱序输入（旧批回执、取消决定），按真正落盘先后裁决 | `drill/store.py`（锁内分配 seq 的哈希链日志）、`drill/rules.py` |
| 撤销先落盘 / 已落盘未发回执 / 同编号冲突三场景，两个真实线程屏障复测 | `drill/scenarios.py`（`threading.Barrier(2)` + 20 轮竞争复测） |
| 读磁盘的独立工具还原承诺集合 | `drill/verifier.py` + `tools/verify_disk.py`（独立子进程、只读 `"r"` 打开） |
| 六万条合成封包 + 三个相隔很远的故障分区 | `drill/synthesize.py`、`drill/large_drill.py` |
| 核对局部修订的实际比对范围及全量结果 | `drill/digest.py`（分段摘要、`revise_commitments`、`reconcile`） |

## 目录结构

```
drill/
  model.py         封包类型、规范 JSON、批次/批准摘要
  store.py         追加式哈希链日志 DurableLog、文件线网 WireSpool、原子写
  trust.py         信任根、HMAC 签名、双根异链批准策略、信任清单
  rules.py         按落盘顺序的回放裁决引擎（含无代际围栏的 LegacyRuleEngine）
  digest.py        分段承诺摘要、局部修订、两侧对账（报告实际比对范围）
  gateway.py       单侧网关：入站落盘 -> 重放 -> 原子发布
  network.py       文件线网 FileLink（断链/重连/重投，无 socket）
  scenarios.py     三场景双线程屏障复测
  incident.py      旧代重投事故复现（修复/旧版/混合三种组合）
  synthesize.py    60000 封包确定性合成与远距离故障分区选择
  large_drill.py   大规模演练编排与精确计数断言
  verifier.py      只读磁盘的独立验证核心
  offline_guard.py 联网模块导入静态闸门
tools/verify_disk.py  独立进程 CLI 验证器（退出码 0=PASS, 1=FAIL）
tests/test_drill.py   16 个 unittest 用例
run_all.py            总装运行器
```

## 如何运行

```bash
# 全量测试（含 60000 封包演练、独立子进程验证、双线程场景）
python -m unittest discover -s tests -v

# 总装运行器：离线守卫 -> 三场景 -> 事故复现 -> 60000 演练 -> 独立验证
python run_all.py
python run_all.py --skip-large          # 快速冒烟

# 对任意演练目录单独运行只读独立验证
python tools/verify_disk.py --data-dir artifacts/large --out verify.json
```

## 关键设计

### 1. 落盘顺序即裁决顺序

入站封包先写 `DurableLog`：锁内分配连续 `seq`，每条记录含
`prev` 哈希与自身哈希，形成可逐行校验的哈希链。规则引擎只认 `seq`，
封包内逻辑时间戳无法改变裁决。两个线程谁先抢到日志锁，谁的 `seq` 更小。

### 2. 双根异链批准

每个信任根属于一条 `control_chain`。批准 HMAC 覆盖
`{batch_digest, partition, generation}`；策略统计**不同控制链**数，
同链多根或同根重复只计一票，不足两条独立链的提交被拒绝。

### 3. 链路代围栏与事故根因

`EPOCH` 单调推进链路代；旧代的提交/回执/批准一律拒绝。
`LegacyRuleEngine` 刻意关闭该围栏：断链重连后旧代 `COMMIT` 被重新接受，
两侧都把已轮换批次重新计入承诺集——头摘要**相等却同时错误**。
独立验证器以正确规则重放磁盘日志，即可抓出“发布 2 条 vs 还原 1 条”的
幽灵承诺（见 `artifacts/incident_legacy_verification.json`）。

### 4. 分段摘要与局部修订的比对范围

承诺条目按 `partition` 哈希到 64 个分段，段内排序折叠成段根，段根再
折叠成头摘要。三个故障分区落在 3 个相距很远的分段；局部修订只重算这
3 段（61 段完全不触碰），对账时也只对差异段逐条比对。

## 六万封包演练结果（确定性可复现）

每侧落盘 60000 封包，两侧使用不同乱序种子但封包多重集一致：

| 指标 | 值 |
| --- | --- |
| 生效承诺 | 6050（6500 候选 − 450 取消先落盘） |
| 取消先落盘拒绝 | 450 |
| 同编号冲突拒绝 | 200（先落盘候选仍生效） |
| 无效批准拒绝 | 700（未知根 400 + 绑定替换 300；同链 350 仅作单票） |
| 旧代围栏拒绝 | 850（旧代重投提交 600 + 旧代回执 250） |
| 候选重投幂等 | 781；回执去重 300 |
| 局部修订重算分段 | 3 / 64，重哈希条目 237，占全量约 4.0% |
| 故障对账逐条范围 | 389 条（仅 3 个差异段），远小于全量 6050 |
| 两侧头摘要 | 完全一致；独立子进程验证 verdict=PASS |

原始报告：`artifacts/large/large_drill_report.json`、
`artifacts/large_verification.json`。

## 离线保证

- 运行期不发起任何连接，链路由 JSONL 文件 spool 模拟；
- `offline_guard.assert_offline()` 用 AST 扫描全部源码，导入
  `socket/ssl/http/urllib/requests/...` 等模块即抛 `OfflineViolation`，
  总装运行器与测试均将其作为第一道闸门；
- 全部数据为本地合成，信任清单中的 HMAC 密钥由 `secrets` 现场生成，
  不接触任何真实密钥材料。
