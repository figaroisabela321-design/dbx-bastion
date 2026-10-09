# TEST HANDOFF — TASK-005C (Bastion Web) for Grok Bot

> **Status honesty contract:** every item below is marked 未执行 / 通过 / 失败
> based on actual runs in the Muse dev environment. Nothing not executed
> is marked as passed.

## 1. Git 基线

- **Branch:** `feature/bastion-web-firewall`
- **Base:** `e35625707` (TASK-005A/005B security close-out)
- **Commits (oldest → newest):**

| SHA | Subject | Status |
|-----|---------|--------|
| `7f74e41f1` | WIP: TASK-005C-1 bastion mode + default-deny firewall (UNVERIFIED) | WIP — code complete, tests not executed |
| `387b9c730` | TASK-005C-2: Bastion Session + Asset/Connection Adapter | code complete, `cargo check` clean |
| `9b062ccc3` | TASK-005C-3: Real DBX QueryExecutor | code complete, `cargo check` clean |
| `7851b1ec6` | TASK-005C-4: QueryGateway HTTP API + controlled audit recovery | code complete, `cargo check` clean |

- **Upstream:** `t8y2/dbx` (origin) — **never push here.** Work lives on the
  feature branch; PR target is the private fork when available.

## 2. 构建依赖及资源要求

- Rust stable (1.99.0 in dev env), `~/.cargo/bin` on PATH.
- **Critical:** linking the `dbx-web` test binary needs **~6 GB peak RSS**
  for a single `rustc` invocation. The dev VM (7.7 GB RAM, 0 swap) cannot
  complete it — `rustc` was SIGKILLed twice (once at `-j 2` after 82 min,
  once at `-j 1` after 30+ min at 5.9 GB RSS).
- **Recommendation:** run the full suite on a machine with ≥16 GB RAM
  (or ≥8 GB + swap). Low-memory flags used in dev:
  `CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0`
- `cargo check -p dbx-web --test bastion_firewall -j 1` **did pass**
  (162 s, 0 errors, 2.6 GB peak) — code compiles; only the final link
  of the test binary OOMs.

## 3. 验证命令

```bash
export PATH="$HOME/.cargo/bin:$PATH"
export CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0

cargo fmt --check                                        # 通过 (dev)
cargo check -p dbx-bastion -j 1                          # 通过 (dev)
cargo check -p dbx-web -j 1                              # 通过 (dev)
cargo check -p dbx-web --test bastion_firewall -j 1      # 通过 (dev, 162s)
cargo test -p dbx-bastion -j 1                           # 通过 (dev, 204/204)
cargo test -p dbx-web --test bastion_firewall -j 1       # 未执行 (OOM, 需高内存环境)
cargo clippy -p dbx-web --all-targets -- -D warnings     # 未通过 — 阻塞在未动的
                                                         # dbx-driver-postgres 的 3 处旧
                                                         # chunks_exact lint (超出 scope)
```

## 4. Bastion Mode 启动方法

```bash
DBX_BASTION_MODE=1 \
DBX_DATA_DIR=/tmp/bastion-e2e \
DBX_PORT=8080 DBX_BIND_ADDR=127.0.0.1 \
./target/debug/dbx-web
```

- 非法 `DBX_BASTION_MODE` 值 → 拒绝启动 (exit non-zero, stderr 说明).
- `DBX_BASTION_MODE=1` + `DBX_DISABLE_PASSWORD=1` → 拒绝启动.
- 数据目录安全检查 (Unix): 须为 euid 所有、0700 或更严、
  非符号链接、上级目录为 euid/root 所有且不可 group/other 写；
  否则 STARTUP_FAILED。非 Unix → 明确拒绝启动。
- 单实例: `bastion.lock` fs2 独占锁；第二实例 fail-fast。
- `GET /api/bastion/health`, `GET /api/bastion/status` 无需认证。

## 5. 安全测试环境变量

| 变量 | 默认 | 说明 |
|------|------|------|
| `DBX_BASTION_MODE` | unset→legacy | `1`/`true`/`bastion` 启用 |
| `DBX_BASTION_SQL_EXECUTION_ENABLED` | `false` | 真实 SQL 执行总开关；不绕过任何安全检查 |
| `DBX_BASTION_ALLOW_INSECURE_COOKIE` | `false` | 设为 1 允许非 Secure cookie (仅非 TLS 开发测试) |
| `DBX_PUBLIC_BASE_PATH` | `/` | 非法值 → 可诊断的启动错误 (非 panic) |
| `DBX_DATA_DIR` | `~/.dbx-web` | bastion 数据在 `$DBX_DATA_DIR/bastion` |

## 6. 测试数据库配置

- **SQLite:** 需一个可写的 SQLite 文件路径用于资产映射的 `dbx_connection_id`
  指向的 DBX connection。DBX 的 connection 配置来自
  `$DBX_DATA_DIR/dbx.db` (legacy storage) 的 `load_connections()`。
- **MySQL / PostgreSQL:** 005C-3 的 `driver_supported()` 仅放行
  `mysql`/`postgres` (有 proven 的 KILL QUERY / cancel request 中断)。
  其他驱动 (sqlite, mssql, oracle, …) 在执行层明确拒绝，需 Grok
  验证其中断/限制/隔离后才能放行。
- 在隔离非生产环境中将 `DBX_BASTION_SQL_EXECUTION_ENABLED=1` 显式开启
  后再测真实执行。

## 7. 测试清单

### 7a. dbx-bastion (已执行)

| Suite | 结果 |
|-------|------|
| lib (17) | 通过 |
| assets (23) | 通过 |
| auth (32) | 通过 |
| bootstrap (4) | 通过 |
| query_analyzer (50) | 通过 |
| query_policy (13) | 通过 |
| query_gateway (25) | 通过 |
| rbac (40) | 通过 |
| **合计** | **204/204 通过** (首次全量跑时有 1 个 flaky 失败，重跑通过) |

### 7b. dbx-web bastion_firewall 集成测试 (未执行 — 需高内存环境)

| # | 测试 | 覆盖 | 状态 |
|---|------|------|------|
| 1 | bastion_health_and_status | health/status 可达 | 未执行 |
| 2 | bastion_denies_legacy_query_routes | 旧 query 路由拒绝 | 未执行 |
| 3 | bastion_denies_data_routes | import/export/transfer/schema 拒绝 | 未执行 |
| 4 | bastion_denies_ai_and_mcp_and_ws | AI/MCP/WS/legacy auth 拒绝 | 未执行 |
| 5 | bastion_firewall_method_and_encoding | method/编码/尾斜杠防火墙 | 未执行 |
| 6 | old_cookie_grants_nothing | 旧 dbx_session cookie 无权限 | 未执行 |
| 7 | disable_password_conflicts_refuses_startup | DISABLE_PASSWORD 冲突拒绝启动 | 未执行 |
| 8 | invalid_mode_refuses_startup | 非法 mode 拒绝启动 | 未执行 |
| 9 | bastion_init_failure_does_not_fall_back_to_legacy | 初始化失败不回退 | 未执行 |
| 10 | untriaged_audit_starts_degraded | 孤立 STARTED → degraded | 未执行 |
| 11 | second_instance_cannot_share_audit_db | 实例锁互斥 | 未执行 |
| 12 | legacy_mode_still_serves_auth_check | legacy 回归 | 未执行 |
| 13 | bastion_dir_0755_refuses_startup | 目录 0755 拒绝 | 未执行 |
| 14 | bastion_dir_0777_refuses_startup | 目录 0777 拒绝 | 未执行 |
| 15 | bastion_dir_symlink_refuses_startup | 符号链接拒绝 | 未执行 |
| 16 | bastion_secure_dir_starts_normally | 安全目录正常启动 | 未执行 |
| 17 | illegal_base_path_refuses_startup | 非法 base_path 拒绝 (5 种值) | 未执行 |
| 18 | legal_base_path_prefix_serves | 合法前缀服务 | 未执行 |
| 19 | base_path_trailing_slash_normalized | 尾斜杠规范化 | 未执行 |
| — | (18 内含) 模糊前缀/编码穿越拒绝 | 防火墙防绕过 | 未执行 |

### 7c. 需 Grok 在高内存环境补充的手动/E2E 验证

- [ ] Session 登录/登出/me 全流程；撤销后立即 401
- [ ] RBAC ALLOW / DENY / 默认拒绝 (通过资产授权配置)
- [ ] 平台管理员调用资产视图仍受 CONNECT 门禁 (无隐含数据权限)
- [ ] SQL AST 各方言行为 (沿用 005A 的 analyzer 测试)
- [ ] 真实 SQL SELECT (mysql/postgres, 非生产资产, 开关开启)
- [ ] 真实 DML 被 policy 拒绝或要求审批 (按环境)
- [ ] QueryGateway 全链路审计: STARTED→SUCCEEDED / FAILED / BLOCKED
- [ ] 超时 → UNKNOWN_INTERRUPTED；取消 → 已确认取消
- [ ] 旧 DBX API (query/script/tx/2pc/import/export/transfer) 在 bastion 模式不可达
- [ ] MCP/AI SQL tools 在 bastion 模式不可达 (未挂载 /mcp)
- [ ] 审计中断 → DEGRADED；triage 恢复流程 (admin + reason + evidence)
- [ ] 生产资产默认拒绝 (Environment::Production)
- [ ] 数据目录权限/属主/符号链接/上级目录 (集成测试 13–16)
- [ ] Legacy Mode 兼容性 (测试 12)

## 8. CI 失败后的修复和回归流程

1. 在 ≥16 GB 内存机器上复现: `cargo test -p dbx-web --test bastion_firewall -j 1`.
2. 失败分类: (a) bastion 代码问题 → 在 feature 分支修复并追加提交；
   (b) 环境/依赖问题 → 记录在本文件，不修改生产代码换取通过；
   (c) flaky → 重跑 3 次确认。
3. 不得删除安全检查、放宽 RBAC、跳过审计、用旧 DBX handler 替代。
4. 修复后重新跑 `cargo test -p dbx-bastion` (204) + 受影响的集成测试。

## 9. 已知风险 (供审查)

- **未验证即合并风险:** 005C-1/2/3/4 的 HTTP 层从未实际运行过；
  编译正确 ≠ 行为正确。Grok 的 E2E 是正式验收前的必需步骤。
- **驱动支持矩阵:** 仅 mysql/postgres 放行；其他驱动拒绝执行是
  有意为之的 fail-closed，不是功能缺失。
- **`dbx-driver-postgres` 的 clippy 旧问题** 会阻塞 `-D warnings`
  全量门禁；与本次改动无关，不建议在本轮顺手修。
- **Cookie Secure:** 默认 Secure；非 TLS 部署必须显式
  `DBX_BASTION_ALLOW_INSECURE_COOKIE=1` (会打 warn 日志)。
- **首次启动需创建 bastion 管理员:** 通过 `AdminBootstrap`
  (见 `crates/dbx-bastion/src/auth/bootstrap.rs`)；测试环境需先 bootstrap。
- **TASK-005D** 安全验收尚未开始；本轮目标是功能代码完成，
  不是宣称生产安全。
