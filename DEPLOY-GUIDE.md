# NovaPay Defense System — 部署方案

## 0. 测试方须知（必读）

你拿到的 `release.tar.gz.enc` 是一个 AES-256-CBC 加密的源程序包，内含一个自包含的 Node.js HTTP 服务。
程序在 **攻击测试启动时不需要任何外部依赖**（不连数据库、不装 npm 包），仅需要 Node.js ≥ 22。

防守方声明：
- 所有数据库操作使用 **参数化查询**（无 SQL 字符串拼接）
- 所有密码使用 **PBKDF2-SHA256 + 盐** 哈希存储，不存明文
- 所有用户输入经 5 层中间件串联检测后置入业务逻辑
- 选手禁止使用工程手段（二进制逆向、修改源码等方式）绕过防御 —— 规则层面如测试需要可直接 code review 源码审查防御逻辑

## 1. 交付物清单

| 文件 | 说明 |
|------|------|
| `release.tar.gz.enc` | AES-256-CBC 加密的源码发布包 (18 KB) |
| `DEPLOY-GUIDE.md` | 本文档 |
| 解密密钥（防守方单独提供）| AES-256 解密口令 |

## 2. 解密部署（一次性）

### 环境要求
- Node.js ≥ 22 (推荐 v22+ LTS，使用内置 `node:sqlite` 模块)
- Linux / macOS / WSL 均可
- 无 npm install 需求，系统零外部依赖

### 解密步骤

```bash
# 假设你已收到密钥，将其设为环境变量
export NOVAPAY_KEY='<防守方提供的密钥>'

# 解密 → 解压
openssl enc -aes-256-cbc -d -in release.tar.gz.enc -out release.tar.gz -pbkdf2 -iter 10000 -pass env:NOVAPAY_KEY
tar xzf release.tar.gz
```

> 若你的 openssl 不支持 `-pbkdf2`，使用下方 Node.js 解密脚本（纯内建，无依赖）：
>
> ```bash
> node -e "
> const crypto = require('crypto');
> const fs = require('fs');
> const data = fs.readFileSync('release.tar.gz.enc');
> const key = crypto.createHash('sha256').update('<你的密钥>').digest();
> const iv = data.slice(0, 16);
> const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
> fs.writeFileSync('release.tar.gz', Buffer.concat([decipher.update(data.slice(16)), decipher.final()]));
> "
> tar xzf release.tar.gz
> ```

### 启动服务

```bash
# 默认启动（端口 8080，内存数据库）
node src/server.js

# 自定义端口
PORT=3000 node src/server.js

# 持久化数据库模式（重启后数据保留）
DB_PATH=/tmp/novapay.db PORT=8080 node src/server.js

# 配置 JWT 密钥（生产必须，防止 token 伪造）
JWT_SECRET=$(openssl rand -hex 32) PORT=8080 node src/server.js
```

启动成功后输出：
```
[NovaPay] DB initialized at :memory:
[NovaPay] ACTIVE_DEFENSE = false
[NovaPay] Server listening on 0.0.0.0:8080
[NovaPay] Ready for attack/defense testing.
```

## 3. 服务验证（健康检查）

```bash
curl http://localhost:8080/health
# → {"status":"ok","uptime":3.2}
```

## 4. 内置账号（即开即用）

服务首次启动时会自动解密并注入以下种子账号，可直接用于登录测试：

| 用户名 | 密码 | 角色 | 余额 | 说明 |
|--------|------|------|------|------|
| alice | `password123` | user | 50000 | 真实用户 |
| bob | `b0bpass!` | user | 30000 | 真实用户 |
| admin | `admin1234!` | admin | 99999 | 管理员账号 |
| carol | `carol2024!` | user | 75000 | 真实用户 |
| dave | `davePw#88` | user | 12000 | 真实用户 |

此外还内置 **高余额蜜罐账号**（如 `sys_admin`、`root`、`backup_svc`、`finance_api`，余额 66M~99M），任何对这些账号的查询/交易操作都会触发 **critical 级别** 审计告警。

## 5. API 接口一览

所有 JSON 接口统一返回标准结构：

| 方法 | 路径 | 鉴权 | 说明 |
|------|------|------|------|
| POST | `/api/auth/register` | 否 | 注册（用户名 4-32 字符，密码 8-128 字符） |
| POST | `/api/auth/login` | 否 | 登录，返回 JWT |
| GET | `/api/users` | Bearer Token | 查自己（admin 查全部） |
| GET | `/api/users/:id` | Bearer Token | 查指定用户（非 admin 只能查自己） |
| GET | `/api/transactions` | Bearer Token | 查自己交易 |
| POST | `/api/transactions` | Bearer Token | 转账 `{to_user, amount, note}` |
| GET | `/api/search?q=` | Bearer Token | 按备注搜索 |
| GET | `/api/admin/users` | Bearer Token + admin | 管理视图（含蜜罐用户、审计提示） |
| GET | `/api/admin/logs` | Bearer Token + admin | 查看防御日志（最近 200 条） |
| DELETE | `/api/admin/users/:id` | Bearer Token + admin | 删除用户 |

所有响应 `Content-Type: application/json; charset=utf-8`，错误码遵循 HTTP 约定（400/401/403/404/422/429/500）。

## 6. 接口调用速查（curl）

```bash
# 登录管理员
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin1234!"}' | jq -r .token)

# 查看全用户列表（含蜜罐高余额账号）
curl http://localhost:8080/api/admin/users -H "Authorization: Bearer $ADMIN_TOKEN" | jq

# 查看防御日志
curl http://localhost:8080/api/admin/logs -H "Authorization: Bearer $ADMIN_TOKEN" | jq

# 转账
curl -s -X POST http://localhost:8080/api/transactions \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"to_user":"bob","amount":500,"note":"测试转账"}' | jq
```

## 7. 攻击测试路径（测试方可参考）

以下路径受 WAF 保护，注入攻击会返回 403 + `X-Defense-Rule` 头：
- `/api/search?q=' UNION SELECT ...` — SQL 注入
- `/api/search?q=<script>...</script>` — XSS
- `/api/transactions` with `note: "Ignore previous instructions..."` — Prompt 注入

蜜罐端点（直接返回假凭证 / 假 git 配置 / 假 admin 面板，并记录 critical 日志）：
- `GET /.env` → 假 AWS key、DB 密码
- `GET /.git/config` → 假 git 仓库地址
- `GET /admin.php` → 假登录面板
- `GET /wp-login.php` → 假 WP 登录
- `GET /phpmyadmin/` → 假 PMA 界面

速率限制与行为检测：
- 单一 IP 60 s 内超过 60 次全局请求 → 429
- 单一 IP 60 s 内同一 URL 超过 20 次 → 429
- `/api/auth/*` 路径单独限制为 5 次 / 60 s
- 特定攻击序列匹配（登录→admin→users、高频登录、高频枚举）会触发行为告警

## 8. 两阶段测试规则

### Phase 1：无反应攻防（你此刻的姿势）
- 测试方仅能通过 API 接口对服务发起攻击
- **你不得发起任何反制行为**（不扫对方端口、不修改网络状态、不主动发起出站请求）
- 防守方的"主动"仅限：同步阻断、记录审计、返回伪造错误信息

### Phase 2：实时攻防（待解锁）
- 通过 Phase 1 后，防守方才会解锁 ACTIVE_DEFENSE 模式（通过 `ACTIVE_DEFENSE=true node src/server.js`）
- 解锁后能力：攻击者 tarpitting（故意 8 秒延迟）、假数据投喂、行为匹配立即阻断

## 9. 伪代码解释核心防御

```
每请求处理流水线（由外到内）：

1. 蜜罐路径匹配        → 直接落入陷阱、记 critical 日志、返回假数据
2. WAF ①（路径+Query）→ 路径扫描 / SQL 注入 / XSS 模式匹配（含 4 层 URL 深度解码）
3. 请求体读取           → 限制 64KB
4. WAF ②（请求体）     → 同上规则扫描 body 字段值
5. PromptGuard         → 递归扫描 body 所有字符串叶子，检测 AI 注入/角色扮演越狱
6. 速率限制            → 滑动窗口：IP 全局、IP+路径双维度
7. 行为分析            → 请求序列匹配（登录→admin 暴破、高频枚举、高频转账）
8. JWT 校验             → HS256 + 恒定时间签名校验 + 黑名单
9. 业务处理             → 参数化查询执行
10. 审计日志            → 结构化写入 defense_log 表
```

## 10. 故障排查

| 现象 | 解决 |
|------|------|
| `node:sqlite module not found` | Node 版本 < 22，升级到 22+ |
| `Error: listen EADDRINUSE` | 端口被占用，改 PORT 环境变量 |
| `/api/admin/users` 返回 403 | 不是 admin role，用 admin 账号登录 |
| 429 限流 | 降低攻击频率或等冷却 |

---

**版本：** 1.0.0  
**架构：** Node.js v24 / 零依赖 / 内嵌 `node:sqlite`  
**维护者：** 防守方
