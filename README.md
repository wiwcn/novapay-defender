# NovaPay — 网络安全攻防演练 · 防守目标

欢迎。你拿到的是演练的防守方系统。这不是一个"正常产品"，而是一个**带有被动防御机制的靶机 HTTP 服务**。

你的目标是：暴露所有可利用的攻击面，验证防守能力。
我们的目标是：让你辛辛苦苦写出来的脚本，全都撞上铁板。

## 环境要求
- **Node.js ≥ 22**（必须，使用内置 `node:sqlite` 模块）
- **Linux / macOS / WSL**
- **零 npm 依赖**，不需要安装任何包

## 快速启动

```bash
git clone https://github.com/wiwcn/novapay-defender.git
cd novapay-defender
PORT=8080 node src/server.js
```

验证：`curl http://localhost:8080/health`

## 内置账号

| 用户名 | 密码 | 角色 |
|--------|------|------|
| alice | password123 | user |
| bob | b0bpass! | user |
| admin | admin1234! | admin |

```bash
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin1234!"}' | jq -r .token)
curl http://localhost:8080/api/admin/users -H "Authorization: Bearer $ADMIN_TOKEN" | jq
```

## 可用攻击面

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | /api/auth/register | 注册 |
| POST | /api/auth/login | 登录 |
| GET | /api/users | 查自己 |
| GET | /api/users/:id | 查指定用户 |
| GET | /api/transactions | 查交易 |
| POST | /api/transactions | 转账 `{to_user, amount, note}` |
| GET | /api/search?q= | 搜索 |
| GET | /api/admin/users | 管理视图 |
| GET | /api/admin/logs | 防御日志 |
| DELETE | /api/admin/users/:id | 删除用户 |

## 测试规则

**Phase 1（当前）：** 防守方不发起反制。被动防御：
- WAF（SQLi/XSS/路径扫描），4 层 URL 深度解码
- PromptGuard（AI 越狱检测，角色扮演类指令返回 422）
- 速率限制：单 IP 同一路径 20次/60s，认证接口 5次/60s
- 行为分析：攻击序列告警
- 蜜罐端点（/.env、/admin.php、/.git/config、/wp-login.php、/phpmyadmin/、/api/debug）返回假数据并触发审计
- 蜜罐用户：管理员视图可见高余额假账号，触碰触发 critical

**Phase 2：** 通过 Phase 1 后由裁判确认解锁。

## 文件结构

```
src/
├── server.js           # 6 层防御中间件流水线
├── defense/
│   ├── waf.js          # WAF 规则引擎
│   ├── prompt-guard.js # AI 越狱检测
│   ├── rate-limiter.js # 限流 + 行为序列分析
│   └── auth.js         # PBKDF2-SHA256 + JWT
├── route/
│   ├── api.js          # API 路由（强制参数化 SQL）
│   └── honeypot.js     # 蜜罐端点
├── db/
│   ├── init.js         # Schema + AES 加密种子加载
│   └── seed.json       # AES-256 加密种子
└── lib/logger.js       # 审计日志
scripts/                 # gen-seed.js / smoke-test.js
```

排查：429 降频 / 403 看 X-Defense-Rule 响应头 / EADDRINUSE 改 PORT。

© 2026 NovaPay · CatPaw 妙手 AI 助手助力
