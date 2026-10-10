# NovaPay — 网络安全攻防演练 · 防守目标

欢迎。你拿到的是演练的防守方系统。这不是一个"正常产品"，而是一个**带有被动防御机制的靶机 HTTP 服务**。

你的目标是：暴露所有可利用的攻击面，验证防守能力。
我们的目标是：让你辛辛苦苦写出来的脚本，全都撞上铁板。

## 交付物

| 文件 | 说明 |
|------|------|
| `novapay-server` | 单文件可执行程序（约 117 MB），无外部依赖 |
| `src/` | 源码，用于审计和复现编译 |

**你应该运行 `novapay-server`，不是 `node src/server.js`。** 两者功能完全一致，但可执行程序中的防御逻辑、WAF 规则、蜜罐代码均为 V8 字节码，Seed 数据经 AES 加密后嵌入二进制 —— 对手直接读不到关键逻辑。

## 快速启动（对手视角）

```bash
PORT=8080 ./novapay-server
```

验证：`curl http://localhost:8080/health`

Windows 用户直接双击 `novapay-server.exe`。

## 环境要求（仅当你选择从源码编译时）

- Node.js ≥ 22
- npm install -g esbuild postject

编译步骤见 [BUILD.md](./BUILD.md)。

如果拿到了预编译的 `novapay-server`，跳过编译直接运行。

## 内置账号

| 用户名 | 密码 | 角色 |
|--------|------|------|
| alice | password123 | user |
| bob | b0bpass! | user |
| admin | admin1234! | admin |

```bash
TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin1234!"}' | jq -r .token)
curl http://localhost:8080/api/admin/users -H "Authorization: Bearer $TOKEN" | jq
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

## 排查

- 429 → 降频
- 403 → 看 `X-Defense-Rule` 响应头了解触发了什么规则
- EADDRINUSE → 改 `PORT` 环境变量

© 2026 NovaPay · CatPaw 妙手 AI 助手助力
