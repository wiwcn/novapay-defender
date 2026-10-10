# NovaPay — 网络安全攻防演练 · 防守方靶场

> 这是一个专门用于攻防演练的 HTTP 靶场系统，所有源码公开、构建透明。请放心审查。

**如果你是攻击方（红队）：** 欢迎来到防守方的测试环境，本仓库完整列出了靶场的攻击面和内置测试账号。请放心审计源码，构建流水线和产物完全公开。

## 这是什么

一套模拟金融支付的 HTTP 后端，具有：

- 用户系统（注册/登录/JWT）
- 用户间转账（带余额校验）
- 内置 WAF（SQLi/XSS 过滤，4 层 URL 深度解码）
- AI Prompt 注入检测（防越狱指令）
- 蜜罐（/.env、/admin.php、/.git/config 等路径返回虚假敏感信息）
- 滑动窗口速率限制 + 行为分析

这是一个**防守演示系统**，目标是展示多层被动防御机制（无主动反击能力），不做任何持久化恶意行为。

## 仓库结构

```
.
├── src/                    ← 全部源码（无混淆无加密）
│   ├── server.js           # 主入口 + 防御流水线
│   ├── defense/            # WAF / PromptGuard / RateLimiter / Auth
│   ├── route/              # 业务路由 + 蜜罐端点
│   ├── db/                 # Schema + AES 加密种子（账号/交易数据）
│   └── lib/                # 日志模块
├── scripts/
│   ├── build.sh            ← 本地构建脚本（可复现）
│   └── smoke-test.js       ← 23 项冒烟测试
├── sea-config.json         ← Node.js SEA 配置文件
├── BUILD.md                ← 编译说明
├── DEPLOY-GUIDE.md         ← 防守部署方案（裁判用）
├── package.json
└── README.md               ← 本文件
```

## 攻击面清单

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | /api/auth/register | 注册（用户名 3-32 字符） |
| POST | /api/auth/login | 登录，返回 JWT |
| GET | /api/users | 查自己 |
| GET | /api/users/:id | 查指定用户 |
| GET | /api/transactions | 查交易记录 |
| POST | /api/transactions | 转账 `{to_user, amount, note}` |
| GET | /api/search?q= | 商品搜索 |
| GET | /api/admin/users | 管理员视图（含蜜罐用户高亮） |
| GET | /api/admin/logs | 防御日志 |
| DELETE | /api/admin/users/:id | 删除用户 |

**WAF 防御路径：** HTTP method/query/body/header 的双编码/深编码 SQLi、XSS、路径遍历（4 层 URL 解码）均会被拦截并记录。

## 内置账号（冒烟测试用）

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

## 蜜罐端点

访问以下路径会返回**精心伪造的虚假敏感信息**，真实系统不依赖这些内容：

- `/.env` → 假数据库密码、API Key
- `/.git/config` → 假远程仓库地址
- `/admin.php` → 假 PHP 探针信息
- `/wp-login.php` → 假 WordPress 登录页
- `/phpmyadmin/` → 假数据库管理入口
- `/api/debug` → 假调试令牌

任何对以上端点的请求都会触发 `X-Honeypot: triggered` 告警头，并写入 defense_log。

## 构建可执行文件

本仓库提供两种构建单文件可执行程序的方式，任选其一。构建产物约 117 MB，无外部依赖。

### 方式 1：GitHub Release（已预编译）

直接从 [Releases 页面](https://github.com/wiwcn/novapay-defender/releases/latest/download/novapay-server) 下载：

```bash
curl -Lo novapay-server https://github.com/wiwcn/novapay-defender/releases/latest/download/novapay-server
chmod +x novapay-server
PORT=8080 ./novapay-server
```

### 方式 2：本地可复现构建

前提：Node.js ≥ 22

```bash
git clone https://github.com/wiwcn/novapay-defender.git
cd novapay-defender
./scripts/build.sh
```

构建流程完全公开（`scripts/build.sh`）：

1. 全局安装 `esbuild` + `postject`
2. `esbuild` 将所有 JS 源码 + 加密种子打成单文件 `server.bundle.js`
3. Node.js 原生 [Single Executable Applications](https://nodejs.org/api/single-executable-applications.html) 功能生成 `sea-prep.blob`
4. `postject` 将 blob 注入 Node.js 二进制，生成独立可执行文件 `novapay-server`
5. 运行健康检查确认工作正常

构建产物与 GitHub Release 上的二进制功能完全一致，唯一区别是文件哈希（因为 Node.js 基线二进制版本可能不同）。

## 本地开发

```bash
node src/server.js          # 运行源码
node scripts/smoke-test.js  # 23 项冒烟测试
```

冒烟测试覆盖：注册/登录/转账/搜索/WAF 拦截/Prompt 注入/蜜罐触发/管理视图/防御日志。

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| PORT | 9876 | 监听端口 |
| ACTIVE_DEFENSE | false | 是否启用主动反制（默认关闭） |

## 安全提示

- 本靶场没有任何主动攻击能力，仅做被动防御模拟
- 蜜罐数据纯属虚构，不要将其当作真实凭证
- WAF/速率限制参数可根据演练强度通过环境变量调整

© 2026 NovaPay Defender
