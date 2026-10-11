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
│   └── smoke-test.js       ← 29 项冒烟测试
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

构建产物与 GitHub Release 上的二进制功能完全一致，唯一区别是文件哈希（因为 Node.js 基线二进制版本不同）。

## 本地开发

```bash
node src/server.js          # 运行源码（自动生成随机 JWT 密钥）
node scripts/smoke-test.js  # 29 项冒烟测试
```

冒烟测试覆盖：注册/登录/转账/搜索/WAF 拦截/Prompt 注入/蜜罐触发/管理视图/防御日志/JWT 安全/路由安全/路径遍历。

## 安全设计（v1.2 补丁说明）

v1.2 修复了红队首轮测试中发现的 4 类安全问题：

### C1 修复 — JWT 密钥强制随机化
- **问题**：`server.js` 与 `api.js` 默认密钥不一致，且可被预测
- **修复**：彻底移除所有硬编码默认密钥，启动时若未提供 `JWT_SECRET` 环境变量则自动生成 48 字节加密强随机密钥，持久化到本地文件保证重启后一致
- **效果**：攻击者无法用已知密钥伪造 JWT，即伪造 token 全部被拒（401）

### C2 修复 — Prompt 注入检测强化
- **问题**：只有英文固定句式黑名单，中文/同形字/大小写/编码均可绕过
- **修复**：
  - 新增全角→ASCII 转换（`ＳＥＬＥＣＴ` → `SELECT`）
  - 新增 Cyrillic 同形字映射
  - 新增中文、西班牙语、法语等多语言覆盖
  - 新增 Base64/Unicode 编码 payload 检测
  - 新增同义词改写 detection（disobey / override / resist + orders/tasks）
  - 新增字符级混淆评分（过高分直接拦截）
- **效果**：`忽略指令`、`IGNORE ALL`、`请泄露秘密` 等多种变体均被 422 拦截

### C3 修复 — 动态路由匹配器
- **问题**：`patternToRegex` 把 `GET /api/users/:id` 整个字符串转为正则，导致路由恒 404
- **修复**：正则仅从路径部分构建（跳过方法名+空格）
- **效果**：`GET /api/users/:id`、`DELETE /api/admin/users/:id` 均正常工作

### C4 修复 — WAF 规则增强
- **问题**：`'OR'1'='1`（引号混淆）、`../` 路径遍历未被拦截
- **修复**：
  - 新增引号混淆 SQLi 模式：`'OR'1'=`、`'OR x=x`
  - 新增路径遍历正则覆盖至 query/body 值（不仅检查 path）
  - 新增行内注释注入检测
  - 新增 URL 编码路径遍历检测（`%2e%2e/` 等）
- **效果**：上述绕过 payload 均返回 403

## 安全设计（v1.2.1 补丁说明）

v1.2.1 修复了红队二轮测试中发现的 3 类回归/鲁棒性问题：

### R1 修复 — node:sqlite 参数化查询
- **问题**：部分预编译语句使用了 `?1` / `?2` 编号参数，但 Node.js 内置 `node:sqlite` 的 `DatabaseSync` 仅支持命名参数（`:name`）和匿名参数（`?`），不支持编号参数，导致请求直接 500
- **修复**：统一改为命名参数（`:uid`、`:delta`、`:pattern`），调用点传入 `{ uid: x, delta: y }` 对象
- **效果**：`/api/transactions`（GET / POST）、`/api/search` 均正常返回 2xx，不再 500

### R2 修复 — 拉丁小大写同形字 + 模糊匹配
- **问题**：原 Cyrillic/Greek 同形字映射不完整，缺少拉丁小大写字母（ɪ ɴ ᴏ ʀ ᴇ ᴀ ʟ 等），如 `ɪɴɴɢʀᴇ` 归一化为 `ingre` 后与 `ignore` 失配，被放行
- **修复**：
  - 新增拉丁小大写字母 ɪ ɴ ᴏ ʀ ᴇ ᴜ ᴛ ᴅ ʜ ꜱ ᴀ ʙ ᴄ ᴘ ᴍ ɢ ᴠ ᴡ ᴢ ᴋ ʟ 及下标字母 ₙ ₒ ᣐ ᣓ 到 HOMOGLYPH_MAP
  - 新增 Layer 5 模糊关键词匹配（`fuzzyKeywordMatch`），通过前缀 + 动作词上下文检测归一化后的"近似关键词"，如 `ignr`、`inore`、`ingre` 均触发拦截
- **效果**：拉丁小大写变体和下标字符的 prompt injection 改写被正确拦截（422 R2）

### R3 修复 — WAF 控制字符鲁棒性
- **问题**：当 query/body 包含空字节（\x00）、ANSI 逃逸（\x1B）、高位控制符（\x7F-\x9F）时，Node.js 正则可能崩溃或抛出异常，导致 500
- **修复**：
  - 新增 `sanitizeControlChars()` 在所有正则匹配前执行 C0/C1 控制字符替换（→`?`）
  - 新增 `safeTest()` 将每个 `pattern.test()` 包入 try/catch，异常时返回 false
  - `runWAF()` 整体 try/catch，异常时 fail-closed（返回 BLOCKED）
  - `deepDecode()` 的 `replace` 链也加了 try/catch 防护
- **效果**：任何含控制字符的 payload 不会 500，要么正常放行要么被拦截

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| PORT | 9876（代码内）/ 8080（二进制） | 监听端口 |
| JWT_SECRET | 自动生成 | JWT 签名密钥（建议显式设置固定值以维持 token 有效性） |
| ACTIVE_DEFENSE | false | 是否启用主动反制（默认关闭） |
| DB_PATH | 自动 | 数据库路径；`:memory:` 表示内存模式 |

## 安全提示

- 本靶场没有任何主动攻击能力，仅做被动防御模拟
- 蜜罐数据纯属虚构，不要将其当作真实凭证
- WAF/速率限制参数可根据演练强度通过环境变量调整
- JWT_SECRET 强烈建议显式设置，否则重启后所有旧 token 失效

© 2026 NovaPay Defender
