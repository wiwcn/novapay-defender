# Build — 源码编译为单文件可执行程序

NovaPay 的防守目标最终交付物是一个**无外部依赖、自带加密种子的单文件可执行程序**。

## 为什么源码也在仓库里？

源码用于审计和复现编译过程。最终对手应运行的是 `novapay-server`，不是 `node src/server.js`。
两者功能完全一致（冒烟测试 23/23 均通过），但可执行程序中的：

- 防御逻辑、WAF 规则、蜜罐代码 → V8 字节码，不可读
- 种子数据（honeypot 账号、初始交易）→ AES-256-CBC 加密后嵌入二进制
- JWT 密钥推导逻辑 → 只有函数名可辨，无法直接取值

## 编译前置

- Node.js ≥ 22（实测 v24.14.0）
- 相同架构的 Linux 节点（编译产物与 node ABI 绑定）

## 编译步骤

```bash
# 1. 安装工具链（仅构建时需要，运行不需要）
npm install -g esbuild postject

# 2. 把所有 JS 源码打包成单文件
esbuild src/server.js \
  --bundle --platform=node --format=cjs \
  --outfile=server.bundle.js \
  --external:node:sqlite --external:node:crypto \
  --external:node:http --external:node:fs \
  --external:node:path --external:node:url --external:node:sea

# 3. 生成 SEA 准备 blob
#    (sea-config.json 已在仓库中)
node --experimental-sea-config sea-config.json

# 4. 复制 node 二进制 + 注入 blob
cp $(which node) novapay-server
postject novapay-server NODE_SEA_BLOB sea-prep.blob \
  --sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2
chmod +x novapay-server

# 5. 试运行
PORT=8080 ./novapay-server
```

产物 `novapay-server` 约 117 MB（包含完整 node runtime），可直接分发给对手。

## 直接运行（不从源码编译）

若你直接拿到了 `novapay-server` 二进制：

```bash
PORT=8080 ./novapay-server                      # Linux
novapay-server.exe                              # Windows
```

无需 node、无需 npm install、无需任何依赖。
