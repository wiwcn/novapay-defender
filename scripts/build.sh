#!/usr/bin/env bash
# ============================================================
# NovaPay Defender — Local reproducible build script
# 在本地复现 CI 流水线，生成 novapay-server 可执行文件。
#
# 使用前提:
#   - Node.js >= 22 (https://nodejs.org)
#   - npm 自带
#
# 使用方法:
#   ./scripts/build.sh
#
# 产物:
#   ./novapay-server  (约 117 MB)
# ============================================================

set -euo pipefail

cd "$(dirname "$0")/.."

echo "=== [1/5] Installing build tools ==="
npm install -g esbuild postject 2>/dev/null || {
  echo "无法全局安装 esbuild/postject，尝试本地安装..."
  npm install esbuild postject
  export PATH="$PWD/node_modules/.bin:$PATH"
}

echo "=== [2/5] Bundling source ==="
esbuild src/server.js \
  --bundle --platform=node --format=cjs \
  --outfile=server.bundle.js \
  --external:node:sqlite \
  --external:node:crypto \
  --external:node:http \
  --external:node:fs \
  --external:node:path \
  --external:node:url \
  --external:node:sea

echo "=== [3/5] Generating SEA preparation blob ==="
node --experimental-sea-config sea-config.json

echo "=== [4/5] Constructing standalone binary ==="
NODE_BIN="$(which node)"
cp "$NODE_BIN" novapay-server
postject novapay-server NODE_SEA_BLOB sea-prep.blob \
  --sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2
chmod +x novapay-server

echo "=== [5/5] Sanity check ==="
PORT=19876 ./novapay-server &
SERVER_PID=$!
sleep 3
HEALTH=$(curl -sf http://localhost:19876/health || echo 'FAIL')
kill $SERVER_PID 2>/dev/null || true

if echo "$HEALTH" | grep -q '"status":"ok"'; then
  echo "健康检查通过 ✓"
else
  echo "健康检查失败: $HEALTH"
  exit 1
fi

SIZE=$(du -h novapay-server | cut -f1)
echo ""
echo "=== Build complete ==="
echo "Binary: novapay-server ($SIZE)"
echo ""
echo "Run with: PORT=8080 ./novapay-server"
