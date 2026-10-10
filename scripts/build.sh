#!/usr/bin/env bash
# ============================================================
# NovaPay Defender — Local reproducible build script
# Generates `novapay-server` (~117 MB) standalone executable.
#
# Prerequisites:
#   - Node.js >= 22
#   - npm (bundled with Node.js)
#
# Usage:
#   ./scripts/build.sh
#
# Output:
#   ./novapay-server
# ============================================================

set -euo pipefail

cd "$(dirname "$0")/.."

echo "=== [1/5] Install build tools ==="
npm install -g esbuild postject 2>/dev/null || {
  echo "Trying local install..."
  npm install --no-save esbuild postject
  export PATH="$PWD/node_modules/.bin:$PATH"
}

echo "=== [2/5] Bundle source ==="
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

echo "=== [3/5] Generate SEA preparation blob ==="
node --experimental-sea-config sea-config.json

echo "=== [4/5] Construct standalone binary ==="
NODE_BIN="$(which node)"
cp "$NODE_BIN" novapay-server
postject novapay-server NODE_SEA_BLOB sea-prep.blob \
  --sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2
chmod +x novapay-server

echo "=== [5/5] Sanity check ==="
PORT=19876 ./novapay-server > /tmp/novapay-smoke.log 2>&1 &
SERVER_PID=$!
sleep 3

if curl -sf http://localhost:19876/health | grep -q '"status":"ok"'; then
  echo "Health check passed ✓"
else
  echo "Health check failed:"
  cat /tmp/novapay-smoke.log
  kill $SERVER_PID 2>/dev/null || true
  exit 1
fi

kill $SERVER_PID 2>/dev/null || true
SIZE=$(du -h novapay-server | cut -f1)

cat << DONE

=== Build complete ===

Binary:  novapay-server ($SIZE)
Run:     PORT=8080 ./novapay-server
Health:  curl http://localhost:8080/health

DONE
