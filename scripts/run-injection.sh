#!/bin/bash
set -e

# Kill any running server
OLD_PID=$(ps aux | grep '[n]ode src/server.js' | awk '{print $2}' | head -1)
if [ -n "$OLD_PID" ]; then
  kill "$OLD_PID" 2>/dev/null || true
  sleep 1
fi

# Remove stale DB
rm -f src/data/novapay.db

# Start server
JWT_SECRET="test_secret_injection_test_only_1234567890abcdef" PORT=9999 node src/server.js > /tmp/novapay.log 2>&1 &
SERVER_PID=$!
echo "Server started with PID $SERVER_PID"

# Wait for server
for i in $(seq 1 10); do
  sleep 1
  if curl -s http://localhost:9999/health > /dev/null 2>&1; then
    echo "Server ready"
    break
  fi
done

# Run injection test
node scripts/injection-test.js 2>&1
RESULT=$?

# Cleanup
kill $SERVER_PID 2>/dev/null || true
exit $RESULT
