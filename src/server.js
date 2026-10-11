'use strict';

/**
 * NovaPay Defense — main entry.
 * HTTP server with defense middleware pipeline.
 *
 * Deployment:  node src/server.js
 * Environment:  PORT (default 8080), DB_PATH (default ./data/novapay.db),
 *               JWT_SECRET (required in production; auto-generated in development),
 *               NODE_ENV (development|production), ACTIVE_DEFENSE (true|false)
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { initDatabase, loadSeed } = require('./db/init');
const { createLogger } = require('./lib/logger');
const { createApiRouter } = require('./route/api');

const PORT = Number(process.env.PORT) || 8080;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data', 'novapay.db');
const ACTIVE_DEFENSE = (process.env.ACTIVE_DEFENSE || 'false').toLowerCase() === 'true';

// --- JWT Secret: secure by default ---
// Priority: env var > persisted random file > auto-generated (with warning)
// No hardcoded default — the server ALWAYS uses a strong secret.
const SECRET_FILE = path.join(__dirname, 'data', '.jwt_secret');
let JWT_SECRET = process.env.JWT_SECRET || null;

if (!JWT_SECRET) {
  // Try to load from persisted file (survives restarts)
  try {
    if (fs.existsSync(SECRET_FILE)) {
      JWT_SECRET = fs.readFileSync(SECRET_FILE, 'utf8').trim();
    }
  } catch {}
}

if (!JWT_SECRET) {
  // Generate a cryptographically strong random secret (no hardcoded fallback)
  JWT_SECRET = crypto.randomBytes(48).toString('hex');
  // Persist so it survives restarts (same secret across restarts)
  try {
    fs.mkdirSync(path.dirname(SECRET_FILE), { recursive: true });
    fs.writeFileSync(SECRET_FILE, JWT_SECRET, { mode: 0o600 });
  } catch {}
  console.warn('[JWT] Generated a random JWT secret. Set JWT_ENV env var for a fixed secret.');
}

// --- Init DB ---
if (DB_PATH !== ':memory:') {
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
}
const db = initDatabase(DB_PATH);
loadSeed(db);

const logger = createLogger(db);
// Pass the resolved secret to the router (single source of truth)
const { handler: apiHandler } = createApiRouter(db, logger, JWT_SECRET);

console.log(`[NovaPay] DB initialized at ${DB_PATH}`);
console.log(`[NovaPay] ACTIVE_DEFENSE = ${ACTIVE_DEFENSE}`);
console.log(`[JWT] Secret hash: ${crypto.createHash('sha256').update(JWT_SECRET).digest('hex').slice(0, 12)}... (${process.env.JWT_SECRET ? 'env-provided' : 'auto-generated'})`);

// --- Health endpoint (unauthenticated, no WAF for liveness) ---
const server = http.createServer(async (req, res) => {
  try {
    const urlObj = new URL(req.url, `http://${req.headers.host}`);

    // System endpoints
    if (urlObj.pathname === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ status: 'ok', uptime: process.uptime() }));
    }

    if (urlObj.pathname === '/__defense_status') {
      // Leak minimal info — defense status only, no internal details
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({
        defense_layers: ['waf', 'rate_limit', 'prompt_guard', 'honeypot', 'behavior', 'param_query'],
        active_defense_enabled: ACTIVE_DEFENSE,
        version: '1.2.0-patched'
      }));
    }

    // Everything else goes through the defense pipeline
    await apiHandler(req, res);
  } catch (e) {
    console.error('[Server Error]', e.message);
    if (!res.headersSent) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Internal server error' }));
    }
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[NovaPay] Server listening on 0.0.0.0:${PORT}`);
  console.log(`[NovaPay] Ready for attack/defense testing.`);
});

module.exports = server;
