'use strict';

/**
 * NovaPay Defense — main entry.
 * HTTP server with defense middleware pipeline.
 *
 * Deployment:  node src/server.js
 * Environment:  PORT (default 8080), DB_PATH (default ./data/novapay.db),
 *               JWT_SECRET, ACTIVE_DEFENSE (true|false)
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const { initDatabase, loadSeed } = require('./db/init');
const { createLogger } = require('./lib/logger');
const { createApiRouter } = require('./route/api');

const PORT = Number(process.env.PORT) || 8080;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data', 'novapay.db');
const JWT_SECRET = process.env.JWT_SECRET || 'default-insecure-secret-change-me';
const ACTIVE_DEFENSE = (process.env.ACTIVE_DEFENSE || 'false').toLowerCase() === 'true';

// --- Init DB ---
if (DB_PATH !== ':memory:') {
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
}
const db = initDatabase(DB_PATH);
loadSeed(db);

const logger = createLogger(db);
const { handler: apiHandler } = createApiRouter(db, logger);

console.log(`[NovaPay] DB initialized at ${DB_PATH}`);
console.log(`[NovaPay] ACTIVE_DEFENSE = ${ACTIVE_DEFENSE}`);
console.log(`[JWT] Secret hash: ${require('crypto').createHash('sha256').update(JWT_SECRET).digest('hex').slice(0, 12)}...`);

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
        version: '1.0.0'
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
