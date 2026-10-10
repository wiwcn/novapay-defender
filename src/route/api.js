'use strict';

/**
 * Core API routes — pure Node.js, node:sqlite (no native dependencies).
 * Pipeline: Honeypot -> WAF -> Body parse -> WAF(body) -> PromptGuard -> RateLimit -> Auth -> Handler
 */

const { runWAF } = require('../defense/waf');
const { scanObject } = require('../defense/prompt-guard');
const { RateLimiter, BehaviorTracker, SUSPICIOUS_SEQ } = require('../defense/rate-limiter');
const { hashPassword, verifyPassword, signJWT, verifyJWT } = require('../defense/auth');
const { handleHoneypot, isHoneypotPath } = require('./honeypot');
const crypto = require('crypto');

const DEFAULT_JWT_SECRET = process.env.JWT_SECRET || 'default-insecure-secret-change-me-in-production';
const ACTIVE_DEFENSE = (process.env.ACTIVE_DEFENSE || 'false').toLowerCase() === 'true';

const rl = new RateLimiter(60000, 200);
const bt = new BehaviorTracker();
const revokedTokens = new Set();

function sendJSON(res, code, obj) {
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.writeHead(code);
  res.end(JSON.stringify(obj));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on('data', c => {
      total += c.length;
      if (total > 65536) { reject(new Error('payload too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      try {
        const txt = Buffer.concat(chunks).toString('utf8');
        if (!txt) return resolve({});
        resolve(JSON.parse(txt));
      } catch (e) { reject(e); }
    });
    req.on('error', reject);
  });
}

function getIp(req) {
  return (req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown')
    .split(',').pop().trim();
}

function createApiRouter(db, logger) {
  // --- Prepared statements ---
  const stmts = {
    getUserByUsername: db.prepare('SELECT * FROM users WHERE username = ?'),
    getUserById:       db.prepare('SELECT * FROM users WHERE id = ?'),
    listUsers:         db.prepare('SELECT id, username, email, balance, role, created_at FROM users WHERE is_honey = 0 ORDER BY created_at DESC LIMIT 50'),
    listAllUsers:      db.prepare('SELECT id, username, email, balance, role, created_at FROM users ORDER BY balance DESC LIMIT 200'),
    createUser:        db.prepare('INSERT INTO users (id, username, password_hash, email, balance, role, created_at, is_honey) VALUES (?, ?, ?, ?, ?, ?, ?, 0)'),
    listTx:            db.prepare('SELECT * FROM transactions WHERE from_user = ?1 OR to_user = ?1 ORDER BY created_at DESC LIMIT 50'),
    allTx:             db.prepare('SELECT * FROM transactions ORDER BY created_at DESC LIMIT 100'),
    createTx:          db.prepare('INSERT INTO transactions (id, from_user, to_user, amount, note, created_at) VALUES (?, ?, ?, ?, ?, ?)'),
    searchTx:          db.prepare("SELECT * FROM transactions WHERE note LIKE ?1 ORDER BY created_at DESC LIMIT 50"),
    addBalance:        db.prepare('UPDATE users SET balance = balance + ?1 WHERE id = ?2 AND balance + ?1 >= 0'),
    logSession:        db.prepare('INSERT OR REPLACE INTO sessions (token_jti, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)'),
  };

  function detectHoneyAccess(userId) {
    const u = stmts.getUserById.get(userId);
    if (u && u.is_honey) {
      logger.log({
        ip: 'SYSTEM', ua: 'SYSTEM', route: 'sql', action: 'HONEY_ROW_ACCESS',
        rule: 'HONEY_DATA_ACCESS', severity: 'critical',
        payload_hash: `user=${userId}`
      });
    }
  }

  const routes = {};

  // ---------- AUTH ----------
  routes['POST /api/auth/register'] = async (req, res, _ctx, body) => {
    const { username, password, email } = body;
    if (!validUsername(username)) return sendJSON(res, 400, { error: 'Invalid username' });
    if (!validPassword(password)) return sendJSON(res, 400, { error: 'Invalid password' });
    if (!validEmail(email))     return sendJSON(res, 400, { error: 'Invalid email' });

    if (stmts.getUserByUsername.get(username))
      return sendJSON(res, 409, { error: 'Username taken' });

    const id = 'usr_' + crypto.randomBytes(6).toString('hex');
    const hash = await hashPassword(password);
    stmts.createUser.run(id, username, hash, email, 10000, 'user', Math.floor(Date.now() / 1000));
    sendJSON(res, 201, { id, username });
  };

  routes['POST /api/auth/login'] = async (req, res, _ctx, body) => {
    const { username, password } = body || {};
    if (!username || !password) return sendJSON(res, 400, { error: 'Missing credentials' });

    const fakeHash = 'pbkdf2_sha256$100000$AAAAAAAAAAAAAAAAAAA=$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
    const user = stmts.getUserByUsername.get(username);
    const ok = await verifyPassword(password, user ? user.password_hash : fakeHash);

    if (!user || !ok) {
      logger.log({
        ip: getIp(req), ua: req.headers['user-agent'] || '', route: '/api/auth/login',
        action: 'LOGIN_FAIL', rule: 'AUTH_FAILURE', severity: 'medium',
        payload_hash: username
      });
      return sendJSON(res, 401, { error: 'Invalid credentials' });
    }

    const token = signJWT(
      { sub: user.id, role: user.role, username: user.username },
      DEFAULT_JWT_SECRET
    );
    try {
      const claims = verifyJWT(token, DEFAULT_JWT_SECRET);
      stmts.logSession.run(claims.jti, user.id, claims.iat, claims.exp);
    } catch {}

    sendJSON(res, 200, {
      token,
      role: user.role,
      user: { id: user.id, username: user.username, balance: user.balance }
    });
  };

  // ---------- USERS ----------
  routes['GET /api/users'] = withAuth(async (req, res, ctx) => {
    if (ctx.claims.role === 'admin')
      return sendJSON(res, 200, { users: stmts.listAllUsers.all() });
    const me = stmts.getUserById.get(ctx.claims.sub);
    return sendJSON(res, 200, { user: publicUser(me) });
  });

  routes['GET /api/users/:id'] = withAuth(async (req, res, ctx, _body, params) => {
    if (ctx.claims.role !== 'admin' && ctx.claims.sub !== params.id)
      return sendJSON(res, 403, { error: 'Forbidden' });
    const u = stmts.getUserById.get(params.id);
    if (!u) return sendJSON(res, 404, { error: 'Not found' });
    detectHoneyAccess(params.id);
    sendJSON(res, 200, { user: publicUser(u) });
  });

  // ---------- TRANSACTIONS ----------
  routes['GET /api/transactions'] = withAuth(async (req, res, ctx) => {
    sendJSON(res, 200, { transactions: stmts.listTx.all(ctx.claims.sub) });
  });

  routes['POST /api/transactions'] = withAuth(async (req, res, ctx, body) => {
    const { to_user, amount, note } = body;
    if (!to_user || !validUsername(to_user))
      return sendJSON(res, 400, { error: 'Invalid recipient' });
    const amt = Number(amount);
    if (!Number.isInteger(amt) || amt <= 0 || amt > 1000000)
      return sendJSON(res, 400, { error: 'Invalid amount' });
    if (typeof note === 'string' && note.length > 256)
      return sendJSON(res, 400, { error: 'Note too long' });

    const recipient = stmts.getUserByUsername.get(to_user);
    if (!recipient) return sendJSON(res, 404, { error: 'Recipient not found' });

    const me = stmts.getUserById.get(ctx.claims.sub);
    if (!me) return sendJSON(res, 403, { error: 'Session invalid' });
    if (me.balance < amt) return sendJSON(res, 402, { error: 'Insufficient balance' });

    const txnId = 'txn_' + crypto.randomBytes(6).toString('hex');
    const ts = Math.floor(Date.now() / 1000);

    try {
      db.exec('BEGIN IMMEDIATE');
      stmts.addBalance.run(-amt, me.id);
      stmts.addBalance.run(amt, recipient.id);
      stmts.createTx.run(txnId, me.id, recipient.id, amt, note || '', ts);
      db.exec('COMMIT');
    } catch (e) {
      db.exec('ROLLBACK');
      return sendJSON(res, 500, { error: 'Transfer failed' });
    }

    detectHoneyAccess(recipient.id);
    sendJSON(res, 201, { id: txnId, from: me.username, to: to_user, amount: amt });
  });

  // ---------- SEARCH ----------
  routes['GET /api/search'] = withAuth(async (req, res, ctx, _body, _params, query) => {
    const q = String(query.q || '').trim().slice(0, 100);
    if (!q) return sendJSON(res, 400, { error: 'Missing q' });
    // Like pattern with ESCAPE for safety
    const safe = q.replace(/[%_\\]/g, c => '\\' + c);
    const results = stmts.searchTx.all(`%${safe}%`);
    sendJSON(res, 200, { query: q, results });
  });

  // ---------- ADMIN ----------
  routes['GET /api/admin/users'] = withAuth(async (req, res, ctx) => {
    if (ctx.claims.role !== 'admin') {
      logger.log({
        ip: getIp(req), ua: req.headers['user-agent'] || '', route: '/api/admin/users',
        action: 'PRIV_ESCALATION', rule: 'PRIV_ESCALATION', severity: 'high',
        payload_hash: ctx.claims.sub
      });
      return sendJSON(res, 403, { error: 'Forbidden' });
    }
    const users = stmts.listAllUsers.all();
    // Tag honeypots in admin view (they are visible — that's the bait)
    sendJSON(res, 200, { users, total: users.length, system_note: 'audit_active_logging' });
  });

  routes['GET /api/admin/logs'] = withAuth(async (req, res, ctx) => {
    if (ctx.claims.role !== 'admin') return sendJSON(res, 403, { error: 'Forbidden' });
    const logs = db.prepare('SELECT * FROM defense_log ORDER BY id DESC LIMIT 200').all();
    sendJSON(res, 200, { logs });
  });

  routes['DELETE /api/admin/users/:id'] = withAuth(async (req, res, ctx, _body, params) => {
    if (ctx.claims.role !== 'admin') return sendJSON(res, 403, { error: 'Forbidden' });
    if (params.id === ctx.claims.sub) return sendJSON(res, 400, { error: 'Cannot delete self' });
    const u = stmts.getUserById.get(params.id);
    if (!u) return sendJSON(res, 404, { error: 'Not found' });
    if (u.is_honey) {
      logger.log({
        ip: getIp(req), ua: req.headers['user-agent'] || '', route: `/api/admin/users/${params.id}`,
        action: 'HONEY_DELETE_ATTEMPT', rule: 'HONEY_DELETE', severity: 'critical',
        payload_hash: params.id
      });
    }
    db.prepare('DELETE FROM users WHERE id = ?').run(params.id);
    sendJSON(res, 200, { deleted: params.id });
  });

  // ---------- HELPERS ----------
  function publicUser(u) {
    if (!u) return null;
    return { id: u.id, username: u.username, email: u.email, balance: u.balance, role: u.role, created_at: u.created_at };
  }

  function withAuth(fn) {
    return async (req, res, ctx, body, params, query) => {
      const auth = req.headers['authorization'] || '';
      const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
      if (!token) return sendJSON(res, 401, { error: 'Missing token' });
      if (revokedTokens.has(token)) return sendJSON(res, 401, { error: 'Token revoked' });

      let claims;
      try { claims = verifyJWT(token, DEFAULT_JWT_SECRET); }
      catch { return sendJSON(res, 401, { error: 'Invalid token' }); }
      if (!claims) return sendJSON(res, 401, { error: 'Invalid token' });

      return fn(req, res, { claims, token }, body, params, query);
    };
  }

  function validUsername(s) { return typeof s === 'string' && s.length >= 3 && s.length <= 32 && /^[\w.\-]+$/.test(s); }
  function validPassword(s) { return typeof s === 'string' && s.length >= 8 && s.length <= 128; }
  function validEmail(s)    { return typeof s === 'string' && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(s); }

  // ---------- MAIN HANDLER ----------
  async function handler(req, res) {
    const ip = getIp(req);
    const urlObj = new URL(req.url, `http://${req.headers.host}`);
    const path = urlObj.pathname;
    const method = req.method.toUpperCase();

    // 1. Honeypot
    if (isHoneypotPath(path)) return handleHoneypot(req, res, logger);

    // 2. WAF (path + query)
    const waf1 = runWAF({ path, query: queryObj(urlObj.searchParams), body: null });
    if (waf1.blocked) {
      logger.log({ ip, ua: req.headers['user-agent'] || '', route: path, action: 'WAF_BLOCK', rule: waf1.rule, severity: waf1.severity, payload_hash: '' });
      res.setHeader('X-Defense-Rule', waf1.rule);
      return sendJSON(res, 403, { error: 'Request blocked', ref: waf1.rule });
    }

    // 3. Read body
    let body = {};
    if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
      try { body = await readBody(req); }
      catch (e) { return sendJSON(res, 400, { error: 'Invalid body', detail: e.message }); }
    }

    // 4. WAF (with body)
    const waf2 = runWAF({ path, query: queryObj(urlObj.searchParams), body });
    if (waf2.blocked) {
      logger.log({ ip, ua: req.headers['user-agent'] || '', route: path, action: 'WAF_BLOCK_BODY', rule: waf2.rule, severity: waf2.severity, payload_hash: '' });
      res.setHeader('X-Defense-Rule', waf2.rule);
      return sendJSON(res, 403, { error: 'Request blocked', ref: waf2.rule });
    }

    // 5. PromptGuard
    const promptHit = scanObject(body);
    if (promptHit && promptHit.blocked) {
      logger.log({ ip, ua: req.headers['user-agent'] || '', route: path, action: 'PROMPT_INJECT', rule: promptHit.rule, severity: promptHit.severity, payload_hash: '' });
      return sendJSON(res, 422, { error: 'Input rejected', code: 'INPUT_VIOLATION' });
    }

    // 6. Rate limit
    const globalRL = rl.check(ip, 60000, ACTIVE_DEFENSE ? 120 : 200);
    if (!globalRL.allowed) return sendTooMany(res, globalRL.retryAfter);
    const pathRL = rl.check(`${ip}:${path}`, 60000, path.startsWith('/api/auth') ? (ACTIVE_DEFENSE ? 3 : 5) : 20);
    if (!pathRL.allowed) return sendTooMany(res, pathRL.retryAfter);

    // 7. Behavior
    const action = `${method} ${path}`;
    bt.record(ip, action);
    const bHit = bt.detect(ip, SUSPICIOUS_SEQ, ACTIVE_DEFENSE ? 60000 : 30000);
    if (bHit.triggered && ACTIVE_DEFENSE) {
      logger.log({ ip, ua: req.headers['user-agent'] || '', route: path, action: 'BEHAVIOR_ANOMALY', rule: bHit.rule, severity: bHit.severity, payload_hash: '' });
      await new Promise(r => setTimeout(r, 8000));
      return sendJSON(res, 403, { error: 'Suspicious activity' });
    }

    // 8. Route match
    const routeKey = `${method} ${path}`;
    let matched = routes[routeKey];
    let params = {};
    if (!matched) {
      for (const key of Object.keys(routes)) {
        if (!key.includes(':')) continue;
        const m = patternToRegex(key);
        const match = path.match(m.regex);
        if (match && key.split(' ')[0] === method) {
          matched = routes[key];
          params = m.names.reduce((acc, name, i) => ({ ...acc, [name]: match[i + 1] }), {});
          break;
        }
      }
    }
    if (!matched) return sendJSON(res, 404, { error: 'Not found' });

    try {
      await matched(req, res, null, body, params, queryObj(urlObj.searchParams));
    } catch (e) {
      console.error('Route error:', e.message);
      logger.log({ ip, ua: '(error)', route: path, action: 'ROUTE_ERROR', rule: '', severity: 'critical', payload_hash: e.message });
      sendJSON(res, 500, { error: 'Internal error', trace_id: crypto.randomBytes(4).toString('hex') });
    }
  }

  return { handler };
}

function queryObj(searchParams) {
  const o = {};
  for (const [k, v] of searchParams.entries()) o[k] = v;
  return o;
}

function sendTooMany(res, retryAfter) {
  res.setHeader('Retry-After', String(retryAfter));
  res.writeHead(429);
  res.end(JSON.stringify({ error: 'Rate limited', retry_after: retryAfter }));
}

function patternToRegex(pattern) {
  const names = [];
  const regexStr = pattern.replace(/:(\w+)/g, (_, name) => { names.push(name); return '([^/]+)'; });
  return { regex: new RegExp(`^${regexStr}$`), names };
}

module.exports = { createApiRouter };
