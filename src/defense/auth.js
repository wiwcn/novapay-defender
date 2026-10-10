'use strict';

/**
 * Authentication + Session security
 * — PBKDF2-SHA256 password hashing
 * — Constant-time comparison (timing-attack mitigation)
 * — JWT (HS256, no external dep)
 * — Session fixation fix: new token issued on login
 */

const crypto = require('crypto');

function constantTimeEqual(a, b) {
  const ba = Buffer.from(a), bb = Buffer.from(b);
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

async function hashPassword(password, iterations = 100000) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.pbkdf2Sync(password, salt, iterations, 32, 'sha256');
  return `pbkdf2_sha256$${iterations}$${salt.toString('base64')}$${hash.toString('base64')}`;
}

async function verifyPassword(password, stored) {
  if (!stored || !stored.startsWith('pbkdf2_sha256$')) return false;
  const [_, iters, saltB64, hashB64] = stored.split('$');
  const iterations = Number(iters);
  const salt = Buffer.from(saltB64, 'base64');
  const expected = Buffer.from(hashB64, 'base64');
  const actual = crypto.pbkdf2Sync(password, salt, iterations, expected.length, 'sha256');
  return constantTimeEqual(actual, expected);
}

// --- JWT (zero-dep) ---

function b64url(input) {
  return Buffer.from(input).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function unb64url(input) {
  input = input.replace(/-/g, '+').replace(/_/g, '/');
  while (input.length % 4) input += '=';
  return Buffer.from(input, 'base64').toString('utf8');
}

function signJWT(payload, secret, ttl = 3600) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const body = { ...payload, iat: now, exp: now + ttl, jti: crypto.randomBytes(8).toString('hex') };
  const encH = b64url(JSON.stringify(header));
  const encB = b64url(JSON.stringify(body));
  const sig = crypto.createHmac('sha256', secret).update(`${encH}.${encB}`).digest('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return `${encH}.${encB}.${sig}`;
}

function verifyJWT(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [h, b, s] = parts;
  const expectedSig = crypto.createHmac('sha256', secret).update(`${h}.${b}`).digest('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  // Constant-time compare signature
  if (!constantTimeEqual(s, expectedSig)) return null;
  const body = JSON.parse(unb64url(b));
  if (body.exp && body.exp < Math.floor(Date.now() / 1000)) return null;
  return body;
}

module.exports = {
  hashPassword, verifyPassword,
  signJWT, verifyJWT,
  constantTimeEqual,
  // Per-instance token blacklist (for logout / session rotation)
  createSessionStore: () => new Set()
};
