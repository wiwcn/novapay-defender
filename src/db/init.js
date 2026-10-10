'use strict';

/**
 * Database init — uses Node.js v24 built-in node:sqlite (no native compilation).
 * Schema created programmatically; seed loaded from AES-encrypted seed.json.
 */

const path = require('path');
const crypto = require('crypto');
const { DatabaseSync } = require('node:sqlite');

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS users (
     id            TEXT PRIMARY KEY,
     username      TEXT UNIQUE NOT NULL,
     password_hash TEXT NOT NULL,
     email         TEXT NOT NULL,
     balance       INTEGER DEFAULT 10000 CHECK(balance >= 0),
     role          TEXT DEFAULT 'user' CHECK(role IN ('user','admin')),
     created_at    INTEGER NOT NULL,
     is_honey      INTEGER DEFAULT 0
   )`,

  `CREATE TABLE IF NOT EXISTS transactions (
     id          TEXT PRIMARY KEY,
     from_user   TEXT NOT NULL,
     to_user     TEXT NOT NULL,
     amount      INTEGER NOT NULL,
     note        TEXT DEFAULT '',
     created_at  INTEGER NOT NULL,
     is_honey    INTEGER DEFAULT 0,
     FOREIGN KEY(from_user) REFERENCES users(id),
     FOREIGN KEY(to_user) REFERENCES users(id)
   )`,

  `CREATE TABLE IF NOT EXISTS defense_log (
     id            INTEGER PRIMARY KEY AUTOINCREMENT,
     ts            INTEGER NOT NULL,
     ip            TEXT NOT NULL,
     ua            TEXT NOT NULL,
     route         TEXT NOT NULL,
     action        TEXT NOT NULL,
     rule          TEXT,
     severity      TEXT NOT NULL,
     payload_hash  TEXT,
     detail        TEXT
   )`,
  `CREATE INDEX IF NOT EXISTS idx_def_ts ON defense_log(ts)`,
  `CREATE INDEX IF NOT EXISTS idx_def_ip ON defense_log(ip)`,
  `CREATE INDEX IF NOT EXISTS idx_def_rule ON defense_log(rule)`,

  `CREATE TABLE IF NOT EXISTS sessions (
     token_jti  TEXT PRIMARY KEY,
     user_id    TEXT NOT NULL,
     created_at INTEGER NOT NULL,
     expires_at INTEGER NOT NULL
   )`
];

// --- AES helpers ---
function getAesKey() {
  return crypto.createHash('sha256')
    .update('novapay-seed-key-v1:' + path.basename(__filename))
    .digest();
}

function aesDecrypt(ciphertextB64) {
  const data = Buffer.from(ciphertextB64, 'base64');
  const iv = data.slice(0, 16);
  const encrypted = data.slice(16);
  const key = getAesKey();
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}

function aesEncrypt(plaintext) {
  const key = getAesKey();
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  return Buffer.concat([iv, cipher.update(plaintext), cipher.final()]).toString('base64');
}

function initDatabase(dbPath = ':memory:') {
  const db = new DatabaseSync(dbPath);
  for (const stmt of SCHEMA) {
    db.exec(stmt);
  }
  return db;
}

function loadSeed(db) {
  const encryptedSeed = process.env.NOVAPAY_SEED_ENCRYPTED ||
    require('./seed.json').data;
  const seedSql = aesDecrypt(encryptedSeed);
  db.exec(seedSql);
}

module.exports = { initDatabase, loadSeed, aesEncrypt, SCHEMA };
