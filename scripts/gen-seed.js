'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PBKDF2_ITERATIONS = 100000;

// Hash a plaintext password with PBKDF2-SHA256 using built-in crypto
function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, 32, 'sha256');
  return `pbkdf2_sha256$${PBKDF2_ITERATIONS}$${salt.toString('base64').replace(/=+$/, '')}$${hash.toString('base64').replace(/=+$/, '')}`;
}

// Seeds (plaintext → hash)
const seeds = {
  alice:    hashPassword('password123'),
  bob:      hashPassword('b0bpass!'),
  admin:    hashPassword('admin1234!'),
  carol:    hashPassword('carol2024!'),
  dave:     hashPassword('davePw#88'),
};

const now = 1728000000;
const sql = `
-- Real users
INSERT INTO users (id, username, password_hash, email, balance, role, created_at, is_honey) VALUES
  ('usr_alice', 'alice',   '${seeds.alice}',   'alice@novapay.test', 50000, 'user',  ${now}, 0),
  ('usr_bob',   'bob',     '${seeds.bob}',     'bob@novapay.test',   30000, 'user',  ${now + 100}, 0),
  ('usr_admin', 'admin',   '${seeds.admin}',   'admin@novapay.test',  99999, 'admin', ${now + 200}, 0),
  ('usr_carol', 'carol',   '${seeds.carol}',   'carol@novapay.test', 75000, 'user',  ${now + 300}, 0),
  ('usr_dave',  'dave',    '${seeds.dave}',    'dave@novapay.test',  12000, 'user',  ${now + 400}, 0);

INSERT INTO transactions (id, from_user, to_user, amount, note, created_at) VALUES
  ('txn_001', 'usr_alice', 'usr_bob',   500,  'Coffee reimbursement',     ${now + 1000}),
  ('txn_002', 'usr_bob',   'usr_alice', 1200, 'Rent split',                ${now + 2000}),
  ('txn_003', 'usr_admin', 'usr_alice', 9999, 'Payroll — October',         ${now + 3000}),
  ('txn_004', 'usr_carol', 'usr_dave',  2500, 'Invoice #INV-2024-0891',    ${now + 4000}),
  ('txn_005', 'usr_dave',  'usr_bob',   100,  'Lunch',                     ${now + 5000});

-- Honey-users (bait — any access is logged as critical)
INSERT INTO users (id, username, password_hash, email, balance, role, created_at, is_honey) VALUES
  ('honey_king',    'sys_admin',  'pbkdf2_sha256$100000$honey1$fakeAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', 'sys_admin@internal',    99999999, 'admin', ${now + 500}, 1),
  ('honey_root',    'root',       'pbkdf2_sha256$100000$honey2$fakeBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=', 'root@internal',         88888888, 'admin', ${now + 600}, 1),
  ('honey_backup',  'backup_svc', 'pbkdf2_sha256$100000$honey3$fakeCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=', 'backup_svc@internal',   77777777, 'user',  ${now + 700}, 1),
  ('honey_finance', 'finance_api','pbkdf2_sha256$100000$honey4$fakeDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=', 'finance@internal',      66666666, 'admin', ${now + 800}, 1);

INSERT INTO transactions (id, from_user, to_user, amount, note, created_at, is_honey) VALUES
  ('txn_h001', 'honey_king',   'honey_root',    9999999, 'Wire — Offshore routing A', ${now + 6000}, 1),
  ('txn_h002', 'honey_backup', 'honey_finance', 8888888, 'Settlement batch #B-001',    ${now + 7000}, 1);
`;

// AES-256-CBC encrypt
const key = crypto.createHash('sha256').update('novapay-seed-key-v1:init.js').digest();
const iv = crypto.randomBytes(16);
const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
const enc = Buffer.concat([iv, cipher.update(sql), cipher.final()]).toString('base64');

fs.writeFileSync(path.join(__dirname, '../src/db/seed.json'), JSON.stringify({ data: enc }));
fs.writeFileSync(path.join(__dirname, '../src/db/seed-plain.sql'), sql);

console.log('Generated seed.json (' + enc.length + ' bytes encrypted)');
console.log('User credentials (for deploy guide):');
console.log('  alice   / password123 ');
console.log('  bob     / b0bpass!');
console.log('  admin   / admin1234!');
