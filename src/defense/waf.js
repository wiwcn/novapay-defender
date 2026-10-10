'use strict';

/**
 * WAF Rule Engine
 * Path scanning, SQL injection, XSS detection with deep URL decoding.
 */

const SCAN_PATHS = [
  /phpmyadmin/i, /\.env/i, /wp-admin/i, /config\.xml/i,
  /\.git\//i, /actuator/i, /aws-secret/i,
  /wp-login\.php/i, /\bak\.\w+$/i
];

const SQLI_PATTERNS = [
  /(\b|%27|["'])\s*(UNION|SELECT|INSERT|UPDATE|DELETE|DROP)\b/i,
  /(--|#|\/\*)\s*$/,
  /'\s*(OR|AND)\s+'?\d+'?\s*=\s*'?\d+/i,
  /;\s*(DROP|DELETE|UPDATE|INSERT)\b/i,
  /(CHAR|CONCAT|0x[0-9a-f]+)\s*\(/i,
  /BENCHMARK\s*\(/i,
  /WAITFOR\s+DELAY/i,
  /SLEEP\s*\(/i,
  /INFORMATION_SCHEMA/i,
  /LOAD_FILE\s*\(/i,
  /INTO\s+OUTFILE/i
];

const XSS_PATTERNS = [
  /<script\b[^>]*>/i,
  /javascript:/i,
  /on\w+\s*=/i,
  /<\s*img[^>]+onerror/i,
  /<\s*svg[^>]+onload/i,
  /alert\s*\(/i,
  /document\.cookie/i,
  /eval\s*\(/i
];

const BLOCKED = (rule, severity) => ({ blocked: true, rule, severity });
const ALLOWED = { blocked: false, rule: '', severity: 'low' };

function deepDecode(input) {
  let prev = input, curr = input;
  for (let i = 0; i < 4; i++) {
    try {
      curr = decodeURIComponent(prev);
      if (curr === prev) break;
      prev = curr;
    } catch (_) { break; }
  }
  return curr;
}

function collectValues(payload) {
  const out = [];
  if (!payload) return out;
  const walk = (v) => {
    if (typeof v === 'string') out.push(v);
    else if (Array.isArray(v)) v.forEach(walk);
    else if (v && typeof v === 'object') Object.values(v).forEach(walk);
  };
  walk(payload);
  return out;
}

function runWAF(ctx) {
  const { path, query, body } = ctx;

  for (const p of SCAN_PATHS) {
    if (p.test(path)) return BLOCKED('PATH_SCAN', 'high');
  }

  const values = [...collectValues(query), ...collectValues(body)];

  for (const raw of values) {
    if (typeof raw !== 'string') continue;
    const decoded = deepDecode(raw);

    for (const pat of SQLI_PATTERNS) {
      if (pat.test(decoded) || pat.test(raw)) {
        return BLOCKED('SQL_INJECT', 'critical');
      }
    }

    for (const pat of XSS_PATTERNS) {
      if (pat.test(decoded) || pat.test(raw)) {
        return BLOCKED('XSS_INJECT', 'high');
      }
    }
  }

  return ALLOWED;
}

module.exports = { runWAF };
