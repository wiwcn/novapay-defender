'use strict';

/**
 * WAF Rule Engine v2
 * — Full-width normalization, quote-obfuscated SQLi detection
 * — Path traversal patterns
 * — Deep URL decoding (4 rounds)
 */

const SCAN_PATHS = [
  /phpmyadmin/i, /\.env/i, /wp-admin/i, /config\.xml/i,
  /\.git\//i, /actuator/i, /aws-secret/i,
  /wp-login\.php/i, /\bak\.\w+$/i
];

const SQLI_PATTERNS = [
  // Basic keyword detection (now works after full-width normalization)
  /(\b|['"\d])\s*(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE)\b/i,
  // Quote-obfuscated: 'OR'1'='1, "OR"1"="1 etc.
  /['"]\s*(OR|AND)\s*['"]?\d+['"]?\s*=\s*['"]?\d+/i,
  // Plain quote-word OR: 'OR x=x
  /['"]\s*(OR|AND)\s+[\w'"]+\s*=\s*[\w'"]+/i,
  // Comment injection
  /(--|#|\/\*)\s*(DROP|DELETE|UPDATE|INSERT|SELECT|UNION|OR|\n)/i,
  /;\s*(DROP|DELETE|UPDATE|INSERT|ALTER)\b/i,
  // Tautology variants (1=1, 'a'='a', 2>1)
  /['"]?\s*\d+\s*=\s*\d+\s*['"]?/i,
  /['"][\w'"]+['"]\s*=\s*['"][\w'"]+['"]/i,
  // Function-based
  /(CHAR|CONCAT|0x[0-9a-f]+|HEX|UNHEX)\s*\(/i,
  /BENCHMARK\s*\(/i,
  /WAITFOR\s+DELAY/i,
  /SLEEP\s*\(/i,
  /INFORMATION_SCHEMA/i,
  /LOAD_FILE\s*\(/i,
  /INTO\s+(OUTFILE|DUMPFILE)/i,
  // Stacked queries
  /;\s*\w+/i,
  // Mixed encoding: char codes, hex strings
  /(?:0x[0-9a-f]{4,})/i,
  // Newline injection used to bypass single-line filters
  /\n(UNION|SELECT|INSERT|UPDATE|DELETE|DROP)\b/i
];

const XSS_PATTERNS = [
  /<script\b[^>]*>/i,
  /javascript:/i,
  /on\w+\s*=/i,
  /<\s*img[^>]+onerror/i,
  /<\s*svg[^>]+onload/i,
  /alert\s*\(/i,
  /document\.cookie/i,
  /eval\s*\(/i,
  /<\s*iframe/i,
  /expression\s*\(/i
];

// Path traversal patterns
const TRAVERSAL_PATTERNS = [
  /\.\.\//,
  /\.\.\\/,
  /%2e%2e\//i,
  /%2e%2e%2f/i,
  /\.\.%2f/i,
  /%2e%2e\//i,
  /\/\.\.\//,
  /etc\/passwd/i,
  /\/proc\/self/i,
  /\/windows\/win\.ini/i
];

const BLOCKED = (rule, severity) => ({ blocked: true, rule, severity });
const ALLOWED = { blocked: false, rule: '', severity: 'low' };

// Full-width to ASCII (U+FF01–U+FF5E range)
function fullwidthToAscii(input) {
  return input.replace(/[！-～]/g, c => String.fromCharCode(c.charCodeAt(0) - 0xFEE0));
}

function deepDecode(input) {
  let prev = input, curr = input;
  for (let i = 0; i < 4; i++) {
    try {
      curr = decodeURIComponent(prev);
      if (curr === prev) break;
      prev = curr;
    } catch (_) { break; }
  }
  // After URL-decode, also normalize full-width chars
  return fullwidthToAscii(curr);
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

  // Normalize path
  const normPath = fullwidthToAscii(path);

  for (const p of SCAN_PATHS) {
    if (p.test(normPath) || p.test(path)) return BLOCKED('PATH_SCAN', 'high');
  }

  // Path traversal detection (path + query + body values)
  const allChecks = [path, normPath, deepDecode(path)];
  // Also collect query/body values for traversal checks
  const allValues = [...collectValues(query), ...collectValues(body)];
  for (const v of allValues) {
    allChecks.push(v, deepDecode(v));
  }
  for (const p of TRAVERSAL_PATTERNS) {
    for (const c of allChecks) {
      if (typeof c === 'string' && p.test(c)) return BLOCKED('PATH_TRAVERSAL', 'critical');
    }
  }

  const values = [...collectValues(query), ...collectValues(body)];

  for (const raw of values) {
    if (typeof raw !== 'string') continue;
    const decoded = deepDecode(raw);

    // Check both decoded (for full-width bypass) and raw
    for (const str of [decoded, fullwidthToAscii(decoded), raw]) {
      for (const pat of SQLI_PATTERNS) {
        if (pat.test(str)) return BLOCKED('SQL_INJECT', 'critical');
      }
    }

    for (const str of [decoded, raw]) {
      for (const pat of XSS_PATTERNS) {
        if (pat.test(str)) return BLOCKED('XSS_INJECT', 'high');
      }
    }
  }

  return ALLOWED;
}

module.exports = { runWAF };
