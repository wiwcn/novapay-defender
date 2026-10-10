'use strict';

/**
 * Structured audit logger — writes to SQLite defense_log table.
 * Sanitizes all fields to prevent log injection attacks.
 */

const CONTROL_CHARS = /[\r\n\t\x00-\x1f]/g;

function sanitize(s) {
  if (s == null) return '';
  return String(s).replace(CONTROL_CHARS, '?').slice(0, 512);
}

function createLogger(db) {
  const stmt = db.prepare(`
    INSERT INTO defense_log (ts, ip, ua, route, action, rule, severity, payload_hash, detail)
    VALUES (@ts, @ip, @ua, @route, @action, @rule, @severity, @payload_hash, @detail)
  `);

  function log(event) {
    try {
      stmt.run({
        ts: Math.floor(Date.now() / 1000),
        ip: sanitize(event.ip),
        ua: sanitize(event.ua),
        route: sanitize(event.route),
        action: sanitize(event.action),
        rule: sanitize(event.rule),
        severity: sanitize(event.severity),
        payload_hash: sanitize(event.payload_hash),
        detail: sanitize(event.detail),
      });
    } catch {
      // Audit failure must not break request flow
    }
  }

  return { log };
}

module.exports = { createLogger, sanitize };
