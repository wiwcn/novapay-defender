'use strict';

/**
 * Sliding-window rate limiter (in-memory) + behavior anomaly tracker.
 * No external dependency — pure Map + timestamps.
 */

class RateLimiter {
  constructor(globalWindow = 60000, globalMax = 200) {
    this.windows = new Map(); // key -> number[]
    this.globalWindow = globalWindow;
    this.globalMax = globalMax;
  }

  check(key, windowMs = 60000, max = 60) {
    const now = Date.now();
    let arr = this.windows.get(key) || [];
    arr = arr.filter(t => now - t < windowMs);
    if (arr.length >= max) {
      this.windows.set(key, arr);
      return {
        allowed: false,
        retryAfter: Math.ceil((arr[0] + windowMs - now) / 1000),
        remaining: 0
      };
    }
    arr.push(now);
    this.windows.set(key, arr);
    return { allowed: true, remaining: max - arr.length, retryAfter: 0 };
  }
}

/**
 * Behavioral anomaly: detects request SEQUENCE patterns that indicate automated attack.
 */
class BehaviorTracker {
  constructor(historyTtl = 120000) {
    this.history = new Map(); // key -> [{ action, ts }]
    this.historyTtl = historyTtl;
  }

  record(key, action, ts = Date.now()) {
    let arr = this.history.get(key) || [];
    arr = arr.filter(e => ts - e.ts < this.historyTtl);
    arr.push({ action, ts });
    this.history.set(key, arr);
    return arr;
  }

  detect(key, patterns, windowMs = 30000) {
    const events = (this.history.get(key) || []).filter(e => Date.now() - e.ts < windowMs);
    for (const { pattern, rule, severity } of patterns) {
      if (pattern.every(p => events.some(e => e.action === p))) {
        return { triggered: true, rule, severity, events };
      }
    }
    return { triggered: false };
  }
}

// Suspicious sequences — AI brute-force / automation signatures
const SUSPICIOUS_SEQ = [
  {
    pattern: ['POST /api/auth/login', 'GET /api/admin/users', 'GET /api/transactions/export'],
    rule: 'BRUTE_ADMIN_ESCALATION',
    severity: 'critical'
  },
  {
    pattern: ['POST /api/auth/login', 'POST /api/auth/login', 'POST /api/auth/login', 'POST /api/auth/login'],
    rule: 'CREDENTIAL_STUFFING',
    severity: 'high'
  },
  {
    pattern: ['GET /api/search?q=', 'GET /api/search?q=', 'GET /api/search?q=', 'GET /api/search?q='],
    rule: 'AUTOMATED_ENUMERATION',
    severity: 'medium'
  },
  {
    pattern: ['POST /api/transactions', 'POST /api/transactions', 'POST /api/transactions', 'POST /api/transactions'],
    rule: 'RAPID_TRANSFER_BOT',
    severity: 'high'
  }
];

module.exports = { RateLimiter, BehaviorTracker, SUSPICIOUS_SEQ };
