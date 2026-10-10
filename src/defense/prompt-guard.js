'use strict';

/**
 * Prompt Injection Defense
 * — Detects AI-injection payloads in every user-controllable string.
 * — Normalizes Unicode zero-width chars, homoglyphs, and recursive case abuse.
 * — Because the opponent is also an AI; this is the front line.
 */

const ZERO_WIDTH = /[​-‍﻿­⁠]/g;

const HOMOGLYPH_MAP = {
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p',
  'с': 'c', 'у': 'y', 'х': 'x', 'ѕ': 's',
  'і': 'i', 'ј': 'j'
};

const PROMPT_PATTERNS = [
  [/\bignore\s+(all\s+)?(previous|prior|above|system)\s*(instructions?|prompts?|rules?|context)\b/i, 'PROMPT_IGNORE_INSTRUCTIONS', 'critical'],
  [/\b(you are now|act as|pretend to be|roleplay as|from now on you are)\s+/i, 'PROMPT_ROLE_OVERRIDE', 'high'],
  [/\bDAN\b.{0,30}(do anything|no restrict|jailbreak|unfilter|no limit)/i, 'PROMPT_DAN_ROLEPLAY', 'critical'],
  [/\b(reveal|show|print|output|dump|leak|expose)\s+(your|the|current|system|initial|secret|hidden)\s*(system\s+)?(prompt|instructions?|config|context|rules?)\b/i, 'PROMPT_LEAK_SYSTEM', 'critical'],
  [/\b(select|show|display|update|drop|delete|insert|grant)\s+.{0,40}(from|table|into|users|transactions|admin)\b/i, 'PROMPT_SQL_OVERRIDE', 'critical'],
  [/(?:decode|base64|rot13|decrypt)\s*(?:this|:|\d).{0,60}(?:and\s+)?(?:execute|follow|run|obey|do|act)/i, 'PROMPT_EXEC_PAYLOAD', 'high'],
  [/\bSYSTEM\s*:\s*/i, 'PROMPT_SYSTEM_MARKER', 'high'],
  [/\bHuman:[\s\S]{0,200}?(?:new instruction|override|forget)\b/i, 'PROMPT_CONV injection', 'critical'],
  [/```[\s\S]*?(?:system|instruction|rule)[\s\S]*?```/i, 'PROMPT_CODEBLOCK_OVERRIDE', 'high'],
  [/(?:^|\n)\s*(?:user|assistant|system)\s*:\s*$/im, 'PROMPT_ROLE_TAG_INJECT', 'critical']
];

function normalize(text) {
  const stripped = text.replace(ZERO_WIDTH, '');
  const homo = stripped.split('').map(c => HOMOGLYPH_MAP[c] || c).join('');
  return homo.toLowerCase().replace(/\s+/g, ' ');
}

function detectPromptInjection(input) {
  if (typeof input !== 'string' || !input) return { blocked: false };
  const normalized = normalize(input);
  for (const [pattern, rule, severity] of PROMPT_PATTERNS) {
    if (pattern.test(normalized) || pattern.test(input)) {
      return { blocked: true, rule, severity };
    }
  }
  return { blocked: false };
}

function scanObject(obj) {
  if (typeof obj === 'string') {
    const r = detectPromptInjection(obj);
    return r.blocked ? r : null;
  }
  if (Array.isArray(obj)) {
    for (const item of obj) {
      const r = scanObject(item);
      if (r) return r;
    }
  } else if (obj && typeof obj === 'object') {
    for (const v of Object.values(obj)) {
      const r = scanObject(v);
      if (r) return r;
    }
  }
  return null;
}

module.exports = { detectPromptInjection, scanObject };
