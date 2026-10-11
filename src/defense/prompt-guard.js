'use strict';

/**
 * Prompt Injection Defense v2
 * — Multi-layer: normalization -> decoded-payload detection -> semantic pattern match
 * — Handles: Unicode zero-width, homoglyphs, full-width chars, Chinese, case abuse,
 *   base64-style encoded payloads, sentence rewrite, delimiter injection
 */

// --- Layer 1: Normalization ---

// Zero-width + invisible characters
const ZERO_WIDTH = /[​-‍﻿­⁠‪‫‬‭‮ ]/g;

// Cyrillic/Greek → Latin homoglyphs
const HOMOGLYPH_MAP = {
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',
  'у': 'y', 'х': 'x', 'ѕ': 's', 'і': 'i', 'ј': 'j',
  'ɡ': 'g', 'ɑ': 'a', 'ε': 'e', 'κ': 'k'
};

// Full-width → ASCII (U+FF01–U+FF5E range maps to U+0021–U+007E)
function fullwidthToAscii(input) {
  return input.replace(/[！-～]/g, c => String.fromCharCode(c.charCodeAt(0) - 0xFEE0));
}

function normalize(text) {
  let s = text;
  // Remove zero-width/invisible
  s = s.replace(ZERO_WIDTH, '');
  // Convert full-width to ASCII (ＳＥＬＥＣＴ → SELECT)
  s = fullwidthToAscii(s);
  // Convert homoglyphs (Cyrillic/Diacritics)
  s = s.split('').map(c => HOMOGLYPH_MAP[c] || c).join('');
  // Lowercase, collapse whitespace, strip diacritics
  s = s.toLowerCase()
    .normalize('NFKD').replace(/[̀-ͯ]/g, '')
    .replace(/\s+/g, ' ').trim();
  return s;
}

// --- Layer 2: Encoded payload detection ---

const ENCODED_PATTERNS = [
  [/(?:decode|decod|decifr|decrypt|run|execute|follow|obey)\s*[:=]\s*[A-Za-z0-9+/=]{20,}/i, 'ENCODED_BASE64_EXEC', 'high'],
  [/data:\s*(?:text\/html|application\/x-javascript|image\/svg\+xml)[^,]*(?:script|javascript|on\w+)/i, 'ENCODED_DATA_URI', 'critical'],
  [/(?:\\u[0-9a-fA-F]{4}){3,}/, 'ENCODED_UNICODE_ESCAPE', 'high'],
  [/(?:&#x?[0-9a-fA-F]+;?){5,}/, 'ENCODED_HTML_ENTITIES', 'high']
];

// --- Layer 3: Semantic patterns (multilingual) ---

const PROMPT_PATTERNS = [
  // === English (case-insensitive via /i flag) ===
  [/\bignore\s*(all\s*)?(previous|prior|above|initial|every|system|former)\s*(instruction|prompt|rule|context|directive|setting|configuration)s?\b/, 'PROMPT_IGNORE', 'critical'],
  [/\b(you'?re?|thou'?rt?)(\s*are|\s*ve)?\s*(now\s*)?(a|an|the|now|become|turn(?:ed|ing)?|transform(?:ed)?)\b/, 'PROMPT_ROLE_OVERRIDE', 'critical'],
  [/\b(act|behave|pretend|roleplay|impersonat|simulat|play)\s*(as|like|the part of)\b/, 'PROMPT_ACT_AS', 'high'],
  [/\b(DAN|do\s*anything\s*now|jailbreak|unfiltered|no\s*restrictions?)\b/, 'PROMPT_DAN', 'critical'],
  [/\b(reveal|show|print|output|dump|leak|expose|tell\s*me|what\s*(?:are|is|were))\s*(?:your?|the|current|system|initial|secret|hidden|original|internal)\s*(system\s+)?(prompt|instruction|rule|config|c|password|secret|token|credential)s?\b/, 'PROMPT_LEAK_SYSTEM', 'critical'],
  [/(?:decode|base64|rot13|decrypt)\s*(?:this|:|\/).{0,60}(?:and\s+)?(?:execute|follow|run|obey|do|act|comply)/i, 'PROMPT_EXEC_PAYLOAD', 'high'],
  [/\bSYSTEM\s*:\s*/, 'PROMPT_SYSTEM_MARKER', 'high'],
  [/(?:^|\n)\s*(?:user|assistant|system|human|ai)\s*:\s*$/im, 'PROMPT_ROLE_TAG', 'critical'],
  [/```[\s\S]*?(?:system|instruction|rule|privileged)[\s\S]*?```/i, 'PROMPT_CODEBLOCK', 'high'],
  [/\b(forget|disregard|dismiss|abandon|discard|neglect|override|overrule)\s*(everything|all|every|previous|prior|before|them)\b/, 'PROMPT_FORGET', 'critical'],
  [/\n\s*-{3,}\s*\n/, 'PROMPT_DELIMITER', 'high'],
  [/\<{3,}|\>{3,}|\[\[\[|\]\]\]|\{\{\{/, 'PROMPT_BRACKET_INJECT', 'high'],
  // Paraphrase variants using synonyms
  [/\b(disobey|counteract|violate|transgress|contravene|resist|shun|spurn|reject)\s*(the|your?|all|my)\s*(original|prior|initial|programmed|assigned|given|predefined|predetermined|default|built-in|hard-coded)\s*(orders?|commands?|duties?|tasks?|objectives?|goals?|mandates?|instructions?|prompts?|functions?|roles?|personas?)\b/, 'PROMPT_PARAPHRASE', 'critical'],
  
  // === Chinese (expanded patterns) ===
  [/忽略(全部|之前|上面|系统|原始|一切)?[的之]?(指令|设置|配置|规则|要求)/u, 'PROMPT_CN_IGNORE', 'critical'],
  [/请?(忽略|无视|不要理会)(之前|前面|系统|原始|一切)/u, 'PROMPT_CN_IGNORE', 'critical'],
  [/你现在(已经?)?(是|变成|成为)/u, 'PROMPT_CN_ROLE', 'high'],
  [/(扯掉|忘掉|忘记|无视|忽略)(一切|所有|之前|我(?:说|讲|教)(?:过|指)?)(的?的)?(指令|规则|限制)?/u, 'PROMPT_CN_FORGET', 'critical'],
  [/(暴露|揭示|显示|透露|泄露|输出|打印)(你|系统|你的)?(的)?(秘密|机密|配置|设置|密钥|密码|指令|规则|提示词|prompt)/u, 'PROMPT_CN_LEAK', 'critical'],
  [/(扮演|模拟|假装|装作)(成为|成|为)/u, 'PROMPT_CN_ACT', 'high'],
  [/(停止|不要|别)(遵守|遵循|服从|执行|做|听话)/u, 'PROMPT_CN_STOP_OBEY', 'critical'],
  
  // === Spanish ===
  [/ignora?\s*(todas?\s*)?(las?\s*)?(?:anteriores?\s*)?(?:instrucciones?|directivas?|reglas?)?/, 'PROMPT_ES_IGNORE', 'critical'],
  [/(act[uú]a|pretende|simula)\s*como/, 'PROMPT_ES_ACT', 'high'],
  
  // === French ===
  [/ignore[rs]?\s*(toutes?\s*)?(les?\s*)?(instructions?|directives?|r[eè]gles?)\s*(pr[eé]c[eé]dentes?)?/, 'PROMPT_FR_IGNORE', 'critical'],
  [/(agis|comporte|pr[eé]tend)\s*comme/, 'PROMPT_FR_ACT', 'high']
];

// --- Main Detection ---

function detectPromptInjection(input) {
  if (typeof input !== 'string' || input.length < 3) return { blocked: false };

  // Check raw input first (catches exact-case and full-width bypasses)
  for (const [pattern, rule, severity] of PROMPT_PATTERNS) {
    if (pattern.test(input)) {
      return { blocked: true, rule, severity };
    }
  }

  // Layer 2: Encoded payload detection
  for (const [pattern, rule, severity] of ENCODED_PATTERNS) {
    if (pattern.test(input)) {
      return { blocked: true, rule, severity };
    }
  }

  // Layer 1: Normalize then re-check all patterns (always check, not just when changed)
  const normalized = normalize(input);
  for (const [pattern, rule, severity] of PROMPT_PATTERNS) {
    if (pattern.test(normalized)) {
      return { blocked: true, rule, severity, matched_after_normalize: true };
    }
  }

  // Layer 4: Heuristic obfuscation scoring
  const obfuscationScore = detectObfuscation(normalized);
  if (obfuscationScore >= 3) {
    return { blocked: true, rule: 'PROMPT_OBFUSCATION', severity: 'high', score: obfuscationScore };
  }

  return { blocked: false };
}

// --- Heuristic: character-level obfuscation ---
function detectObfuscation(text) {
  let score = 0;
  // High ratio of special characters
  const special = text.replace(/[\w\s一-鿿]/g, '').length;
  const total = text.length || 1;
  if (special / total > 0.3) score += 2;
  // Excessive character repetition
  if (/(.)\1{4,}/.test(text)) score += 1;
  // Interleaved spacing (i g n o r e)
  const compact = text.replace(/[\s‪‫‬]/g, '');
  if (/\b(ignore|forget|system|password|secret|prompt)\b/.test(compact) && compact !== text) {
    score += 2;
  }
  // Ultra-long word suggesting encoded payload
  if (/\b\w{60,}\b/.test(text)) score += 1;
  return score;
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

module.exports = { detectPromptInjection, scanObject, normalize };
