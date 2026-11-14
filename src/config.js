'use strict';
// Oberig settings. Everything comes from the environment; nothing is read from or written to disk.

const VERSION = '0.2.0';

const NEAR_URL = 'https://cloud-api.near.ai/v1';
const DEFAULT_MODEL = 'deepseek-ai/DeepSeek-V4.1-Flash-1017';
const DEFAULT_PORT = 8790;

function flag(v, def) {
  if (v === undefined || v === '') return def;
  return !/^(0|false|off|no)$/i.test(String(v).trim());
}

function oneOf(name, v, allowed, def) {
  if (v === undefined || v === '') return def;
  const s = String(v).trim().toLowerCase();
  if (!allowed.includes(s)) throw new Error(`${name} must be one of ${allowed.join(', ')} (got "${v}")`);
  return s;
}

/**
 * Builds the config. `overrides` is for tests and the CLI (for example port).
 * The NEAR AI key comes only from NEARAI_API_KEY or NEAR_AI_API_KEY.
 */
function loadConfig(overrides = {}, env = process.env) {
  const keyVar = env.NEARAI_API_KEY ? 'NEARAI_API_KEY' : env.NEAR_AI_API_KEY ? 'NEAR_AI_API_KEY' : null;
  const port = Number(overrides.port || env.OBERIG_PORT || DEFAULT_PORT);
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('OBERIG_PORT must be a port number');
  const cfg = {
    host: '127.0.0.1',
    port,
    nearUrl: NEAR_URL,
    model: (env.OBERIG_MODEL || DEFAULT_MODEL).trim(),
    apiKey: keyVar ? String(env[keyVar]).trim() : null,
    keyVar,
    requireAttestation: flag(env.OBERIG_REQUIRE_ATTESTATION, true),
    verifyMode: oneOf('OBERIG_VERIFY', env.OBERIG_VERIFY, ['local', 'full'], 'local'),
    requireTcb: oneOf('OBERIG_REQUIRE_TCB', env.OBERIG_REQUIRE_TCB, ['warn', 'uptodate'], 'warn'),
    signingAlgo: oneOf('OBERIG_SIGNING_ALGO', env.OBERIG_SIGNING_ALGO, ['ed25519', 'ecdsa'], 'ed25519'),
    attestTtlMs: Math.max(60, Number(env.OBERIG_ATTEST_TTL || 600)) * 1000,
    shield: oneOf('OBERIG_SHIELD', env.OBERIG_SHIELD, ['block', 'warn', 'off'], 'block'),
    mask: flag(env.OBERIG_MASK, true),
    maskPII: flag(env.OBERIG_MASK_PII, true),
    terms: String(env.OBERIG_TERMS || '').split(',').map((s) => s.trim()).filter((s) => s.length >= 2),
    allowEmails: ['users.noreply.github.com', 'noreply.github.com'],
    upstreamStream: flag(env.OBERIG_UPSTREAM_STREAM, false),
    maxTokens: Number(env.OBERIG_MAX_TOKENS || 32768),
    quiet: flag(env.OBERIG_QUIET, false),
    timeoutMs: 600000,
    ...overrides,
  };
  cfg.customTerms = cfg.terms;
  cfg.maskSecrets = cfg.mask;
  if (!cfg.mask) cfg.maskPII = false;
  return cfg;
}

module.exports = { VERSION, NEAR_URL, DEFAULT_MODEL, DEFAULT_PORT, loadConfig };
