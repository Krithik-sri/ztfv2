import { Decision } from './core/interfaces.js';

/**
 * Centralized configuration for the Zero Trust Framework.
 * All values can be overridden via environment variables.
 */
export interface ZtfConfig {
  /** Redis connection URL. Env: REDIS_URL. Default: 'redis://localhost:6379' */
  redisUrl: string;
  /** Default cache TTL for policy decisions in seconds. Env: CACHE_TTL_SECONDS. Default: 60 */
  cacheTtlSeconds: number;
  /** Default decision when no policy matches (all ABSTAIN or no policies). Env: DEFAULT_DECISION. Default: 'DENY' */
  defaultDecision: Decision;
  /**
   * HMAC secret for signing session tokens. Env: SESSION_SECRET.
   * Required when creating sessions — throws if not set.
   */
  sessionSecret: string;
  /** Session TTL in seconds. Env: SESSION_TTL_SECONDS. Default: 3600 (1 hour) */
  sessionTtlSeconds: number;
}

/**
 * Parses a string into a Decision enum value.
 * Returns null if the string is not a valid Decision.
 */
function parseDecision(value: string | undefined): Decision | null {
  if (!value) return null;
  const upper = value.toUpperCase();
  if (upper === 'ALLOW') return Decision.ALLOW;
  if (upper === 'DENY') return Decision.DENY;
  if (upper === 'ABSTAIN') return Decision.ABSTAIN;
  return null;
}

/**
 * Loads configuration from environment variables with sensible defaults.
 * Partial overrides are supported — any field not provided uses the default.
 *
 * @param overrides - Optional partial config to override env/defaults
 * @returns Complete ZtfConfig
 */
export function loadConfig(overrides: Partial<ZtfConfig> = {}): ZtfConfig {
  return {
    redisUrl: overrides.redisUrl
      ?? process.env.REDIS_URL
      ?? 'redis://localhost:6379',

    cacheTtlSeconds: overrides.cacheTtlSeconds
      ?? (process.env.CACHE_TTL_SECONDS ? parseInt(process.env.CACHE_TTL_SECONDS, 10) : 60),

    defaultDecision: overrides.defaultDecision
      ?? parseDecision(process.env.DEFAULT_DECISION)
      ?? Decision.DENY,

    sessionSecret: overrides.sessionSecret
      ?? process.env.SESSION_SECRET
      ?? '',

    sessionTtlSeconds: overrides.sessionTtlSeconds
      ?? (process.env.SESSION_TTL_SECONDS ? parseInt(process.env.SESSION_TTL_SECONDS, 10) : 3600),
  };
}
