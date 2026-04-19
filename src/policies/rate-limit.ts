import { IPolicy, IRequest, Decision } from '../core/interfaces.js';
import { RedisClient } from '../cache/redis-client.js';

/**
 * Options for the built-in rate limit policy.
 */
export interface RateLimitPolicyOptions {
  /** Maximum number of requests allowed in the time window */
  maxRequests: number;
  /** Time window in seconds */
  windowSecs: number;
  /**
   * Function to extract the rate-limit key from a request.
   * Default: uses the subject (userId) as the key.
   * Common alternatives: IP-based (`req => req.context.ip`), or combined.
   */
  keyExtractor?: (request: IRequest) => string;
  /** Redis client for distributed counting. Required. */
  redisClient: RedisClient;
  /** Policy priority. Default: 100 (high, checked early to reject fast) */
  priority?: number;
}

/**
 * Creates a rate-limiting policy using Redis INCR + EXPIRE.
 *
 * Behavior:
 * - Returns DENY if the request count exceeds `maxRequests` within `windowSecs`.
 * - Returns ABSTAIN otherwise (does not grant access — other policies decide that).
 *
 * Uses Redis INCR for atomic counting and EXPIRE for automatic window cleanup.
 * This is a distributed rate limiter — works across multiple app instances.
 *
 * @example
 * ```typescript
 * const rateLimit = createRateLimitPolicy({
 *   maxRequests: 100,
 *   windowSecs: 60,
 *   redisClient,
 * });
 * policyEngine.addPolicy(rateLimit);
 * ```
 */
export function createRateLimitPolicy(options: RateLimitPolicyOptions): IPolicy {
  const {
    maxRequests,
    windowSecs,
    redisClient,
    keyExtractor = (req) => req.subject,
    priority = 100,
  } = options;

  return {
    id: 'builtin:rate-limit',
    description: `Rate limit: ${maxRequests} requests per ${windowSecs}s`,
    priority,
    cacheTtl: 0, // Never cache rate-limit decisions — they must be evaluated on every request
    evaluate: async (request: IRequest): Promise<Decision> => {
      const key = `ztf:ratelimit:${keyExtractor(request)}`;

      const count = await redisClient.incr(key);

      // Set expiry only on first request in the window (count === 1)
      if (count === 1) {
        await redisClient.expire(key, windowSecs);
      }

      if (count > maxRequests) {
        return Decision.DENY;
      }

      // ABSTAIN: rate limit not exceeded, let other policies decide
      return Decision.ABSTAIN;
    },
  };
}
