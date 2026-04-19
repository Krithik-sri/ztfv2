import { IPolicy, IRequest, Decision } from '../core/interfaces.js';

/**
 * Options for the built-in IP filter policy.
 */
export interface IpPolicyOptions {
  /**
   * List of allowed IP addresses or CIDR ranges.
   * If provided, only IPs in this list are allowed.
   * If not provided, all IPs are allowed unless in the denylist.
   */
  allowlist?: string[];
  /**
   * List of denied IP addresses or CIDR ranges.
   * Denylist is checked BEFORE allowlist (DENY wins).
   */
  denylist?: string[];
  /** Policy priority. Default: 90 (high, checked early) */
  priority?: number;
}

/**
 * Creates an IP-based access policy.
 *
 * Evaluation order:
 * 1. If IP is in denylist → DENY
 * 2. If allowlist is provided and IP is NOT in it → DENY
 * 3. Otherwise → ABSTAIN (let other policies decide)
 *
 * Note: Currently supports exact IP matching only. CIDR range support
 * can be added by installing a library like `ip-range-check` or implementing
 * a CIDR parser.
 *
 * @example
 * ```typescript
 * const ipPolicy = createIpPolicy({
 *   denylist: ['10.0.0.1', '192.168.1.100'],
 *   allowlist: ['10.0.0.0/8'], // Note: CIDR not yet supported
 * });
 * policyEngine.addPolicy(ipPolicy);
 * ```
 */
export function createIpPolicy(options: IpPolicyOptions): IPolicy {
  const {
    allowlist,
    denylist,
    priority = 90,
  } = options;

  // Pre-compute Sets for O(1) lookup
  const denySet = denylist ? new Set(denylist) : null;
  const allowSet = allowlist ? new Set(allowlist) : null;

  return {
    id: 'builtin:ip-filter',
    description: `IP filter: ${denylist?.length ?? 0} denied, ${allowlist?.length ?? 'any'} allowed`,
    priority,
    evaluate: (request: IRequest): Decision => {
      const ip = request.context.ip;

      // Denylist checked first — DENY wins
      if (denySet && denySet.has(ip)) {
        return Decision.DENY;
      }

      // If allowlist exists, IP must be in it
      if (allowSet && !allowSet.has(ip)) {
        return Decision.DENY;
      }

      // No opinion — let other policies decide
      return Decision.ABSTAIN;
    },
  };
}
