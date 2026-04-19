import { IPolicyEngine, IRequest, Decision, IPolicy, EvaluationResult, AuditEvent } from './interfaces.js';
import { RedisClient } from '../cache/redis-client.js';
import { PolicyEvaluationError, RedisUnavailableError } from './errors.js';
import { createHash } from 'crypto';

/**
 * Options for constructing a PolicyEngine.
 */
export interface PolicyEngineOptions {
  /** Redis client for decision caching. */
  redisClient: RedisClient;
  /** Enable/disable Redis caching. Default: true */
  cacheEnabled?: boolean;
  /** Default cache TTL in seconds. Default: 60 */
  cacheTtlSeconds?: number;
  /**
   * Default decision when no policy has an opinion (all ABSTAIN or no policies).
   * For Zero Trust, this should almost always be DENY.
   * Default: Decision.DENY
   */
  defaultDecision?: Decision;
  /**
   * Audit hook called after every evaluation.
   * Fires for allows, denies, and default-decision fallbacks.
   * Runs asynchronously — errors in the hook are caught and logged, never breaking the request flow.
   */
  onDecision?: (event: AuditEvent) => void | Promise<void>;
}

/**
 * Policy Engine with ABSTAIN support, priority-based evaluation,
 * async policies, per-policy cache TTL, and audit hooks.
 *
 * Evaluation strategy (DENY-wins):
 * 1. Policies are sorted by priority (descending). Equal priority preserves insertion order.
 * 2. Each policy is evaluated (sync or async via Promise.resolve).
 * 3. On first DENY → short-circuit, return DENY immediately.
 * 4. ALLOW votes are accumulated. ABSTAIN is neutral.
 * 5. After all policies: if any ALLOW → return ALLOW. Else → return `defaultDecision`.
 *
 * Cache key is a SHA-256 hash of `subject:action:resource:sortedRoles`.
 * The context's timestamp is intentionally excluded — otherwise every request
 * would generate a unique cache key, making the cache useless.
 */
export class PolicyEngine implements IPolicyEngine {
  private policies: IPolicy[] = [];
  private redisClient: RedisClient;
  private cacheEnabled: boolean;
  private cacheTtlSeconds: number;
  private defaultDecision: Decision;
  private onDecision?: (event: AuditEvent) => void | Promise<void>;

  constructor(options: PolicyEngineOptions) {
    this.redisClient = options.redisClient;
    this.cacheEnabled = options.cacheEnabled ?? true;
    this.cacheTtlSeconds = options.cacheTtlSeconds ?? 60;
    this.defaultDecision = options.defaultDecision ?? Decision.DENY;
    this.onDecision = options.onDecision;
  }

  /**
   * Register a new policy. The engine re-sorts policies by priority
   * after each addition. If a policy with the same ID already exists,
   * it is replaced.
   */
  public addPolicy(policy: IPolicy): void {
    // Remove existing policy with same ID to prevent duplicates
    this.policies = this.policies.filter(p => p.id !== policy.id);
    this.policies.push(policy);
    this.sortPolicies();
  }

  /**
   * Remove a policy by ID.
   * @returns true if the policy was found and removed
   */
  public removePolicy(policyId: string): boolean {
    const initialLength = this.policies.length;
    this.policies = this.policies.filter(p => p.id !== policyId);
    return this.policies.length < initialLength;
  }

  /**
   * Replace a policy by ID with a new policy.
   * The new policy's ID is set to match the old one.
   * @returns true if the policy was found and replaced
   */
  public replacePolicy(policyId: string, newPolicy: IPolicy): boolean {
    const index = this.policies.findIndex(p => p.id === policyId);
    if (index === -1) return false;

    // Ensure the replacement keeps the same ID
    const replacement: IPolicy = { ...newPolicy, id: policyId };
    this.policies[index] = replacement;
    this.sortPolicies();
    return true;
  }

  /** Get all currently registered policies (read-only snapshot). */
  public getPolicies(): ReadonlyArray<IPolicy> {
    return [...this.policies];
  }

  /**
   * Evaluate a request against all registered policies.
   *
   * The engine attempts to read from cache first. On cache miss,
   * policies are evaluated in priority order with DENY short-circuiting.
   *
   * Tradeoff: Cache reads that fail (Redis down) are treated as cache misses,
   * allowing the engine to still evaluate policies. Cache writes that fail
   * are logged but don't fail the request. This means the engine degrades
   * gracefully when Redis is unavailable — policies still run, but without
   * caching. The middleware layer is responsible for the ultimate fail-closed
   * behavior (503) when Redis is needed for session lookups.
   */
  public async evaluate(request: IRequest): Promise<Decision> {
    const startTime = Date.now();
    const cacheKey = this.generateCacheKey(request);

    // Try cache read (swallow Redis errors — treat as cache miss)
    if (this.cacheEnabled) {
      try {
        const cachedDecision = await this.redisClient.get(cacheKey);
        if (cachedDecision && this.isValidDecision(cachedDecision)) {
          const result: EvaluationResult = {
            decision: cachedDecision as Decision,
            policyId: null,
            cached: true,
            reason: 'Served from cache',
          };
          await this.emitAuditEvent(request, result, startTime);
          return result.decision;
        }
      } catch (err) {
        // Cache read failed — proceed with live evaluation
        console.warn('[ztfv2] Cache read failed, evaluating policies directly:', (err as Error).message);
      }
    }

    // Evaluate policies
    let hasAllow = false;
    let decisivePolicyId: string | null = null;
    let minCacheTtl = this.cacheTtlSeconds;

    for (const policy of this.policies) {
      let result: Decision;
      try {
        // Support both sync and async evaluate() via Promise.resolve
        result = await Promise.resolve(policy.evaluate(request));
      } catch (err) {
        throw new PolicyEvaluationError(
          policy.id,
          (err as Error).message ?? 'Unknown error',
          err,
        );
      }

      // Track per-policy cacheTtl (use minimum across contributing policies)
      if (policy.cacheTtl !== undefined) {
        minCacheTtl = Math.min(minCacheTtl, policy.cacheTtl);
      }

      if (result === Decision.DENY) {
        // DENY wins — short-circuit immediately
        const evalResult: EvaluationResult = {
          decision: Decision.DENY,
          policyId: policy.id,
          cached: false,
          reason: `Denied by policy "${policy.id}"`,
        };

        await this.cacheDecision(cacheKey, Decision.DENY, minCacheTtl);
        await this.emitAuditEvent(request, evalResult, startTime);
        return Decision.DENY;
      }

      if (result === Decision.ALLOW) {
        hasAllow = true;
        // Track the first policy that allowed (for audit purposes)
        if (!decisivePolicyId) {
          decisivePolicyId = policy.id;
        }
      }
      // ABSTAIN: no-op, continue to next policy
    }

    // All policies evaluated — determine final decision
    let finalDecision: Decision;
    let reason: string;

    if (hasAllow) {
      finalDecision = Decision.ALLOW;
      reason = `Allowed by policy "${decisivePolicyId}"`;
    } else {
      finalDecision = this.defaultDecision;
      decisivePolicyId = null;
      reason = `No policy had an opinion — defaultDecision is ${this.defaultDecision}`;
    }

    const evalResult: EvaluationResult = {
      decision: finalDecision,
      policyId: decisivePolicyId,
      cached: false,
      reason,
    };

    await this.cacheDecision(cacheKey, finalDecision, minCacheTtl);
    await this.emitAuditEvent(request, evalResult, startTime);
    return finalDecision;
  }

  /**
   * Sort policies by priority descending. Stable sort preserves insertion
   * order for same-priority policies.
   */
  private sortPolicies(): void {
    this.policies.sort((a, b) => (b.priority ?? 0) - (a.priority ?? 0));
  }

  /**
   * Generate a deterministic cache key from the request.
   *
   * Uses SHA-256 hash of `subject:action:resource:sortedRoles` to avoid
   * key-length issues and to exclude the timestamp (which would make
   * every request's cache key unique and defeat caching).
   */
  private generateCacheKey(request: IRequest): string {
    const roles = (request.context.roles ?? []).slice().sort().join(',');
    const raw = `${request.subject}:${request.action}:${request.resource}:${roles}`;
    const hash = createHash('sha256').update(raw).digest('hex');
    return `ztf:decision:${hash}`;
  }

  /** Validate that a cached string is a valid Decision enum value. */
  private isValidDecision(value: string): boolean {
    return value === Decision.ALLOW || value === Decision.DENY || value === Decision.ABSTAIN;
  }

  /**
   * Cache a decision in Redis. Swallows errors — a cache write failure
   * should never cause a request to fail.
   */
  private async cacheDecision(cacheKey: string, decision: Decision, ttl: number): Promise<void> {
    if (!this.cacheEnabled || ttl <= 0) return;

    try {
      await this.redisClient.set(cacheKey, decision, ttl);
    } catch (err) {
      console.warn('[ztfv2] Cache write failed:', (err as Error).message);
    }
  }

  /**
   * Emit an audit event via the onDecision hook.
   * Errors in the hook are caught and logged — they never affect the request.
   */
  private async emitAuditEvent(
    request: IRequest,
    result: EvaluationResult,
    startTime: number,
  ): Promise<void> {
    if (!this.onDecision) return;

    const event: AuditEvent = {
      request,
      result,
      timestamp: new Date().toISOString(),
      durationMs: Date.now() - startTime,
    };

    try {
      await Promise.resolve(this.onDecision(event));
    } catch (err) {
      console.error('[ztfv2] onDecision hook error:', (err as Error).message);
    }
  }
}
