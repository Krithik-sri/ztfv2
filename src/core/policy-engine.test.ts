import { describe, it, expect, vi, beforeEach } from 'vitest';
import { PolicyEngine } from './policy-engine.js';
import { Decision, IPolicy, IRequest, AuditEvent } from './interfaces.js';

// Create a mock RedisClient
function createMockRedis() {
  return {
    get: vi.fn().mockResolvedValue(null),
    set: vi.fn().mockResolvedValue(undefined),
    del: vi.fn().mockResolvedValue(undefined),
    incr: vi.fn().mockResolvedValue(1),
    expire: vi.fn().mockResolvedValue(true),
    scan: vi.fn().mockResolvedValue([]),
    exists: vi.fn().mockResolvedValue(false),
    connect: vi.fn().mockResolvedValue(undefined),
    disconnect: vi.fn().mockResolvedValue(undefined),
    isHealthy: vi.fn().mockReturnValue(true),
    getClient: vi.fn(),
  } as any;
}

function createRequest(overrides: Partial<IRequest> = {}): IRequest {
  return {
    subject: 'user-1',
    action: 'get',
    resource: '/test',
    context: { timestamp: new Date(), ip: '127.0.0.1', roles: ['user'] },
    ...overrides,
  };
}

describe('PolicyEngine', () => {
  let engine: PolicyEngine;
  let mockRedis: ReturnType<typeof createMockRedis>;

  beforeEach(() => {
    mockRedis = createMockRedis();
    engine = new PolicyEngine({
      redisClient: mockRedis,
      cacheEnabled: false, // Disable cache for unit tests
    });
  });

  // ─── ABSTAIN + Default Decision ──────────────────────────────────────────

  describe('ABSTAIN + Default Decision', () => {
    it('should return DENY by default when no policies are registered', async () => {
      const decision = await engine.evaluate(createRequest());
      expect(decision).toBe(Decision.DENY);
    });

    it('should return configurable defaultDecision when all policies ABSTAIN', async () => {
      const engineAllow = new PolicyEngine({
        redisClient: mockRedis,
        cacheEnabled: false,
        defaultDecision: Decision.ALLOW,
      });

      engineAllow.addPolicy({
        id: 'abstain-policy',
        evaluate: () => Decision.ABSTAIN,
      });

      const decision = await engineAllow.evaluate(createRequest());
      expect(decision).toBe(Decision.ALLOW);
    });

    it('should return ALLOW when a policy allows and none deny', async () => {
      engine.addPolicy({ id: 'allow', evaluate: () => Decision.ALLOW });
      engine.addPolicy({ id: 'abstain', evaluate: () => Decision.ABSTAIN });

      const decision = await engine.evaluate(createRequest());
      expect(decision).toBe(Decision.ALLOW);
    });

    it('should return DENY when any policy denies, even if others allow', async () => {
      engine.addPolicy({ id: 'allow', evaluate: () => Decision.ALLOW });
      engine.addPolicy({ id: 'deny', evaluate: () => Decision.DENY });

      const decision = await engine.evaluate(createRequest());
      expect(decision).toBe(Decision.DENY);
    });

    it('DENY should win even when allow has higher priority', async () => {
      engine.addPolicy({ id: 'allow', priority: 100, evaluate: () => Decision.ALLOW });
      engine.addPolicy({ id: 'deny', priority: 50, evaluate: () => Decision.DENY });

      const decision = await engine.evaluate(createRequest());
      expect(decision).toBe(Decision.DENY);
    });

    it('ABSTAIN + DENY should be DENY', async () => {
      engine.addPolicy({ id: 'abstain', evaluate: () => Decision.ABSTAIN });
      engine.addPolicy({ id: 'deny', evaluate: () => Decision.DENY });

      const decision = await engine.evaluate(createRequest());
      expect(decision).toBe(Decision.DENY);
    });
  });

  // ─── Priority + Short-circuit ────────────────────────────────────────────

  describe('Priority + Short-circuit', () => {
    it('should evaluate higher-priority policies first', async () => {
      const order: string[] = [];

      engine.addPolicy({
        id: 'low',
        priority: 10,
        evaluate: () => { order.push('low'); return Decision.ABSTAIN; },
      });
      engine.addPolicy({
        id: 'high',
        priority: 100,
        evaluate: () => { order.push('high'); return Decision.ABSTAIN; },
      });
      engine.addPolicy({
        id: 'mid',
        priority: 50,
        evaluate: () => { order.push('mid'); return Decision.ABSTAIN; },
      });

      await engine.evaluate(createRequest());
      expect(order).toEqual(['high', 'mid', 'low']);
    });

    it('should short-circuit on DENY (not evaluate remaining policies)', async () => {
      const spyAfterDeny = vi.fn(() => Decision.ALLOW);

      engine.addPolicy({
        id: 'deny-first',
        priority: 100,
        evaluate: () => Decision.DENY,
      });
      engine.addPolicy({
        id: 'allow-after',
        priority: 50,
        evaluate: spyAfterDeny,
      });

      const decision = await engine.evaluate(createRequest());
      expect(decision).toBe(Decision.DENY);
      expect(spyAfterDeny).not.toHaveBeenCalled();
    });
  });

  // ─── Async Policies ──────────────────────────────────────────────────────

  describe('Async Policies', () => {
    it('should handle async evaluate() functions', async () => {
      engine.addPolicy({
        id: 'async-policy',
        evaluate: async () => {
          await new Promise((r) => setTimeout(r, 10));
          return Decision.ALLOW;
        },
      });

      const decision = await engine.evaluate(createRequest());
      expect(decision).toBe(Decision.ALLOW);
    });

    it('should handle mixed sync and async policies', async () => {
      engine.addPolicy({
        id: 'sync',
        priority: 100,
        evaluate: () => Decision.ABSTAIN,
      });
      engine.addPolicy({
        id: 'async',
        priority: 50,
        evaluate: async () => Decision.ALLOW,
      });

      const decision = await engine.evaluate(createRequest());
      expect(decision).toBe(Decision.ALLOW);
    });
  });

  // ─── removePolicy + replacePolicy ────────────────────────────────────────

  describe('removePolicy + replacePolicy', () => {
    it('removePolicy should return true if policy was found and removed', () => {
      engine.addPolicy({ id: 'test', evaluate: () => Decision.ALLOW });
      expect(engine.removePolicy('test')).toBe(true);
      expect(engine.removePolicy('nonexistent')).toBe(false);
    });

    it('removePolicy should affect subsequent evaluations', async () => {
      engine.addPolicy({ id: 'allow-all', evaluate: () => Decision.ALLOW });

      expect(await engine.evaluate(createRequest())).toBe(Decision.ALLOW);

      engine.removePolicy('allow-all');
      expect(await engine.evaluate(createRequest())).toBe(Decision.DENY); // defaultDecision
    });

    it('replacePolicy should swap the policy in place', async () => {
      engine.addPolicy({ id: 'flip', evaluate: () => Decision.ALLOW });
      expect(await engine.evaluate(createRequest())).toBe(Decision.ALLOW);

      engine.replacePolicy('flip', { id: 'flip', evaluate: () => Decision.DENY });
      expect(await engine.evaluate(createRequest())).toBe(Decision.DENY);
    });

    it('replacePolicy should return false for nonexistent policy', () => {
      expect(engine.replacePolicy('ghost', { id: 'ghost', evaluate: () => Decision.ALLOW })).toBe(false);
    });

    it('addPolicy with duplicate ID should replace the existing policy', async () => {
      engine.addPolicy({ id: 'dup', evaluate: () => Decision.ALLOW });
      engine.addPolicy({ id: 'dup', evaluate: () => Decision.DENY });

      expect(engine.getPolicies().filter(p => p.id === 'dup')).toHaveLength(1);
      expect(await engine.evaluate(createRequest())).toBe(Decision.DENY);
    });
  });

  // ─── onDecision Audit Hook ───────────────────────────────────────────────

  describe('onDecision Audit Hook', () => {
    it('should fire the onDecision hook on every evaluation', async () => {
      const events: AuditEvent[] = [];
      const auditEngine = new PolicyEngine({
        redisClient: mockRedis,
        cacheEnabled: false,
        onDecision: (event) => { events.push(event); },
      });

      auditEngine.addPolicy({ id: 'allow', evaluate: () => Decision.ALLOW });
      await auditEngine.evaluate(createRequest());

      expect(events).toHaveLength(1);
      expect(events[0].result.decision).toBe(Decision.ALLOW);
      expect(events[0].result.policyId).toBe('allow');
      expect(events[0].durationMs).toBeGreaterThanOrEqual(0);
      expect(events[0].timestamp).toBeDefined();
    });

    it('should fire even when using default decision', async () => {
      const events: AuditEvent[] = [];
      const auditEngine = new PolicyEngine({
        redisClient: mockRedis,
        cacheEnabled: false,
        onDecision: (event) => { events.push(event); },
      });

      await auditEngine.evaluate(createRequest());

      expect(events).toHaveLength(1);
      expect(events[0].result.decision).toBe(Decision.DENY);
      expect(events[0].result.policyId).toBeNull();
    });

    it('should not break evaluation if onDecision throws', async () => {
      const auditEngine = new PolicyEngine({
        redisClient: mockRedis,
        cacheEnabled: false,
        onDecision: () => { throw new Error('hook error'); },
      });

      auditEngine.addPolicy({ id: 'allow', evaluate: () => Decision.ALLOW });

      // Should not throw
      const decision = await auditEngine.evaluate(createRequest());
      expect(decision).toBe(Decision.ALLOW);
    });
  });

  // ─── Per-policy cacheTtl ─────────────────────────────────────────────────

  describe('Per-policy cacheTtl', () => {
    it('should use minimum cacheTtl across contributing policies', async () => {
      const cachedEngine = new PolicyEngine({
        redisClient: mockRedis,
        cacheEnabled: true,
        cacheTtlSeconds: 60,
      });

      cachedEngine.addPolicy({
        id: 'short-cache',
        cacheTtl: 10,
        evaluate: () => Decision.ALLOW,
      });
      cachedEngine.addPolicy({
        id: 'long-cache',
        cacheTtl: 300,
        evaluate: () => Decision.ABSTAIN,
      });

      await cachedEngine.evaluate(createRequest());

      // The SET call should use the minimum cacheTtl (10)
      expect(mockRedis.set).toHaveBeenCalledWith(
        expect.any(String),
        Decision.ALLOW,
        10,
      );
    });

    it('should not cache when any policy has cacheTtl: 0', async () => {
      const cachedEngine = new PolicyEngine({
        redisClient: mockRedis,
        cacheEnabled: true,
        cacheTtlSeconds: 60,
      });

      cachedEngine.addPolicy({
        id: 'no-cache',
        cacheTtl: 0,
        evaluate: () => Decision.ALLOW,
      });

      await cachedEngine.evaluate(createRequest());

      // SET should not have been called
      expect(mockRedis.set).not.toHaveBeenCalled();
    });
  });

  // ─── Cache Key Correctness ───────────────────────────────────────────────

  describe('Cache Key', () => {
    it('should produce the same cache key for the same request (ignoring timestamp)', async () => {
      const cachedEngine = new PolicyEngine({
        redisClient: mockRedis,
        cacheEnabled: true,
      });

      cachedEngine.addPolicy({ id: 'allow', evaluate: () => Decision.ALLOW });

      const req1 = createRequest({ context: { timestamp: new Date('2026-01-01'), ip: '1.2.3.4', roles: ['admin'] } });
      const req2 = createRequest({ context: { timestamp: new Date('2026-06-15'), ip: '1.2.3.4', roles: ['admin'] } });

      await cachedEngine.evaluate(req1);
      await cachedEngine.evaluate(req2);

      // Both should have used the same cache key
      const key1 = mockRedis.set.mock.calls[0][0];
      const key2 = mockRedis.set.mock.calls[1][0];
      expect(key1).toBe(key2);
    });

    it('should produce different cache keys for different roles', async () => {
      const cachedEngine = new PolicyEngine({
        redisClient: mockRedis,
        cacheEnabled: true,
      });

      cachedEngine.addPolicy({ id: 'allow', evaluate: () => Decision.ALLOW });

      const req1 = createRequest({ context: { timestamp: new Date(), ip: '1.2.3.4', roles: ['admin'] } });
      const req2 = createRequest({ context: { timestamp: new Date(), ip: '1.2.3.4', roles: ['user'] } });

      await cachedEngine.evaluate(req1);
      await cachedEngine.evaluate(req2);

      const key1 = mockRedis.set.mock.calls[0][0];
      const key2 = mockRedis.set.mock.calls[1][0];
      expect(key1).not.toBe(key2);
    });
  });

  // ─── Redis Failure Handling ──────────────────────────────────────────────

  describe('Redis Failure Handling', () => {
    it('should evaluate policies when cache read fails (graceful degradation)', async () => {
      mockRedis.get.mockRejectedValue(new Error('Redis down'));

      const cachedEngine = new PolicyEngine({
        redisClient: mockRedis,
        cacheEnabled: true,
      });

      cachedEngine.addPolicy({ id: 'allow', evaluate: () => Decision.ALLOW });

      // Should not throw — just skip cache and evaluate
      const decision = await cachedEngine.evaluate(createRequest());
      expect(decision).toBe(Decision.ALLOW);
    });

    it('should not throw when cache write fails', async () => {
      mockRedis.set.mockRejectedValue(new Error('Redis down'));

      const cachedEngine = new PolicyEngine({
        redisClient: mockRedis,
        cacheEnabled: true,
      });

      cachedEngine.addPolicy({ id: 'allow', evaluate: () => Decision.ALLOW });

      const decision = await cachedEngine.evaluate(createRequest());
      expect(decision).toBe(Decision.ALLOW);
    });
  });

  // ─── Policy Evaluation Errors ────────────────────────────────────────────

  describe('Policy Evaluation Errors', () => {
    it('should throw PolicyEvaluationError when a policy throws', async () => {
      engine.addPolicy({
        id: 'bad-policy',
        evaluate: () => { throw new Error('boom'); },
      });

      await expect(engine.evaluate(createRequest())).rejects.toThrow('Policy "bad-policy" evaluation failed');
    });
  });
});
