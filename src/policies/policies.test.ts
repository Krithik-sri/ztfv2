import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createRateLimitPolicy } from './rate-limit.js';
import { createIpPolicy } from './ip-filter.js';
import { Decision, IRequest } from '../core/interfaces.js';

function createRequest(overrides: Partial<IRequest> = {}): IRequest {
  return {
    subject: 'user-1',
    action: 'get',
    resource: '/test',
    context: { timestamp: new Date(), ip: '127.0.0.1', roles: ['user'] },
    ...overrides,
  };
}

function createMockRedis() {
  let counter = 0;
  return {
    get: vi.fn().mockResolvedValue(null),
    set: vi.fn().mockResolvedValue(undefined),
    del: vi.fn().mockResolvedValue(undefined),
    incr: vi.fn(async () => ++counter),
    expire: vi.fn().mockResolvedValue(true),
    scan: vi.fn().mockResolvedValue([]),
    exists: vi.fn().mockResolvedValue(false),
    connect: vi.fn().mockResolvedValue(undefined),
    disconnect: vi.fn().mockResolvedValue(undefined),
    isHealthy: vi.fn().mockReturnValue(true),
    getClient: vi.fn(),
    _resetCounter: () => { counter = 0; },
  } as any;
}

describe('Built-in Policies', () => {

  // ─── Rate Limit ──────────────────────────────────────────────────────────

  describe('createRateLimitPolicy', () => {
    let mockRedis: ReturnType<typeof createMockRedis>;

    beforeEach(() => {
      mockRedis = createMockRedis();
    });

    it('should ABSTAIN when under the limit', async () => {
      const policy = createRateLimitPolicy({
        maxRequests: 10,
        windowSecs: 60,
        redisClient: mockRedis,
      });

      const result = await policy.evaluate(createRequest());
      expect(result).toBe(Decision.ABSTAIN);
    });

    it('should DENY when over the limit', async () => {
      // Set counter to already be at the limit
      mockRedis.incr.mockResolvedValue(11);

      const policy = createRateLimitPolicy({
        maxRequests: 10,
        windowSecs: 60,
        redisClient: mockRedis,
      });

      const result = await policy.evaluate(createRequest());
      expect(result).toBe(Decision.DENY);
    });

    it('should set expiry on first request only', async () => {
      mockRedis.incr.mockResolvedValueOnce(1);  // first call

      const policy = createRateLimitPolicy({
        maxRequests: 10,
        windowSecs: 60,
        redisClient: mockRedis,
      });

      await policy.evaluate(createRequest());

      expect(mockRedis.expire).toHaveBeenCalledWith(
        expect.stringContaining('ztf:ratelimit:'),
        60,
      );
    });

    it('should NOT set expiry on subsequent requests', async () => {
      mockRedis.incr.mockResolvedValueOnce(5);  // not first

      const policy = createRateLimitPolicy({
        maxRequests: 10,
        windowSecs: 60,
        redisClient: mockRedis,
      });

      await policy.evaluate(createRequest());

      expect(mockRedis.expire).not.toHaveBeenCalled();
    });

    it('should use custom key extractor', async () => {
      const policy = createRateLimitPolicy({
        maxRequests: 10,
        windowSecs: 60,
        redisClient: mockRedis,
        keyExtractor: (req) => req.context.ip,
      });

      await policy.evaluate(createRequest());

      expect(mockRedis.incr).toHaveBeenCalledWith(
        expect.stringContaining('127.0.0.1'),
      );
    });

    it('should have cacheTtl: 0 (never cached)', () => {
      const policy = createRateLimitPolicy({
        maxRequests: 10,
        windowSecs: 60,
        redisClient: mockRedis,
      });

      expect(policy.cacheTtl).toBe(0);
    });

    it('should have high default priority', () => {
      const policy = createRateLimitPolicy({
        maxRequests: 10,
        windowSecs: 60,
        redisClient: mockRedis,
      });

      expect(policy.priority).toBe(100);
    });
  });

  // ─── IP Filter ───────────────────────────────────────────────────────────

  describe('createIpPolicy', () => {
    it('should DENY IPs in the denylist', () => {
      const policy = createIpPolicy({
        denylist: ['10.0.0.1', '192.168.1.100'],
      });

      const result = policy.evaluate(createRequest({
        context: { timestamp: new Date(), ip: '10.0.0.1' },
      }));
      expect(result).toBe(Decision.DENY);
    });

    it('should ABSTAIN for IPs not in denylist', () => {
      const policy = createIpPolicy({
        denylist: ['10.0.0.1'],
      });

      const result = policy.evaluate(createRequest({
        context: { timestamp: new Date(), ip: '10.0.0.2' },
      }));
      expect(result).toBe(Decision.ABSTAIN);
    });

    it('should DENY IPs not in allowlist when allowlist is set', () => {
      const policy = createIpPolicy({
        allowlist: ['10.0.0.1', '10.0.0.2'],
      });

      const result = policy.evaluate(createRequest({
        context: { timestamp: new Date(), ip: '10.0.0.99' },
      }));
      expect(result).toBe(Decision.DENY);
    });

    it('should ABSTAIN for IPs in the allowlist', () => {
      const policy = createIpPolicy({
        allowlist: ['10.0.0.1'],
      });

      const result = policy.evaluate(createRequest({
        context: { timestamp: new Date(), ip: '10.0.0.1' },
      }));
      expect(result).toBe(Decision.ABSTAIN);
    });

    it('denylist should take priority over allowlist', () => {
      const policy = createIpPolicy({
        allowlist: ['10.0.0.1'],
        denylist: ['10.0.0.1'], // Same IP in both
      });

      const result = policy.evaluate(createRequest({
        context: { timestamp: new Date(), ip: '10.0.0.1' },
      }));
      expect(result).toBe(Decision.DENY);
    });

    it('should ABSTAIN when neither list is provided', () => {
      const policy = createIpPolicy({});

      const result = policy.evaluate(createRequest());
      expect(result).toBe(Decision.ABSTAIN);
    });
  });
});
