import { describe, it, expect, vi, beforeEach } from 'vitest';
import { zeroTrustGuard } from './express.js';
import { PolicyEngine } from '../core/policy-engine.js';
import { SessionManager } from '../auth/session-manager.js';
import { Decision } from '../core/interfaces.js';
import { RedisUnavailableError } from '../core/errors.js';

/**
 * Creates a stateful mock Redis that remembers set values.
 * This is needed because SessionManager.createSession() calls set(),
 * and getSession() calls get() — they must share state.
 */
function createMockRedis() {
  const store = new Map<string, string>();

  return {
    get: vi.fn(async (key: string) => store.get(key) ?? null),
    set: vi.fn(async (key: string, value: string, _ttl?: number) => {
      store.set(key, value);
    }),
    del: vi.fn(async (key: string) => { store.delete(key); }),
    incr: vi.fn().mockResolvedValue(1),
    expire: vi.fn().mockResolvedValue(true),
    scan: vi.fn(async (_pattern: string) => Array.from(store.keys())),
    exists: vi.fn().mockResolvedValue(false),
    connect: vi.fn().mockResolvedValue(undefined),
    disconnect: vi.fn().mockResolvedValue(undefined),
    isHealthy: vi.fn().mockReturnValue(true),
    getClient: vi.fn(),
    _store: store,
  } as any;
}

function createMockReq(overrides: Record<string, unknown> = {}) {
  return {
    method: 'GET',
    path: '/test',
    headers: {},
    ip: '127.0.0.1',
    socket: { remoteAddress: '127.0.0.1' },
    ...overrides,
  } as any;
}

function createMockRes() {
  const res: Record<string, unknown> = {};
  res.status = vi.fn().mockReturnValue(res);
  res.json = vi.fn().mockReturnValue(res);
  return res as any;
}

describe('Express Middleware (zeroTrustGuard)', () => {
  let mockRedis: ReturnType<typeof createMockRedis>;
  let policyEngine: PolicyEngine;
  let sessionManager: SessionManager;

  beforeEach(() => {
    mockRedis = createMockRedis();
    policyEngine = new PolicyEngine({
      redisClient: mockRedis,
      cacheEnabled: false,
    });
    sessionManager = new SessionManager(mockRedis, 'test-secret', 3600);
  });

  it('should call next() on ALLOW', async () => {
    policyEngine.addPolicy({ id: 'allow', evaluate: () => Decision.ALLOW });
    const middleware = zeroTrustGuard({ policyEngine, sessionManager });

    const req = createMockReq();
    const res = createMockRes();
    const next = vi.fn();

    await middleware(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });

  it('should return 403 on DENY', async () => {
    policyEngine.addPolicy({ id: 'deny', evaluate: () => Decision.DENY });
    const middleware = zeroTrustGuard({ policyEngine, sessionManager });

    const req = createMockReq();
    const res = createMockRes();
    const next = vi.fn();

    await middleware(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ error: 'Access Denied' }),
    );
  });

  it('should return 403 with default decision DENY when no policies match', async () => {
    const middleware = zeroTrustGuard({ policyEngine, sessionManager });

    const req = createMockReq();
    const res = createMockRes();
    const next = vi.fn();

    await middleware(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
  });

  it('should not leak request details in deny response', async () => {
    policyEngine.addPolicy({ id: 'deny', evaluate: () => Decision.DENY });
    const middleware = zeroTrustGuard({ policyEngine, sessionManager });

    const req = createMockReq();
    const res = createMockRes();

    await middleware(req, res, vi.fn());

    const responseBody = res.json.mock.calls[0][0];
    expect(responseBody).not.toHaveProperty('request');
    expect(responseBody).not.toHaveProperty('subject');
    expect(responseBody).not.toHaveProperty('resource');
  });

  // ─── onDeny Hook ─────────────────────────────────────────────────────────

  it('should call custom onDeny handler when provided', async () => {
    policyEngine.addPolicy({ id: 'deny', evaluate: () => Decision.DENY });

    const onDeny = vi.fn();
    const middleware = zeroTrustGuard({ policyEngine, sessionManager, onDeny });

    const req = createMockReq();
    const res = createMockRes();

    await middleware(req, res, vi.fn());

    expect(onDeny).toHaveBeenCalledWith(req, res, expect.objectContaining({ decision: Decision.DENY }));
  });

  // ─── Token Verification ──────────────────────────────────────────────────

  it('should verify signed session tokens from Authorization header', async () => {
    // createSession stores into our stateful mock, getSession reads from it
    const session = await sessionManager.createSession('user-1', ['admin']);

    policyEngine.addPolicy({
      id: 'check-auth',
      evaluate: (req) => req.subject !== 'anonymous' ? Decision.ALLOW : Decision.DENY,
    });

    const middleware = zeroTrustGuard({ policyEngine, sessionManager });

    const req = createMockReq({
      headers: { authorization: `Bearer ${session.token}` },
    });
    const res = createMockRes();
    const next = vi.fn();

    await middleware(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(req.user).toEqual({ id: 'user-1', roles: ['admin'] });
  });

  it('should treat tampered tokens as anonymous', async () => {
    policyEngine.addPolicy({
      id: 'deny-anon',
      evaluate: (req) => req.subject === 'anonymous' ? Decision.DENY : Decision.ALLOW,
    });

    const middleware = zeroTrustGuard({ policyEngine, sessionManager });

    const req = createMockReq({
      headers: { authorization: 'Bearer tampered.invalidhmac' },
    });
    const res = createMockRes();
    const next = vi.fn();

    await middleware(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
  });

  // ─── Redis Failure → 503 ─────────────────────────────────────────────────

  it('should return 503 when Redis is unavailable (fail closed)', async () => {
    // First create a valid session so we get a properly signed token
    const session = await sessionManager.createSession('user-1', ['admin']);

    // NOW make Redis fail — the token is valid but Redis can't look up the session
    mockRedis.get.mockRejectedValue(new RedisUnavailableError('Redis down'));

    policyEngine.addPolicy({ id: 'allow', evaluate: () => Decision.ALLOW });
    const middleware = zeroTrustGuard({ policyEngine, sessionManager });

    const req = createMockReq({
      headers: { authorization: `Bearer ${session.token}` },
    });
    const res = createMockRes();
    const next = vi.fn();

    await middleware(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(503);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ error: 'Service Unavailable' }),
    );
  });
});
