import { describe, it, expect, vi, beforeEach } from 'vitest';
import { SessionManager, ISession } from './session-manager.js';

function createMockRedis() {
  const store = new Map<string, { value: string; ttl?: number }>();

  return {
    get: vi.fn(async (key: string) => store.get(key)?.value ?? null),
    set: vi.fn(async (key: string, value: string, ttl?: number) => {
      store.set(key, { value, ttl });
    }),
    del: vi.fn(async (key: string) => { store.delete(key); }),
    scan: vi.fn(async (pattern: string) => {
      const keys = Array.from(store.keys()).filter(k =>
        k.startsWith(pattern.replace('*', ''))
      );
      return keys;
    }),
    expire: vi.fn(async () => true),
    incr: vi.fn(async () => 1),
    exists: vi.fn(async () => false),
    connect: vi.fn(async () => {}),
    disconnect: vi.fn(async () => {}),
    isHealthy: vi.fn(() => true),
    getClient: vi.fn(),
    _store: store,
  } as any;
}

const TEST_SECRET = 'test-secret-key-for-hmac-signing';

describe('SessionManager', () => {
  let sm: SessionManager;
  let mockRedis: ReturnType<typeof createMockRedis>;

  beforeEach(() => {
    mockRedis = createMockRedis();
    sm = new SessionManager(mockRedis, TEST_SECRET, 3600);
  });

  // ─── Constructor Validation ──────────────────────────────────────────────

  describe('Constructor', () => {
    it('should throw if secret is empty', () => {
      expect(() => new SessionManager(mockRedis, '')).toThrow('non-empty secret');
    });

    it('should accept a valid secret', () => {
      expect(() => new SessionManager(mockRedis, 'valid-secret')).not.toThrow();
    });
  });

  // ─── Token Signing & Verification ────────────────────────────────────────

  describe('Token Signing', () => {
    it('should create a session with a signed token', async () => {
      const session = await sm.createSession('user-1', ['admin']);

      expect(session.token).toBeDefined();
      expect(session.token).toContain('.'); // format: id.hmac
      expect(session.sessionId).toBeDefined();
      // Token should NOT equal the sessionId
      expect(session.token).not.toBe(session.sessionId);
    });

    it('should verify a valid token and return the sessionId', async () => {
      const session = await sm.createSession('user-1', ['admin']);
      const sessionId = sm.verifyToken(session.token);
      expect(sessionId).toBe(session.sessionId);
    });

    it('should reject a tampered token', () => {
      expect(() => sm.verifyToken('tampered.token')).toThrow('Invalid');
    });

    it('should reject a malformed token (no dot)', () => {
      expect(() => sm.verifyToken('notokenhere')).toThrow('Malformed');
    });

    it('should reject empty token', () => {
      expect(() => sm.verifyToken('')).toThrow('Malformed');
    });

    it('should reject token with modified signature', async () => {
      const session = await sm.createSession('user-1', ['admin']);
      const [id] = session.token.split('.');
      const tampered = `${id}.AAAAAAAAtamperedHMAC`;
      expect(() => sm.verifyToken(tampered)).toThrow('Invalid');
    });

    it('should reject token with modified session ID', async () => {
      const session = await sm.createSession('user-1', ['admin']);
      const [, hmac] = session.token.split('.');
      const fakeId = Buffer.from('fake-session-id').toString('base64url');
      const tampered = `${fakeId}.${hmac}`;
      expect(() => sm.verifyToken(tampered)).toThrow('Invalid');
    });
  });

  // ─── Session CRUD ────────────────────────────────────────────────────────

  describe('Session CRUD', () => {
    it('should create and retrieve a session', async () => {
      const session = await sm.createSession('user-1', ['admin'], { department: 'IT' });

      const retrieved = await sm.getSession(session.token);
      expect(retrieved).not.toBeNull();
      expect(retrieved!.userId).toBe('user-1');
      expect(retrieved!.roles).toEqual(['admin']);
      expect(retrieved!.metadata).toEqual({ department: 'IT' });
    });

    it('should return null for a valid token whose session expired', async () => {
      const session = await sm.createSession('user-1', ['admin']);

      // Simulate expiry by clearing the store
      mockRedis._store.clear();

      const retrieved = await sm.getSession(session.token);
      expect(retrieved).toBeNull();
    });

    it('should invalidate a session', async () => {
      const session = await sm.createSession('user-1', ['admin']);

      await sm.invalidateSession(session.token);

      const retrieved = await sm.getSession(session.token);
      expect(retrieved).toBeNull();
    });
  });

  // ─── invalidateByUserId ──────────────────────────────────────────────────

  describe('invalidateByUserId', () => {
    it('should invalidate all sessions for a user', async () => {
      await sm.createSession('user-1', ['admin']);
      await sm.createSession('user-1', ['user']);
      await sm.createSession('user-2', ['user']);

      const count = await sm.invalidateByUserId('user-1');
      expect(count).toBe(2);

      // user-2's session should still exist
      const remaining = Array.from(mockRedis._store.keys());
      expect(remaining).toHaveLength(1);
    });

    it('should return 0 if user has no sessions', async () => {
      const count = await sm.invalidateByUserId('nonexistent');
      expect(count).toBe(0);
    });
  });

  // ─── Refresh ─────────────────────────────────────────────────────────────

  describe('refresh', () => {
    it('should extend session TTL', async () => {
      const session = await sm.createSession('user-1', ['admin']);
      const originalExpiry = session.expiresAt;

      // Small delay to ensure time difference
      await new Promise(r => setTimeout(r, 50));

      const refreshed = await sm.refresh(session.token);
      expect(refreshed).not.toBeNull();
      expect(refreshed!.expiresAt.getTime()).toBeGreaterThan(originalExpiry.getTime());
    });

    it('should accept custom TTL', async () => {
      const session = await sm.createSession('user-1', ['admin']);

      const refreshed = await sm.refresh(session.token, 7200);
      expect(refreshed).not.toBeNull();
      // The new expiresAt should be ~2 hours from now
      const twoHoursFromNow = Date.now() + 7200 * 1000;
      expect(refreshed!.expiresAt.getTime()).toBeLessThanOrEqual(twoHoursFromNow + 1000);
      expect(refreshed!.expiresAt.getTime()).toBeGreaterThan(twoHoursFromNow - 2000);
    });

    it('should return null for expired session', async () => {
      const session = await sm.createSession('user-1', ['admin']);
      mockRedis._store.clear();

      const refreshed = await sm.refresh(session.token);
      expect(refreshed).toBeNull();
    });

    it('should reject tampered token on refresh', async () => {
      await expect(sm.refresh('bad.token')).rejects.toThrow('Invalid');
    });
  });
});
