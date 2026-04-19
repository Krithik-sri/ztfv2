import { RedisClient } from '../cache/redis-client.js';
import { InvalidSessionTokenError } from '../core/errors.js';
import { createHmac, randomUUID, timingSafeEqual } from 'crypto';

/**
 * Session data stored in Redis.
 */
export interface ISession {
  /** Internal session ID (UUID). Never exposed to clients — only the signed token leaves the server. */
  sessionId: string;
  /** The signed token returned to the client: `base64url(sessionId).base64url(hmac)` */
  token: string;
  /** The authenticated user's ID */
  userId: string;
  /** User's roles for RBAC */
  roles: string[];
  /** When the session was created */
  createdAt: Date;
  /** When the session expires */
  expiresAt: Date;
  /** Extensible metadata bag */
  metadata?: Record<string, unknown>;
}

/**
 * Manages user sessions in Redis with HMAC-signed tokens.
 *
 * Security model:
 * - Session IDs are UUIDs stored as Redis keys (`session:<uuid>`).
 * - Clients never see raw session IDs. They receive a signed token:
 *   `base64url(sessionId).base64url(hmac-sha256(sessionId, secret))`
 * - This prevents Redis key enumeration and session forgery.
 *
 * The SESSION_SECRET must be set (via env var or constructor). Without it,
 * session creation throws immediately — fail-safe by design.
 */
export class SessionManager {
  private redisClient: RedisClient;
  private sessionTtl: number;
  private secret: string;

  /**
   * @param redisClient - Redis client instance (constructor-injected)
   * @param secret - HMAC secret for signing tokens. Required.
   * @param sessionTtl - Session TTL in seconds. Default: 3600 (1 hour)
   */
  constructor(redisClient: RedisClient, secret: string, sessionTtl: number = 3600) {
    if (!secret || secret.length === 0) {
      throw new Error(
        '[ztfv2] SessionManager requires a non-empty secret for HMAC token signing. ' +
        'Set the SESSION_SECRET environment variable or pass it to the constructor.'
      );
    }
    this.redisClient = redisClient;
    this.secret = secret;
    this.sessionTtl = sessionTtl;
  }

  /**
   * Sign a session ID using HMAC-SHA256.
   * Token format: `<base64url(sessionId)>.<base64url(hmac)>`
   */
  private signToken(sessionId: string): string {
    const hmac = createHmac('sha256', this.secret).update(sessionId).digest('base64url');
    const encodedId = Buffer.from(sessionId).toString('base64url');
    return `${encodedId}.${hmac}`;
  }

  /**
   * Verify and extract the session ID from a signed token.
   *
   * Uses timing-safe comparison to prevent timing attacks on the HMAC.
   * @returns The raw sessionId if valid
   * @throws {InvalidSessionTokenError} if the token is malformed or tampered
   */
  public verifyToken(token: string): string {
    const parts = token.split('.');
    if (parts.length !== 2) {
      throw new InvalidSessionTokenError('Malformed token: expected format <id>.<signature>');
    }

    const [encodedId, providedHmac] = parts;
    let sessionId: string;
    try {
      sessionId = Buffer.from(encodedId, 'base64url').toString('utf-8');
    } catch {
      throw new InvalidSessionTokenError('Malformed token: invalid base64url encoding');
    }

    const expectedHmac = createHmac('sha256', this.secret).update(sessionId).digest('base64url');

    // Timing-safe comparison to prevent timing attacks
    const expected = Buffer.from(expectedHmac);
    const provided = Buffer.from(providedHmac);

    if (expected.length !== provided.length || !timingSafeEqual(expected, provided)) {
      throw new InvalidSessionTokenError('Invalid token signature');
    }

    return sessionId;
  }

  /**
   * Create a new session and return a signed token.
   *
   * @param userId - The user's identifier
   * @param roles - The user's roles
   * @param metadata - Optional extra session data
   * @returns The session object including the signed `token` field
   */
  public async createSession(
    userId: string,
    roles: string[],
    metadata: Record<string, unknown> = {},
  ): Promise<ISession> {
    const sessionId = randomUUID();
    const token = this.signToken(sessionId);
    const now = new Date();
    const expiresAt = new Date(now.getTime() + this.sessionTtl * 1000);

    const session: ISession = {
      sessionId,
      token,
      userId,
      roles,
      createdAt: now,
      expiresAt,
      metadata,
    };

    const key = `session:${sessionId}`;
    await this.redisClient.set(key, JSON.stringify(session), this.sessionTtl);

    return session;
  }

  /**
   * Retrieve a session by its signed token.
   *
   * @param token - The signed token from the client
   * @returns The session if valid, or null if expired/not found
   * @throws {InvalidSessionTokenError} if the token is tampered
   */
  public async getSession(token: string): Promise<ISession | null> {
    const sessionId = this.verifyToken(token);
    return this.getSessionById(sessionId);
  }

  /**
   * Internal: retrieve a session by raw ID (no token verification).
   * Used by invalidateByUserId where we already have internal IDs.
   */
  private async getSessionById(sessionId: string): Promise<ISession | null> {
    const key = `session:${sessionId}`;
    const data = await this.redisClient.get(key);
    if (!data) return null;

    try {
      const parsed = JSON.parse(data);
      // Reconstitute Date objects
      parsed.createdAt = new Date(parsed.createdAt);
      parsed.expiresAt = new Date(parsed.expiresAt);
      return parsed as ISession;
    } catch {
      console.error(`[ztfv2] Failed to parse session data for ${sessionId}`);
      return null;
    }
  }

  /**
   * Invalidate a single session by its signed token.
   *
   * @param token - The signed token from the client
   * @throws {InvalidSessionTokenError} if the token is tampered
   */
  public async invalidateSession(token: string): Promise<void> {
    const sessionId = this.verifyToken(token);
    const key = `session:${sessionId}`;
    await this.redisClient.del(key);
  }

  /**
   * Invalidate ALL sessions for a given user.
   *
   * Uses Redis SCAN (not KEYS) to avoid blocking the Redis server.
   * This is O(n) over all session keys, which is unavoidable without
   * a secondary index. For high-scale deployments, consider maintaining
   * a `user-sessions:<userId>` set in Redis.
   *
   * @param userId - The user whose sessions should be invalidated
   * @returns The number of sessions that were invalidated
   */
  public async invalidateByUserId(userId: string): Promise<number> {
    const keys = await this.redisClient.scan('session:*');
    let count = 0;

    for (const key of keys) {
      const data = await this.redisClient.get(key);
      if (!data) continue;

      try {
        const session = JSON.parse(data);
        if (session.userId === userId) {
          await this.redisClient.del(key);
          count++;
        }
      } catch {
        // Corrupted session data — delete it
        await this.redisClient.del(key);
      }
    }

    return count;
  }

  /**
   * Refresh a session's expiry (sliding window).
   *
   * @param token - The signed token from the client
   * @param ttl - Optional custom TTL in seconds. Defaults to the session's configured TTL.
   * @returns The updated session, or null if not found/expired
   * @throws {InvalidSessionTokenError} if the token is tampered
   */
  public async refresh(token: string, ttl?: number): Promise<ISession | null> {
    const sessionId = this.verifyToken(token);
    const session = await this.getSessionById(sessionId);
    if (!session) return null;

    const effectiveTtl = ttl ?? this.sessionTtl;
    const now = new Date();
    session.expiresAt = new Date(now.getTime() + effectiveTtl * 1000);

    const key = `session:${sessionId}`;
    await this.redisClient.set(key, JSON.stringify(session), effectiveTtl);

    return session;
  }
}
