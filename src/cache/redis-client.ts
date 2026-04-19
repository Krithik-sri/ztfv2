import Redis from 'ioredis';
import { RedisUnavailableError } from '../core/errors.js';

/**
 * Redis client wrapper with constructor injection, health tracking,
 * and graceful failure handling.
 *
 * Supports three construction modes:
 * 1. `new RedisClient(existingRedisInstance)` — for testing or shared connections
 * 2. `new RedisClient('redis://...')` — connects to a URL
 * 3. `RedisClient.getInstance()` — (deprecated) singleton for backward compat
 */
export class RedisClient {
  private static instance: RedisClient | null = null;
  private client: Redis;
  private healthy = false;

  constructor(clientOrUrl?: Redis | string) {
    if (clientOrUrl instanceof Redis) {
      this.client = clientOrUrl;
      // Assume externally-managed client is healthy if already connected
      this.healthy = this.client.status === 'ready';
    } else {
      const redisUrl = clientOrUrl ?? process.env.REDIS_URL ?? 'redis://localhost:6379';
      this.client = new Redis(redisUrl, {
        lazyConnect: true,
        retryStrategy: (times: number) => {
          const delay = Math.min(times * 50, 2000);
          return delay;
        },
      });
    }

    this.client.on('error', (err: Error) => {
      this.healthy = false;
      console.error('[ztfv2] Redis Client Error:', err.message);
    });

    this.client.on('ready', () => {
      this.healthy = true;
    });

    this.client.on('close', () => {
      this.healthy = false;
    });
  }

  /**
   * @deprecated Use constructor injection instead: `new RedisClient(url)` or `new RedisClient(redisInstance)`.
   * Retained for backward compatibility only.
   */
  public static getInstance(): RedisClient {
    if (!RedisClient.instance) {
      RedisClient.instance = new RedisClient();
    }
    return RedisClient.instance;
  }

  /** Reset the singleton — primarily for testing. */
  public static resetInstance(): void {
    RedisClient.instance = null;
  }

  /** Connect to Redis (only needed when using URL-based construction with lazyConnect). */
  public async connect(): Promise<void> {
    if (this.client.status !== 'ready' && this.client.status !== 'connecting') {
      await this.client.connect();
    }
  }

  /** Gracefully disconnect from Redis. */
  public async disconnect(): Promise<void> {
    try {
      await this.client.quit();
    } catch {
      // Ignore errors on disconnect — may already be closed
    }
  }

  /** Whether the Redis connection is currently healthy. */
  public isHealthy(): boolean {
    return this.healthy;
  }

  /** Get the underlying ioredis client (for advanced usage). */
  public getClient(): Redis {
    return this.client;
  }

  /**
   * Get a value from Redis.
   * @throws {RedisUnavailableError} if Redis is unavailable
   */
  public async get(key: string): Promise<string | null> {
    try {
      return await this.client.get(key);
    } catch (err) {
      throw new RedisUnavailableError(`Failed to GET key "${key}"`, err);
    }
  }

  /**
   * Set a value in Redis, optionally with a TTL.
   * @throws {RedisUnavailableError} if Redis is unavailable
   */
  public async set(key: string, value: string, ttlSeconds?: number): Promise<void> {
    try {
      if (ttlSeconds && ttlSeconds > 0) {
        await this.client.set(key, value, 'EX', ttlSeconds);
      } else {
        await this.client.set(key, value);
      }
    } catch (err) {
      throw new RedisUnavailableError(`Failed to SET key "${key}"`, err);
    }
  }

  /**
   * Delete a key from Redis.
   * @throws {RedisUnavailableError} if Redis is unavailable
   */
  public async del(key: string): Promise<void> {
    try {
      await this.client.del(key);
    } catch (err) {
      throw new RedisUnavailableError(`Failed to DEL key "${key}"`, err);
    }
  }

  /**
   * Update the TTL of an existing key.
   * @throws {RedisUnavailableError} if Redis is unavailable
   */
  public async expire(key: string, ttlSeconds: number): Promise<boolean> {
    try {
      const result = await this.client.expire(key, ttlSeconds);
      return result === 1;
    } catch (err) {
      throw new RedisUnavailableError(`Failed to EXPIRE key "${key}"`, err);
    }
  }

  /**
   * Increment a key's value by 1. Returns the new value.
   * If the key doesn't exist, it is set to 0 before incrementing.
   * @throws {RedisUnavailableError} if Redis is unavailable
   */
  public async incr(key: string): Promise<number> {
    try {
      return await this.client.incr(key);
    } catch (err) {
      throw new RedisUnavailableError(`Failed to INCR key "${key}"`, err);
    }
  }

  /**
   * Scan for keys matching a pattern. Uses SCAN (not KEYS) to avoid blocking.
   * Returns all matching keys across the full keyspace.
   * @throws {RedisUnavailableError} if Redis is unavailable
   */
  public async scan(pattern: string): Promise<string[]> {
    try {
      const keys: string[] = [];
      let cursor = '0';
      do {
        const [nextCursor, batch] = await this.client.scan(cursor, 'MATCH', pattern, 'COUNT', 100);
        cursor = nextCursor;
        keys.push(...batch);
      } while (cursor !== '0');
      return keys;
    } catch (err) {
      throw new RedisUnavailableError(`Failed to SCAN pattern "${pattern}"`, err);
    }
  }

  /**
   * Check if a key exists.
   * @throws {RedisUnavailableError} if Redis is unavailable
   */
  public async exists(key: string): Promise<boolean> {
    try {
      const result = await this.client.exists(key);
      return result === 1;
    } catch (err) {
      throw new RedisUnavailableError(`Failed to EXISTS key "${key}"`, err);
    }
  }
}
