import { describe, it, expect, vi, beforeEach } from 'vitest';
import { RedisClient } from './redis-client.js';
import { RedisUnavailableError } from '../core/errors.js';

describe('RedisClient', () => {
  beforeEach(() => {
    RedisClient.resetInstance();
  });

  // ─── Constructor Injection ───────────────────────────────────────────────

  describe('Constructor Injection', () => {
    it('should accept a URL string', () => {
      const c = new RedisClient('redis://custom:6380');
      expect(c).toBeInstanceOf(RedisClient);
    });

    it('should accept undefined (uses defaults)', () => {
      const c = new RedisClient();
      expect(c).toBeInstanceOf(RedisClient);
    });

    it('should accept an existing Redis-like instance', () => {
      // Create a mock that looks like an ioredis instance
      const EventEmitter = require('events');
      const mockInstance = new EventEmitter();
      mockInstance.status = 'ready';
      mockInstance.get = vi.fn();
      mockInstance.set = vi.fn();
      mockInstance.del = vi.fn();

      // Use Object.setPrototypeOf to make instanceof check pass
      const Redis = require('ioredis').default;
      Object.setPrototypeOf(mockInstance, Redis.prototype);

      const c = new RedisClient(mockInstance);
      expect(c).toBeInstanceOf(RedisClient);
    });
  });

  // ─── Deprecated Singleton ────────────────────────────────────────────────

  describe('getInstance (deprecated)', () => {
    it('should return the same instance on repeated calls', () => {
      const a = RedisClient.getInstance();
      const b = RedisClient.getInstance();
      expect(a).toBe(b);
    });

    it('should return a new instance after resetInstance', () => {
      const a = RedisClient.getInstance();
      RedisClient.resetInstance();
      const b = RedisClient.getInstance();
      expect(a).not.toBe(b);
    });
  });

  // ─── Error Wrapping ──────────────────────────────────────────────────────

  describe('Error Wrapping', () => {
    function createFailingRedis(method: string) {
      const EventEmitter = require('events');
      const mockInstance = new EventEmitter();
      mockInstance.status = 'ready';
      mockInstance.get = vi.fn().mockResolvedValue(null);
      mockInstance.set = vi.fn().mockResolvedValue('OK');
      mockInstance.del = vi.fn().mockResolvedValue(1);
      mockInstance.expire = vi.fn().mockResolvedValue(1);
      mockInstance.incr = vi.fn().mockResolvedValue(1);
      mockInstance.exists = vi.fn().mockResolvedValue(0);
      mockInstance.scan = vi.fn().mockResolvedValue(['0', []]);
      mockInstance.connect = vi.fn().mockResolvedValue(undefined);
      mockInstance.quit = vi.fn().mockResolvedValue('OK');

      // Override the specific method to fail
      mockInstance[method] = vi.fn().mockRejectedValue(new Error('conn refused'));

      // Make instanceof Redis pass
      const Redis = require('ioredis').default;
      Object.setPrototypeOf(mockInstance, Redis.prototype);

      return new RedisClient(mockInstance);
    }

    it('should throw RedisUnavailableError on get failure', async () => {
      const c = createFailingRedis('get');
      await expect(c.get('key')).rejects.toThrow(RedisUnavailableError);
    });

    it('should throw RedisUnavailableError on set failure', async () => {
      const c = createFailingRedis('set');
      await expect(c.set('key', 'val')).rejects.toThrow(RedisUnavailableError);
    });

    it('should throw RedisUnavailableError on del failure', async () => {
      const c = createFailingRedis('del');
      await expect(c.del('key')).rejects.toThrow(RedisUnavailableError);
    });

    it('should throw RedisUnavailableError on scan failure', async () => {
      const c = createFailingRedis('scan');
      await expect(c.scan('session:*')).rejects.toThrow(RedisUnavailableError);
    });

    it('should throw RedisUnavailableError on incr failure', async () => {
      const c = createFailingRedis('incr');
      await expect(c.incr('key')).rejects.toThrow(RedisUnavailableError);
    });

    it('should throw RedisUnavailableError on expire failure', async () => {
      const c = createFailingRedis('expire');
      await expect(c.expire('key', 60)).rejects.toThrow(RedisUnavailableError);
    });
  });

  // ─── Health Tracking ─────────────────────────────────────────────────────

  describe('Health Tracking', () => {
    it('should start unhealthy with URL-based construction (lazyConnect)', () => {
      const c = new RedisClient('redis://localhost:6379');
      expect(c.isHealthy()).toBe(false);
    });

    it('should become healthy when ioredis emits ready', () => {
      const EventEmitter = require('events');
      const mockInstance = new EventEmitter();
      mockInstance.status = 'connecting';

      const Redis = require('ioredis').default;
      Object.setPrototypeOf(mockInstance, Redis.prototype);

      const c = new RedisClient(mockInstance);
      expect(c.isHealthy()).toBe(false);

      mockInstance.emit('ready');
      expect(c.isHealthy()).toBe(true);
    });

    it('should become unhealthy on error and close events', () => {
      const EventEmitter = require('events');
      const mockInstance = new EventEmitter();
      mockInstance.status = 'connecting';

      const Redis = require('ioredis').default;
      Object.setPrototypeOf(mockInstance, Redis.prototype);

      const c = new RedisClient(mockInstance);

      mockInstance.emit('ready');
      expect(c.isHealthy()).toBe(true);

      mockInstance.emit('error', new Error('lost'));
      expect(c.isHealthy()).toBe(false);

      mockInstance.emit('ready');
      expect(c.isHealthy()).toBe(true);

      mockInstance.emit('close');
      expect(c.isHealthy()).toBe(false);
    });
  });
});
