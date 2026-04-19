import Redis from 'ioredis';

export class RedisClient {
    private static instance: RedisClient;
    private client: Redis;

    private constructor() {
        // Default to localhost:6379 if not provided
        const redisUrl = process.env.REDIS_URL || 'redis://localhost:6379';
        this.client = new Redis(redisUrl, {
            lazyConnect: true,
            retryStrategy: (times) => {
                const delay = Math.min(times * 50, 2000);
                return delay;
            },
        });

        this.client.on('error', (err) => {
            console.error('Redis Client Error', err);
        });

        this.client.on('connect', () => {
            console.log('Redis Client Connected');
        });
    }

    public static getInstance(): RedisClient {
        if (!RedisClient.instance) {
            RedisClient.instance = new RedisClient();
        }
        return RedisClient.instance;
    }

    public async connect(): Promise<void> {
        if (this.client.status !== 'ready' && this.client.status !== 'connecting') {
            await this.client.connect();
        }
    }

    public async disconnect(): Promise<void> {
        await this.client.quit();
    }

    public getClient(): Redis {
        return this.client;
    }

    public async get(key: string): Promise<string | null> {
        return this.client.get(key);
    }

    public async set(key: string, value: string, ttlSeconds?: number): Promise<void> {
        if (ttlSeconds) {
            await this.client.set(key, value, 'EX', ttlSeconds);
        } else {
            await this.client.set(key, value);
        }
    }

    public async del(key: string): Promise<void> {
        await this.client.del(key);
    }
}
