import { RedisClient } from '../cache/redis-client';
import { randomUUID } from 'crypto';

export interface ISession {
    sessionId: string;
    userId: string;
    roles: string[];
    createdAt: Date;
    expiresAt: Date;
    [key: string]: any;
}

export class SessionManager {
    private redisClient: RedisClient;
    private sessionTtl: number; // seconds

    constructor(redisClient: RedisClient, sessionTtl: number = 3600) {
        this.redisClient = redisClient;
        this.sessionTtl = sessionTtl;
    }

    public async createSession(userId: string, roles: string[], metadata: any = {}): Promise<ISession> {
        const sessionId = randomUUID();
        const now = new Date();
        const expiresAt = new Date(now.getTime() + this.sessionTtl * 1000);

        const session: ISession = {
            sessionId,
            userId,
            roles,
            createdAt: now,
            expiresAt,
            ...metadata,
        };

        const key = `session:${sessionId}`;
        await this.redisClient.set(key, JSON.stringify(session), this.sessionTtl);

        return session;
    }

    public async getSession(sessionId: string): Promise<ISession | null> {
        const key = `session:${sessionId}`;
        const data = await this.redisClient.get(key);
        if (!data) return null;

        try {
            const session = JSON.parse(data);
            // Reconstitute Date objects
            session.createdAt = new Date(session.createdAt);
            session.expiresAt = new Date(session.expiresAt);
            return session;
        } catch (e) {
            console.error('Error parsing session data', e);
            return null;
        }
    }

    public async invalidateSession(sessionId: string): Promise<void> {
        const key = `session:${sessionId}`;
        await this.redisClient.del(key);
    }

    public async refreshSession(sessionId: string): Promise<ISession | null> {
        const session = await this.getSession(sessionId);
        if (!session) return null;

        // Extend TTL
        const now = new Date();
        const expiresAt = new Date(now.getTime() + this.sessionTtl * 1000);
        session.expiresAt = expiresAt;

        const key = `session:${sessionId}`;
        await this.redisClient.set(key, JSON.stringify(session), this.sessionTtl);

        return session;
    }
}
