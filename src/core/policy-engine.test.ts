import { describe, it, expect, vi, beforeEach } from 'vitest';
import { PolicyEngine } from './policy-engine';
import { RedisClient } from '../cache/redis-client';
import { Decision, IPolicy, IRequest } from './interfaces';

// Mock RedisClient
vi.mock('../cache/redis-client', () => {
    return {
        RedisClient: {
            getInstance: vi.fn(),
        }
    };
});

describe('PolicyEngine', () => {
    let policyEngine: PolicyEngine;
    let mockRedisClient: any;

    beforeEach(() => {
        mockRedisClient = {
            get: vi.fn(),
            set: vi.fn(),
        } as any;
        policyEngine = new PolicyEngine(mockRedisClient, false); // Disable cache for unit tests
    });

    it('should deny by default', async () => {
        const request: IRequest = {
            subject: 'user1',
            action: 'read',
            resource: 'doc1',
            context: { timestamp: new Date(), ip: '127.0.0.1' }
        };
        const decision = await policyEngine.evaluate(request);
        expect(decision).toBe(Decision.DENY);
    });

    it('should allow if a policy allows', async () => {
        const allowPolicy: IPolicy = {
            id: 'allow-all',
            evaluate: () => Decision.ALLOW,
        };
        policyEngine.addPolicy(allowPolicy);

        const request: IRequest = {
            subject: 'user1',
            action: 'read',
            resource: 'doc1',
            context: { timestamp: new Date(), ip: '127.0.0.1' }
        };

        const decision = await policyEngine.evaluate(request);
        expect(decision).toBe(Decision.ALLOW);
    });

    it('should deny if a policy specifically denies, even if another allows', async () => {
        const allowPolicy: IPolicy = {
            id: 'allow-all',
            evaluate: () => Decision.ALLOW,
        };
        const denyPolicy: IPolicy = {
            id: 'deny-specific',
            evaluate: () => Decision.DENY,
        };

        // Add both. Order primarily matters if we don't have precedence, 
        // but our engine logic says "If ANY returns DENY, fail fast".
        policyEngine.addPolicy(allowPolicy);
        policyEngine.addPolicy(denyPolicy);

        const request: IRequest = {
            subject: 'user1',
            action: 'read',
            resource: 'doc1',
            context: { timestamp: new Date(), ip: '127.0.0.1' }
        };

        const decision = await policyEngine.evaluate(request);
        expect(decision).toBe(Decision.DENY);
    });
});
