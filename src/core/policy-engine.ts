import { IPolicyEngine, IRequest, Decision, IPolicy } from './interfaces';
import { RedisClient } from '../cache/redis-client';

export class PolicyEngine implements IPolicyEngine {
    private policies: IPolicy[] = [];
    private redisClient: RedisClient;
    private cacheEnabled: boolean;
    private defaultDecision: Decision;

    constructor(redisClient: RedisClient, cacheEnabled: boolean = true, defaultDecision: Decision = Decision.DENY) {
        this.redisClient = redisClient;
        this.cacheEnabled = cacheEnabled;
        this.defaultDecision = defaultDecision;
    }

    public addPolicy(policy: IPolicy): void {
        this.policies.push(policy);
    }

    public removePolicy(policyId: string): void {
        this.policies = this.policies.filter(p => p.id !== policyId);
    }

    public async evaluate(request: IRequest): Promise<Decision> {
        const cacheKey = this.generateCacheKey(request);

        if (this.cacheEnabled) {
            const cachedDecision = await this.redisClient.get(cacheKey);
            if (cachedDecision) {
                return cachedDecision as Decision;
            }
        }

        let decision = this.defaultDecision;

        // Simple strategy: If any policy allows, we allow. (OR logic)
        // Alternatively: We could have a strategy where all must allow, or specific priority.
        // For Zero Trust, typically "Explicit Allow" is required.
        // Let's iterate. If a policy returns ALLOW, we might stop or check others.
        // Let's assume a "First Match" or "Consensus" approach?
        // Let's go with: Default DENY. If ANY policy explicitly ALLOWS, and NO policy explicitly DENIES (priority to DENY).

        let hasAllow = false;
        let hasDeny = false;

        for (const policy of this.policies) {
            const result = await policy.evaluate(request);
            if (result === Decision.DENY) {
                hasDeny = true;
                break; // Fail fast
            }
            if (result === Decision.ALLOW) {
                hasAllow = true;
            }
        }

        if (hasDeny) {
            decision = Decision.DENY;
        } else if (hasAllow) {
            decision = Decision.ALLOW;
        }

        if (this.cacheEnabled) {
            await this.redisClient.set(cacheKey, decision, 60); // Cache for 60 seconds
        }

        return decision;
    }

    private generateCacheKey(request: IRequest): string {
        // Simple key generation. In production, might need hashing.
        const key = `policy:${request.subject}:${request.action}:${request.resource}:${JSON.stringify(request.context)}`;
        return key;
    }
}
