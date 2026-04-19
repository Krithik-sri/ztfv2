import { UserIdentity } from './identity-provider';
import { RiskAssessment } from './risk-engine';

export type PolicyDecision = 'ALLOW' | 'BLOCK' | 'CHALLENGE';

export class PolicyEngine {
    /**
     * Decide access based on Policy Rules
     */
    static decide(resource: string, user: UserIdentity | null, risk: RiskAssessment): PolicyDecision {

        // RULE 1: Must be authenticated
        if (!user) {
            return 'BLOCK';
        }

        // RULE 2: Critical resources require Admin and Low Risk
        if (resource.includes('/admin')) {
            if (user.role !== 'admin') return 'BLOCK';
            if (risk.score > 20) return 'BLOCK'; // Strict risk threshold for admin
        }

        // RULE 3: General resources
        // If risk is very high -> Block
        if (risk.score >= 80) return 'BLOCK';

        // If risk is medium -> Challenge (Mocking challenge as block for now, or just logging)
        // In real world, this would redirect to MFA
        if (risk.score >= 50) return 'CHALLENGE';

        return 'ALLOW';
    }
}
