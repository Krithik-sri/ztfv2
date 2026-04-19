import { Request } from 'express';
import { UserIdentity } from './identity-provider';

export interface RiskAssessment {
    score: number; // 0-100 (100 is failing/high risk, 0 is safe)
    factors: string[];
}

export class RiskEngine {
    /**
     * Assess risk based on user, time, ip, etc.
     */
    static async assess(req: Request, user: UserIdentity | null): Promise<RiskAssessment> {
        const factors: string[] = [];
        let riskScore = 0;

        // FACTOR 1: Unknown User
        if (!user) {
            riskScore += 100;
            factors.push('Unknown User');
            return { score: riskScore, factors };
        }

        // FACTOR 2: Strange IP (Simulation)
        const ip = req.ip || 'unknown';
        // Simulate "bad IP" if a specific header is passed
        if (req.headers['x-sim-risk'] === 'high-ip') {
            riskScore += 50;
            factors.push('Suspicious IP Address');
        }

        // FACTOR 3: Time of Day (Simulate "after hours" access)
        // For demo, we trigger this with a header too
        if (req.headers['x-sim-risk'] === 'after-hours') {
            riskScore += 30;
            factors.push('Access outside business hours');
        }

        // FACTOR 4: Device Health (Simulate unpatched device)
        if (req.headers['x-sim-device'] === 'unpatched') {
            riskScore += 40;
            factors.push('Device missing security patches');
        }

        return {
            score: Math.min(riskScore, 100),
            factors
        };
    }
}
