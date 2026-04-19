import { Request, Response, NextFunction } from 'express';
import { IdentityProvider } from '../services/identity-provider';
import { RiskEngine } from '../services/risk-engine';
import { PolicyEngine } from '../services/policy-engine';
import { monitor } from '../services/monitor';
import { v4 as uuidv4 } from 'uuid';

export const zeroTrustMiddleware = async (req: Request, res: Response, next: NextFunction) => {
    const requestId = uuidv4();
    const timestamp = new Date().toISOString();
    const resource = req.path;

    // 1. Verify Identity
    const user = await IdentityProvider.verify(req);

    // 2. Assess Risk
    const risk = await RiskEngine.assess(req, user);

    // 3. Make Policy Decision
    const decision = PolicyEngine.decide(resource, user, risk);

    // 4. Log to Monitor (Zero Trust Visibility)
    monitor.logEvent({
        id: requestId,
        timestamp,
        user: user ? user.username : 'Anonymous',
        action: req.method,
        resource,
        trustScore: 100 - risk.score, // Invert risk for "Trust Score"
        status: decision,
        riskFactors: risk.factors
    });

    // 5. Enforce Decision
    if (decision === 'BLOCK') {
        res.status(403).json({
            error: 'Access Denied (Zero Trust)',
            reason: 'Policy violation or high risk detected',
            riskScore: risk.score,
            factors: risk.factors
        });
        return;
    }

    if (decision === 'CHALLENGE') {
        // In a real app, this would trigger MFA.
        // For this demo, we'll allow it but add a warning header
        res.setHeader('X-Zero-Trust-Warning', 'High Risk - Please verify identity');
        // We proceed, but maybe we want to block for the demo clarity if it's a challenge?
        // Let's block for now to show the red status clearly in the dashboard,
        // or we can allow with a warning.
        // Let's start with blocking for Challenge to make it obvious.
        res.status(403).json({
            error: 'Access Challenge Required',
            reason: 'Risk level requires additional verification',
            riskScore: risk.score
        });
        return;
    }

    // ALLOW
    next();
};
