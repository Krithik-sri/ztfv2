import { Request, Response, NextFunction } from 'express';
import { IPolicyEngine, IRequest, Decision } from '../core/interfaces';
import { SessionManager } from '../auth/session-manager';
import { ContextEvaluator } from '../core/context';

export interface ZeroTrustMiddlewareConfig {
    policyEngine: IPolicyEngine;
    sessionManager: SessionManager;
    // Function to extract resource/action from request if not standard
    resourceExtractor?: (req: Request) => string;
    actionExtractor?: (req: Request) => string;
}

export const zeroTrustGuard = (config: ZeroTrustMiddlewareConfig) => {
    const { policyEngine, sessionManager, resourceExtractor, actionExtractor } = config;

    return async (req: Request, res: Response, next: NextFunction) => {
        try {
            // 1. Identify User (Session)
            let userId = 'anonymous';
            let roles: string[] = [];

            // Assume Bearer token or Cookie. Let's look for Authorization header first.
            const authHeader = req.headers.authorization;
            if (authHeader && authHeader.startsWith('Bearer ')) {
                const sessionId = authHeader.split(' ')[1];
                const session = await sessionManager.getSession(sessionId);
                if (session) {
                    userId = session.userId;
                    roles = session.roles;
                    // Extend session? Maybe not on every request for performance, but usually yes.
                }
            }

            // 2. Build Context
            const context = await ContextEvaluator.buildContext(req, { userId, roles });

            // 3. Determine Resource and Action
            // defaults: method = action, path = resource
            const action = actionExtractor ? actionExtractor(req) : req.method.toLowerCase();
            const resource = resourceExtractor ? resourceExtractor(req) : req.path;

            const accessRequest: IRequest = {
                subject: userId,
                action,
                resource,
                context
            };

            // 4. Evaluate Policy
            const decision = await policyEngine.evaluate(accessRequest);

            if (decision === Decision.ALLOW) {
                // Attach user info to request for downstream use
                (req as any).user = { id: userId, roles };
                next();
            } else {
                res.status(403).json({ error: 'Access Denied', request: accessRequest });
            }

        } catch (error) {
            console.error('Zero Trust Middleware Error:', error);
            res.status(500).json({ error: 'Internal Security Error' });
        }
    };
};
