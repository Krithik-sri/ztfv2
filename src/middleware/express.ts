import { Request, Response, NextFunction } from 'express';
import { Decision, EvaluationResult, AuditEvent, ZeroTrustGuardOptions } from '../core/interfaces.js';
import { evaluateHttpRequest, GenericHttpRequest } from '../core/evaluate.js';
import { PolicyEngine } from '../core/policy-engine.js';
import { SessionManager } from '../auth/session-manager.js';
import { RedisUnavailableError } from '../core/errors.js';

/**
 * Express-specific configuration for the Zero Trust middleware.
 * Extends the framework-agnostic ZeroTrustGuardOptions with Express types.
 */
export interface ExpressGuardConfig {
  /** The policy engine instance */
  policyEngine: PolicyEngine;
  /** The session manager instance */
  sessionManager: SessionManager;
  /**
   * Default decision when no policy matches. Defaults to DENY (fail-closed).
   * This is a safety net — in a well-configured system, at least one policy
   * should always have an opinion.
   */
  defaultDecision?: Decision;
  /**
   * Custom deny handler. Receives the Express req/res and the evaluation result.
   * If not provided, returns a 403 JSON response.
   *
   * Note: The full request details are NOT included in the default response
   * to avoid leaking internal information to attackers.
   */
  onDeny?: (req: Request, res: Response, result: EvaluationResult) => void;
  /**
   * Audit hook fired on every evaluation.
   * Runs asynchronously — errors are caught and logged.
   */
  onDecision?: (event: AuditEvent) => void | Promise<void>;
  /** Custom resource extractor */
  resourceExtractor?: (req: Request) => string;
  /** Custom action extractor */
  actionExtractor?: (req: Request) => string;
}

/**
 * Express middleware that enforces Zero Trust access control on every request.
 *
 * Behavior:
 * - Extracts Bearer token from Authorization header
 * - Verifies the signed session token (HMAC)
 * - Builds request context and evaluates policies
 * - On ALLOW: attaches `req.user` and calls `next()`
 * - On DENY: calls `onDeny` handler or returns 403
 * - On Redis failure: returns 503 (fail-closed, never fail-open)
 *
 * @example
 * ```typescript
 * app.use(zeroTrustGuard({
 *   policyEngine,
 *   sessionManager,
 *   onDeny: (req, res, result) => {
 *     res.status(403).json({ error: 'Not allowed' });
 *   },
 * }));
 * ```
 */
export const zeroTrustGuard = (config: ExpressGuardConfig) => {
  const { policyEngine, sessionManager, onDeny, resourceExtractor, actionExtractor } = config;

  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Map Express request to GenericHttpRequest
      const genericReq: GenericHttpRequest = {
        method: req.method,
        path: req.path,
        headers: req.headers as Record<string, string | string[] | undefined>,
        ip: req.ip,
        socket: req.socket,
      };

      const evalResult = await evaluateHttpRequest(
        genericReq,
        policyEngine,
        sessionManager,
        {
          resourceExtractor: resourceExtractor
            ? (_generic) => resourceExtractor(req)
            : undefined,
          actionExtractor: actionExtractor
            ? (_generic) => actionExtractor(req)
            : undefined,
        },
      );

      if (evalResult.decision === Decision.ALLOW) {
        // Attach user info for downstream middleware/routes
        (req as unknown as Record<string, unknown>).user = evalResult.user;
        next();
      } else {
        if (onDeny) {
          onDeny(req, res, evalResult.result);
        } else {
          // Default deny response — intentionally minimal to avoid information leakage
          res.status(403).json({
            error: 'Access Denied',
            decision: evalResult.result.decision,
          });
        }
      }
    } catch (error) {
      if (error instanceof RedisUnavailableError) {
        // Fail closed: Redis is down → 503, not 500
        // Never silently fail open — this is a Zero Trust requirement
        console.error('[ztfv2] Redis unavailable, failing closed:', error.message);
        res.status(503).json({
          error: 'Service Unavailable',
          message: 'Security infrastructure is temporarily unavailable. Please retry.',
        });
      } else {
        console.error('[ztfv2] Middleware error:', error);
        res.status(500).json({ error: 'Internal Security Error' });
      }
    }
  };
};
