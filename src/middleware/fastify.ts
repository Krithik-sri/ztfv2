import { Decision, EvaluationResult } from '../core/interfaces.js';
import { evaluateHttpRequest, GenericHttpRequest } from '../core/evaluate.js';
import { PolicyEngine } from '../core/policy-engine.js';
import { SessionManager } from '../auth/session-manager.js';
import { RedisUnavailableError } from '../core/errors.js';

/**
 * Fastify-specific guard configuration.
 */
export interface FastifyGuardConfig {
  policyEngine: PolicyEngine;
  sessionManager: SessionManager;
  defaultDecision?: Decision;
  onDeny?: (request: unknown, reply: unknown, result: EvaluationResult) => void;
  resourceExtractor?: (request: unknown) => string;
  actionExtractor?: (request: unknown) => string;
}

/**
 * Fastify preHandler hook for Zero Trust access control.
 *
 * @example
 * ```typescript
 * import Fastify from 'fastify';
 * import { zeroTrustFastify } from 'ztfv2/middleware/fastify';
 *
 * const app = Fastify();
 * app.addHook('preHandler', zeroTrustFastify({ policyEngine, sessionManager }));
 * ```
 */
export const zeroTrustFastify = (config: FastifyGuardConfig) => {
  const { policyEngine, sessionManager, onDeny, resourceExtractor, actionExtractor } = config;

  return async (request: Record<string, unknown>, reply: Record<string, unknown>) => {
    try {
      const req = request as {
        method: string;
        url: string;
        headers: Record<string, string | string[] | undefined>;
        ip?: string;
        socket?: { remoteAddress?: string };
      };

      const genericReq: GenericHttpRequest = {
        method: req.method,
        path: req.url.split('?')[0], // Strip query string
        headers: req.headers,
        ip: req.ip as string | undefined,
        socket: req.socket,
      };

      const evalResult = await evaluateHttpRequest(
        genericReq,
        policyEngine,
        sessionManager,
        {
          resourceExtractor: resourceExtractor
            ? () => (resourceExtractor as (r: unknown) => string)(request)
            : undefined,
          actionExtractor: actionExtractor
            ? () => (actionExtractor as (r: unknown) => string)(request)
            : undefined,
        },
      );

      if (evalResult.decision === Decision.ALLOW) {
        (request as Record<string, unknown>).user = evalResult.user;
        // Fastify preHandler — don't call reply, just return
      } else {
        if (onDeny) {
          onDeny(request, reply, evalResult.result);
        } else {
          const rep = reply as { code: (n: number) => { send: (body: unknown) => void } };
          rep.code(403).send({
            error: 'Access Denied',
            decision: evalResult.result.decision,
          });
        }
      }
    } catch (error) {
      if (error instanceof RedisUnavailableError) {
        const rep = reply as { code: (n: number) => { send: (body: unknown) => void } };
        rep.code(503).send({
          error: 'Service Unavailable',
          message: 'Security infrastructure is temporarily unavailable.',
        });
      } else {
        throw error;
      }
    }
  };
};
