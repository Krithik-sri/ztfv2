import { Decision, EvaluationResult } from '../core/interfaces.js';
import { evaluateHttpRequest, GenericHttpRequest } from '../core/evaluate.js';
import { PolicyEngine } from '../core/policy-engine.js';
import { SessionManager } from '../auth/session-manager.js';
import { RedisUnavailableError } from '../core/errors.js';

/**
 * Koa-specific guard configuration.
 */
export interface KoaGuardConfig {
  policyEngine: PolicyEngine;
  sessionManager: SessionManager;
  defaultDecision?: Decision;
  onDeny?: (ctx: unknown, result: EvaluationResult) => void;
  resourceExtractor?: (ctx: unknown) => string;
  actionExtractor?: (ctx: unknown) => string;
}

/**
 * Koa middleware for Zero Trust access control.
 *
 * @example
 * ```typescript
 * import Koa from 'koa';
 * import { zeroTrustKoa } from 'ztfv2/middleware/koa';
 *
 * const app = new Koa();
 * app.use(zeroTrustKoa({ policyEngine, sessionManager }));
 * ```
 */
export const zeroTrustKoa = (config: KoaGuardConfig) => {
  const { policyEngine, sessionManager, onDeny, resourceExtractor, actionExtractor } = config;

  return async (ctx: Record<string, unknown>, next: () => Promise<void>) => {
    try {
      const koaCtx = ctx as {
        method: string;
        path: string;
        headers: Record<string, string | string[] | undefined>;
        ip?: string;
        request?: { ip?: string };
        socket?: { remoteAddress?: string };
      };

      const genericReq: GenericHttpRequest = {
        method: koaCtx.method,
        path: koaCtx.path,
        headers: koaCtx.headers,
        ip: koaCtx.ip ?? koaCtx.request?.ip,
        socket: koaCtx.socket,
      };

      const evalResult = await evaluateHttpRequest(
        genericReq,
        policyEngine,
        sessionManager,
        {
          resourceExtractor: resourceExtractor
            ? () => (resourceExtractor as (c: unknown) => string)(ctx)
            : undefined,
          actionExtractor: actionExtractor
            ? () => (actionExtractor as (c: unknown) => string)(ctx)
            : undefined,
        },
      );

      if (evalResult.decision === Decision.ALLOW) {
        (ctx as Record<string, unknown>).state = {
          ...((ctx as Record<string, unknown>).state as Record<string, unknown> ?? {}),
          user: evalResult.user,
        };
        await next();
      } else {
        if (onDeny) {
          onDeny(ctx, evalResult.result);
        } else {
          const koaResponse = ctx as { status: number; body: unknown };
          koaResponse.status = 403;
          koaResponse.body = {
            error: 'Access Denied',
            decision: evalResult.result.decision,
          };
        }
      }
    } catch (error) {
      if (error instanceof RedisUnavailableError) {
        const koaResponse = ctx as { status: number; body: unknown };
        koaResponse.status = 503;
        koaResponse.body = {
          error: 'Service Unavailable',
          message: 'Security infrastructure is temporarily unavailable.',
        };
      } else {
        throw error;
      }
    }
  };
};
