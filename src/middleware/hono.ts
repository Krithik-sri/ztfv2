import { Decision, EvaluationResult } from '../core/interfaces.js';
import { evaluateHttpRequest, GenericHttpRequest } from '../core/evaluate.js';
import { PolicyEngine } from '../core/policy-engine.js';
import { SessionManager } from '../auth/session-manager.js';
import { RedisUnavailableError } from '../core/errors.js';

/**
 * Hono-specific guard configuration.
 */
export interface HonoGuardConfig {
  policyEngine: PolicyEngine;
  sessionManager: SessionManager;
  defaultDecision?: Decision;
  onDeny?: (c: unknown, result: EvaluationResult) => Response | void;
  resourceExtractor?: (c: unknown) => string;
  actionExtractor?: (c: unknown) => string;
}

/**
 * Hono middleware for Zero Trust access control.
 *
 * @example
 * ```typescript
 * import { Hono } from 'hono';
 * import { zeroTrustHono } from 'ztfv2/middleware/hono';
 *
 * const app = new Hono();
 * app.use('*', zeroTrustHono({ policyEngine, sessionManager }));
 * ```
 */
export const zeroTrustHono = (config: HonoGuardConfig) => {
  const { policyEngine, sessionManager, onDeny, resourceExtractor, actionExtractor } = config;

  return async (c: Record<string, unknown>, next: () => Promise<void>) => {
    try {
      const honoCtx = c as {
        req: {
          method: string;
          path: string;
          header: (name: string) => string | undefined;
          raw: { headers: Record<string, string | string[] | undefined> };
        };
        json: (body: unknown, status?: number) => Response;
        set: (key: string, value: unknown) => void;
      };

      // Build headers map from Hono's request
      const headers: Record<string, string | string[] | undefined> = {};
      if (honoCtx.req.raw?.headers) {
        const rawHeaders = honoCtx.req.raw.headers;
        if (typeof (rawHeaders as Record<string, unknown>).forEach === 'function') {
          (rawHeaders as unknown as Headers).forEach((value: string, key: string) => {
            headers[key.toLowerCase()] = value;
          });
        }
      }
      // Fallback: try to get authorization directly
      if (!headers['authorization']) {
        const auth = honoCtx.req.header('authorization');
        if (auth) headers['authorization'] = auth;
      }

      const genericReq: GenericHttpRequest = {
        method: honoCtx.req.method,
        path: honoCtx.req.path,
        headers,
      };

      const evalResult = await evaluateHttpRequest(
        genericReq,
        policyEngine,
        sessionManager,
        {
          resourceExtractor: resourceExtractor
            ? () => (resourceExtractor as (ctx: unknown) => string)(c)
            : undefined,
          actionExtractor: actionExtractor
            ? () => (actionExtractor as (ctx: unknown) => string)(c)
            : undefined,
        },
      );

      if (evalResult.decision === Decision.ALLOW) {
        honoCtx.set('user', evalResult.user);
        await next();
      } else {
        if (onDeny) {
          const result = onDeny(c, evalResult.result);
          if (result) return result;
        }
        return honoCtx.json({
          error: 'Access Denied',
          decision: evalResult.result.decision,
        }, 403);
      }
    } catch (error) {
      if (error instanceof RedisUnavailableError) {
        const honoCtx = c as { json: (body: unknown, status?: number) => Response };
        return honoCtx.json({
          error: 'Service Unavailable',
          message: 'Security infrastructure is temporarily unavailable.',
        }, 503);
      }
      throw error;
    }
  };
};
