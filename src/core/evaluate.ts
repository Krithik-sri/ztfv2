import { IRequest, Decision, EvaluationResult, AuditEvent } from './interfaces.js';
import { PolicyEngine } from './policy-engine.js';
import { SessionManager } from '../auth/session-manager.js';
import { ContextEvaluator } from './context.js';
import { RedisUnavailableError, InvalidSessionTokenError } from './errors.js';

/**
 * Framework-agnostic HTTP request shape.
 * Framework adapters map their native request objects to this interface.
 */
export interface GenericHttpRequest {
  /** HTTP method (e.g., 'GET', 'POST') */
  method: string;
  /** Request path (e.g., '/admin/dashboard') */
  path: string;
  /** Request headers */
  headers: Record<string, string | string[] | undefined>;
  /** Client IP address */
  ip?: string;
  /** Socket for fallback IP extraction */
  socket?: { remoteAddress?: string };
}

/**
 * Result of the framework-agnostic evaluation.
 */
export interface EvaluateHttpResult {
  /** The policy decision */
  decision: Decision;
  /** Evaluation details */
  result: EvaluationResult;
  /** Authenticated user info (null for anonymous) */
  user: { id: string; roles: string[] } | null;
}

/**
 * Framework-agnostic evaluation function.
 *
 * This is the core logic shared by all framework adapters (Express, Fastify, Koa, Hono).
 * It handles:
 * 1. Session token extraction and verification
 * 2. Context building
 * 3. Policy evaluation
 *
 * Framework adapters only need to map their native request type to GenericHttpRequest
 * and handle the response based on the returned EvaluateHttpResult.
 *
 * @throws {RedisUnavailableError} if Redis is down (adapter should return 503)
 * @throws {InvalidSessionTokenError} if the bearer token is tampered
 */
export async function evaluateHttpRequest(
  req: GenericHttpRequest,
  policyEngine: PolicyEngine,
  sessionManager: SessionManager,
  options: {
    resourceExtractor?: (req: GenericHttpRequest) => string;
    actionExtractor?: (req: GenericHttpRequest) => string;
  } = {},
): Promise<EvaluateHttpResult> {
  // 1. Extract session from Bearer token
  let userId = 'anonymous';
  let roles: string[] = [];
  let user: { id: string; roles: string[] } | null = null;

  const authHeader = req.headers['authorization'] ?? req.headers['Authorization'];
  const authValue = Array.isArray(authHeader) ? authHeader[0] : authHeader;

  if (authValue && authValue.startsWith('Bearer ')) {
    const token = authValue.slice(7);
    try {
      const session = await sessionManager.getSession(token);
      if (session) {
        userId = session.userId;
        roles = session.roles;
        user = { id: userId, roles };
      }
    } catch (err) {
      if (err instanceof InvalidSessionTokenError) {
        // Tampered token — treat as anonymous (policy will deny)
        // Don't throw — let the policy engine make the decision
      } else {
        throw err; // Redis errors propagate up
      }
    }
  }

  // 2. Build context
  const context = await ContextEvaluator.buildContext(req, { userId, roles });

  // 3. Determine resource and action
  const action = options.actionExtractor ? options.actionExtractor(req) : req.method.toLowerCase();
  const resource = options.resourceExtractor ? options.resourceExtractor(req) : req.path;

  const accessRequest: IRequest = {
    subject: userId,
    action,
    resource,
    context,
  };

  // 4. Evaluate
  const decision = await policyEngine.evaluate(accessRequest);

  return {
    decision,
    result: {
      decision,
      policyId: null, // The engine already emitted audit events internally
      cached: false,
    },
    user,
  };
}
