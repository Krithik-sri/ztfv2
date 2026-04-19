/**
 * ztfv2 — Zero Trust Framework v2
 *
 * A Redis-backed Zero Trust security framework for Node.js/TypeScript.
 * Enforces strict identity verification and least-privilege access for every request.
 *
 * @packageDocumentation
 */

// ─── Core Types & Interfaces ─────────────────────────────────────────────────
export {
  Decision,
  type IContext,
  type IRequest,
  type IPolicy,
  type IPolicyEngine,
  type EvaluationResult,
  type AuditEvent,
  type ZeroTrustGuardOptions,
} from './core/interfaces.js';

// ─── Core Engine ─────────────────────────────────────────────────────────────
export { PolicyEngine } from './core/policy-engine.js';
export type { PolicyEngineOptions } from './core/policy-engine.js';

// ─── Context ─────────────────────────────────────────────────────────────────
export { ContextEvaluator } from './core/context.js';

// ─── Framework-Agnostic Evaluate ─────────────────────────────────────────────
export { evaluateHttpRequest } from './core/evaluate.js';
export type { GenericHttpRequest, EvaluateHttpResult } from './core/evaluate.js';

// ─── Redis Client ────────────────────────────────────────────────────────────
export { RedisClient } from './cache/redis-client.js';

// ─── Session Management ──────────────────────────────────────────────────────
export { SessionManager } from './auth/session-manager.js';
export type { ISession } from './auth/session-manager.js';

// ─── Express Middleware ──────────────────────────────────────────────────────
export { zeroTrustGuard } from './middleware/express.js';
export type { ExpressGuardConfig } from './middleware/express.js';

// ─── Framework Adapters ──────────────────────────────────────────────────────
export { zeroTrustFastify } from './middleware/fastify.js';
export type { FastifyGuardConfig } from './middleware/fastify.js';

export { zeroTrustKoa } from './middleware/koa.js';
export type { KoaGuardConfig } from './middleware/koa.js';

export { zeroTrustHono } from './middleware/hono.js';
export type { HonoGuardConfig } from './middleware/hono.js';

// ─── Built-in Policies ──────────────────────────────────────────────────────
export { createRateLimitPolicy, createIpPolicy } from './policies/index.js';
export type { RateLimitPolicyOptions, IpPolicyOptions } from './policies/index.js';

// ─── Configuration ───────────────────────────────────────────────────────────
export { loadConfig } from './config.js';
export type { ZtfConfig } from './config.js';

// ─── Error Classes ───────────────────────────────────────────────────────────
export {
  RedisUnavailableError,
  InvalidSessionTokenError,
  PolicyEvaluationError,
} from './core/errors.js';
