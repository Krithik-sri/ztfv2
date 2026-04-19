/**
 * Contextual information about the current request.
 * Built by the ContextEvaluator and passed to policies for evaluation.
 */
export interface IContext {
  /** Client IP address */
  ip: string;
  /** Client user-agent string */
  userAgent?: string;
  /** Timestamp when the request was received */
  timestamp: Date;
  /** Authenticated user ID, or undefined for anonymous */
  userId?: string;
  /** User's roles for RBAC decisions */
  roles?: string[];
  /** Extensible metadata bag for custom context data */
  metadata?: Record<string, unknown>;
}

/**
 * A normalized access request passed to the PolicyEngine for evaluation.
 * Framework adapters build this from HTTP requests.
 */
export interface IRequest {
  /** The user or service identity making the request */
  subject: string;
  /** The action being performed (e.g., 'get', 'post', 'delete') */
  action: string;
  /** The resource being accessed (e.g., '/admin/dashboard') */
  resource: string;
  /** Rich context about the request environment */
  context: IContext;
}

/**
 * Policy evaluation outcomes.
 *
 * Strategy: DENY wins over ALLOW; ABSTAIN is neutral.
 * - If ANY policy returns DENY → final decision is DENY (short-circuits).
 * - If at least one ALLOW and no DENY → final decision is ALLOW.
 * - If all ABSTAIN (or no policies registered) → falls through to configurable `defaultDecision`.
 */
export enum Decision {
  ALLOW = 'ALLOW',
  DENY = 'DENY',
  /**
   * The policy does not apply to this request and has no opinion.
   * This is the key fix for the "unrelated policies always DENY" bug:
   * policies that don't match a request should ABSTAIN instead of DENY.
   */
  ABSTAIN = 'ABSTAIN',
}

/**
 * A policy that can evaluate access requests.
 *
 * Policies may return synchronously or asynchronously — the engine
 * handles both via `Promise.resolve(policy.evaluate(req))`.
 */
export interface IPolicy {
  /** Unique policy identifier */
  id: string;
  /** Human-readable description */
  description?: string;
  /**
   * Evaluation priority. Higher numbers are evaluated first.
   * When two policies have the same priority, insertion order is preserved.
   * Default: 0
   */
  priority?: number;
  /**
   * Per-policy cache TTL override in seconds.
   * When set, the engine uses the minimum cacheTtl among all contributing policies.
   * Set to 0 to disable caching for requests that hit this policy.
   *
   * Tradeoff: Lower TTL = faster revocation but more Redis/compute load.
   * Higher TTL = better performance but stale decisions persist longer.
   */
  cacheTtl?: number;
  /** Evaluate the request and return a Decision (sync or async). */
  evaluate(request: IRequest): Promise<Decision> | Decision;
}

/**
 * The policy engine interface.
 * Implementations evaluate requests against registered policies.
 */
export interface IPolicyEngine {
  /** Evaluate a request against all registered policies. */
  evaluate(request: IRequest): Promise<Decision>;
  /** Register a new policy. */
  addPolicy(policy: IPolicy): void;
  /** Remove a policy by ID. Returns true if the policy was found and removed. */
  removePolicy(policyId: string): boolean;
  /** Replace a policy by ID. Returns true if the policy was found and replaced. */
  replacePolicy(policyId: string, newPolicy: IPolicy): boolean;
}

/**
 * Result of a policy evaluation, including which policy was decisive.
 */
export interface EvaluationResult {
  /** The final decision */
  decision: Decision;
  /** ID of the policy that was decisive (null if defaultDecision was used) */
  policyId: string | null;
  /** Whether the result was served from cache */
  cached: boolean;
  /** Optional reason/description */
  reason?: string;
}

/**
 * Audit event emitted on every policy evaluation.
 * Consumed by the `onDecision` hook for logging, metrics, or alerting.
 */
export interface AuditEvent {
  /** The access request that was evaluated */
  request: IRequest;
  /** The evaluation result */
  result: EvaluationResult;
  /** ISO 8601 timestamp of the evaluation */
  timestamp: string;
  /** Duration of evaluation in milliseconds */
  durationMs: number;
}

/**
 * Configuration options for the zeroTrustGuard middleware.
 */
export interface ZeroTrustGuardOptions {
  /** The policy engine instance to use for evaluating requests */
  policyEngine: IPolicyEngine;
  /** The session manager instance for session lookups */
  sessionManager: import('../auth/session-manager.js').SessionManager;
  /**
   * Default decision when the engine returns the configured default.
   * This is a middleware-level override — if not set, uses the engine's defaultDecision.
   * Defaults to Decision.DENY for fail-closed security.
   */
  defaultDecision?: Decision;
  /**
   * Customize the response when a request is denied.
   * If not provided, returns a 403 JSON response.
   */
  onDeny?: (req: unknown, res: unknown, result: EvaluationResult) => void;
  /**
   * Audit hook fired on every evaluation (allow, deny, or abstain).
   * Use for logging, metrics, or alerting.
   */
  onDecision?: (event: AuditEvent) => void;
  /** Custom function to extract the resource identifier from a request */
  resourceExtractor?: (req: unknown) => string;
  /** Custom function to extract the action from a request */
  actionExtractor?: (req: unknown) => string;
}
