/**
 * Thrown when a Redis operation fails due to connection issues.
 * Middleware should catch this and return 503 (fail closed).
 */
export class RedisUnavailableError extends Error {
  constructor(message = 'Redis is unavailable', public readonly cause?: unknown) {
    super(message);
    this.name = 'RedisUnavailableError';
  }
}

/**
 * Thrown when a session token fails HMAC verification.
 * This indicates a tampered or forged token.
 */
export class InvalidSessionTokenError extends Error {
  constructor(message = 'Invalid or tampered session token') {
    super(message);
    this.name = 'InvalidSessionTokenError';
  }
}

/**
 * Thrown when a policy's evaluate() function throws unexpectedly.
 * Wraps the original error with the policy ID for debugging.
 */
export class PolicyEvaluationError extends Error {
  constructor(
    public readonly policyId: string,
    message: string,
    public readonly cause?: unknown,
  ) {
    super(`Policy "${policyId}" evaluation failed: ${message}`);
    this.name = 'PolicyEvaluationError';
  }
}
