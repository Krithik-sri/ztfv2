# Changelog

All notable changes to this project will be documented in this file.

## [2.0.0] — 2026-04-20

### Breaking Changes

- **Constructor injection replaces singleton** — `RedisClient.getInstance()` is deprecated. Use `new RedisClient(url)` or `new RedisClient(ioredisInstance)`.
- **`SessionManager` now requires a `secret` parameter** — `new SessionManager(redis, secret, ttl)`.
- **`PolicyEngine` constructor takes an options object** — `new PolicyEngine({ redisClient, ... })` instead of positional args.
- **Session tokens are HMAC-signed** — `createSession()` returns `{ token }` instead of raw `sessionId`. Use `session.token` for client-facing tokens.
- **`IContext` and `ISession` no longer use `[key: string]: any`** — replaced with typed `metadata?: Record<string, unknown>`.

### Added

- **`Decision.ABSTAIN`** — Policies can now abstain from a decision. DENY wins over ALLOW; ABSTAIN is neutral. Falls through to configurable `defaultDecision` when no policy has an opinion.
- **Configurable `defaultDecision`** — Set on `PolicyEngine` constructor and `zeroTrustGuard()`. Defaults to `DENY`.
- **HMAC-SHA256 signed session tokens** — Raw Redis keys never leave the server. Timing-safe verification prevents timing attacks.
- **Graceful Redis failure** — Middleware returns `503 Service Unavailable` when Redis is down. Cache failures degrade gracefully (evaluated without cache). Never fails open.
- **`sessionManager.invalidateByUserId(userId)`** — Revoke all sessions for a user. Uses `SCAN` (not `KEYS`) to avoid blocking Redis.
- **Async `evaluate()` support** — Policies can return `Promise<Decision>` or `Decision`. The engine handles both via `Promise.resolve()`.
- **Policy `priority` field** — Higher-priority policies evaluate first. Short-circuits on first `DENY`.
- **`removePolicy(id)` returns `boolean`** — Indicates whether the policy was found.
- **`replacePolicy(id, newPolicy)`** — Atomic replacement of a policy by ID.
- **`onDecision` audit hook** — Fires on every evaluation with `{ request, result, timestamp, durationMs }`.
- **`onDeny` customisation** — Custom deny handler on `zeroTrustGuard()`.
- **`sessionManager.refresh(token, ttl?)`** — Sliding window session expiry.
- **Per-policy `cacheTtl` override** — Engine uses minimum cacheTtl across contributing policies. Set to `0` to disable caching.
- **Framework adapters** — `zeroTrustFastify()`, `zeroTrustKoa()`, `zeroTrustHono()` middlewares. Framework-agnostic `evaluateHttpRequest()` core.
- **Environment variable configuration** — `REDIS_URL`, `CACHE_TTL_SECONDS`, `SESSION_TTL_SECONDS`, `DEFAULT_DECISION`, `SESSION_SECRET`.
- **`loadConfig()` helper** — Loads configuration from env vars with sensible defaults and partial overrides.
- **`createRateLimitPolicy()`** — Built-in distributed rate limiting via Redis `INCR`+`EXPIRE`.
- **`createIpPolicy()`** — Built-in IP allowlist/denylist filtering.
- **Custom error classes** — `RedisUnavailableError`, `InvalidSessionTokenError`, `PolicyEvaluationError`.
- **Full TypeScript type exports** — All public types exported with JSDoc documentation.
- **78 unit tests** — Covering policy engine, session manager, Redis client, Express middleware, and built-in policies.

### Changed

- **Cache key generation** — Uses SHA-256 hash of `subject:action:resource:sortedRoles`. Previously used `JSON.stringify(context)` which included the timestamp, making the cache effectively useless.
- **Deny response** — No longer leaks the full `accessRequest` object in 403 responses.
- **`addPolicy()` with duplicate ID** — Now replaces the existing policy instead of creating a duplicate.

### Removed

- **`src/services/` directory** — Removed demo-only code (`identity-provider.ts`, `risk-engine.ts`, `monitor.ts`, `policy-engine.ts`). These were mock implementations not used by the framework.
- **`src/middleware/zero-trust.ts`** — Removed old middleware that used the demo services.
- **`uuid` dependency** — Replaced with Node.js built-in `crypto.randomUUID()`.

### Fixed

- **Unrelated policies blocking requests** — The root cause was policies returning `DENY` for requests they didn't care about. `Decision.ABSTAIN` fixes this at the type level.
- **Useless cache** — Cache keys now exclude the timestamp, so identical requests within the TTL hit the cache.
- **`@types/uuid` in production dependencies** — Moved to `devDependencies`.

### Security

- **Session ID enumeration** — Raw Redis keys (`session:<uuid>`) are never exposed to clients. Only HMAC-signed tokens leave the server.
- **Timing attacks** — Token verification uses `crypto.timingSafeEqual()`.
- **Information leakage** — 403 responses no longer include internal request details.
- **Fail-closed** — Redis failure → 503 (not 500 or silent pass-through).
