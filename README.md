# Zero Trust Framework v2 (ztfv2)

A Redis-backed Zero Trust security framework for Node.js/TypeScript.

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)]()
[![License: ISC](https://img.shields.io/badge/License-ISC-blue.svg)](https://opensource.org/licenses/ISC)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0-blue)](https://www.typescriptlang.org/)

## Overview

**ztfv2** enforces strict identity verification and least-privilege access for every request. It uses a policy engine with **ABSTAIN/ALLOW/DENY** decisions, **HMAC-signed session tokens**, and **Redis** for high-performance caching and session storage.

### Key Features

- **ABSTAIN-aware Policy Engine** — Policies return ALLOW, DENY, or ABSTAIN. DENY wins. ABSTAIN is neutral. Unrelated policies no longer block requests.
- **HMAC-Signed Session Tokens** — Raw Redis keys never leave the server. Tokens are signed with SHA-256 HMAC.
- **Fail-Closed Redis** — Returns 503 when Redis is unavailable. Never silently fails open.
- **Priority + Short-Circuit** — Higher-priority policies evaluate first. DENY short-circuits immediately.
- **Audit Hooks** — `onDecision` fires on every evaluation with full context and timing.
- **Multi-Framework** — Drop-in middleware for Express, Fastify, Koa, and Hono.
- **Built-in Policies** — Rate limiting and IP filtering out of the box.
- **Constructor Injection** — No singletons. Full testability.

---

## Architecture & Flow

```mermaid
graph TD
    A[Client Request] -->|Hit| B(Framework Middleware);
    B --> C{Bearer Token?};
    C -- Yes --> D[Verify HMAC Signature];
    D -- Invalid --> E[Treat as Anonymous];
    D -- Valid --> F[Load Session from Redis];
    C -- No --> E;
    F --> G[Build Context];
    E --> G;
    G --> H[Policy Engine];
    H --> I{Check Cache?};
    I -- Hit --> J[Return Cached Decision];
    I -- Miss --> K[Evaluate Policies by Priority];
    K --> L{Any DENY?};
    L -- Yes --> M[Short-circuit → DENY];
    L -- No --> N{Any ALLOW?};
    N -- Yes --> O[Decision: ALLOW];
    N -- No --> P[Decision: defaultDecision];
    M --> Q[Cache Decision];
    O --> Q;
    P --> Q;
    J --> R{Decision?};
    Q --> R;
    R -- ALLOW --> S[Next Middleware / Route];
    R -- DENY --> T((403 Forbidden));
    R -- Redis Down --> U((503 Service Unavailable));
```

---

## Installation

```bash
npm install ztfv2
```

### Prerequisites

- **Node.js** ≥ 18 (uses `crypto.randomUUID`)
- **Redis** instance running (see [Redis Setup](#-redis-setup))

---

## Redis Setup

### Local (Docker)

```bash
docker run -d --name redis -p 6379:6379 redis:7-alpine
```

### Local (Native)

```bash
# macOS
brew install redis && brew services start redis

# Ubuntu/Debian
sudo apt install redis-server && sudo systemctl start redis
```

### Cloud

Set the `REDIS_URL` environment variable:

```bash
REDIS_URL=redis://username:password@your-redis-host:6379
```

---

## Quick Start

### 1. Set Environment Variables

```bash
# Required for session signing
SESSION_SECRET=your-secret-key-min-32-chars

# Optional (shown with defaults)
REDIS_URL=redis://localhost:6379
CACHE_TTL_SECONDS=60
SESSION_TTL_SECONDS=3600
DEFAULT_DECISION=DENY
```

### 2. Initialize Components

```typescript
import {
  RedisClient,
  PolicyEngine,
  SessionManager,
  zeroTrustGuard,
  Decision,
  loadConfig,
} from 'ztfv2';

const config = loadConfig();

// Constructor injection — no singletons
const redisClient = new RedisClient(config.redisUrl);
const sessionManager = new SessionManager(redisClient, config.sessionSecret);
const policyEngine = new PolicyEngine({
  redisClient,
  defaultDecision: config.defaultDecision,
  cacheTtlSeconds: config.cacheTtlSeconds,
  onDecision: (event) => {
    console.log(`[AUDIT] ${event.result.decision} ${event.request.resource}`);
  },
});
```

### 3. Define Policies with ABSTAIN

The key change from v1: **policies should return `ABSTAIN` for requests they don't care about**, not `DENY`. This fixes the bug where unrelated policies would block requests.

```typescript
// Correct v2 pattern — ABSTAIN for unrelated requests
policyEngine.addPolicy({
  id: 'admin-only',
  priority: 50,
  evaluate: (req) => {
    if (!req.resource.startsWith('/admin')) {
      return Decision.ABSTAIN; // Not my concern
    }
    return req.context.roles?.includes('admin')
      ? Decision.ALLOW
      : Decision.DENY;
  },
});

// Public routes
policyEngine.addPolicy({
  id: 'public-routes',
  priority: 40,
  evaluate: (req) => {
    if (req.resource === '/login' || req.resource === '/health') {
      return Decision.ALLOW;
    }
    return Decision.ABSTAIN;
  },
});
```

**Decision strategy:**
| Scenario | Result |
|---|---|
| Any policy returns DENY | **DENY** (short-circuits) |
| At least one ALLOW, no DENY | **ALLOW** |
| All ABSTAIN / no policies | **defaultDecision** (default: DENY) |

### 4. Apply Middleware

```typescript
import express from 'express';

const app = express();

app.use(zeroTrustGuard({
  policyEngine,
  sessionManager,
  onDeny: (req, res, result) => {
    res.status(403).json({ error: 'Forbidden', reason: result.reason });
  },
}));

// Create sessions on login
app.post('/login', async (req, res) => {
  // ... authenticate user ...
  const session = await sessionManager.createSession('user-123', ['admin']);
  res.json({ token: session.token }); // Signed token, NOT raw sessionId
});

app.listen(3000);
```

---

## Session Security

### Signed Tokens (HMAC-SHA256)

Session tokens are signed using HMAC-SHA256. The format is:

```
base64url(sessionId).base64url(hmac-sha256(sessionId, secret))
```

- The raw Redis key (`session:<uuid>`) **never leaves the server**
- Tokens are verified with timing-safe comparison to prevent timing attacks
- Tampered tokens are silently treated as anonymous (policy engine handles denial)

### Session Management

```typescript
// Create
const session = await sessionManager.createSession('user-id', ['role'], { department: 'IT' });
// Returns: { sessionId, token, userId, roles, createdAt, expiresAt, metadata }

// Verify & Retrieve
const session = await sessionManager.getSession(token);

// Refresh (sliding expiry)
await sessionManager.refresh(token);        // Uses default TTL
await sessionManager.refresh(token, 7200);  // Custom TTL (2 hours)

// Invalidate single session
await sessionManager.invalidateSession(token);

// Invalidate ALL sessions for a user (e.g., on password change)
const count = await sessionManager.invalidateByUserId('user-id');
```

---

## Fail-Open vs Fail-Closed

ztfv2 uses a **layered failure strategy**:

| Failure | Behavior | Why |
|---|---|---|
| Redis down (session lookup) | **503 Service Unavailable** | Can't verify identity → fail closed |
| Redis down (cache read) | **Evaluate policies without cache** | Cache is optimization, not security |
| Redis down (cache write) | **Log warning, continue** | Decision was already made |
| Policy throws error | **PolicyEvaluationError** | Surfaces the bug immediately |
| `onDecision` hook throws | **Log error, continue** | Audit failure shouldn't block requests |

> **Zero Trust principle**: When in doubt, deny. The `defaultDecision` is `DENY` and Redis failures return 503. The framework **never silently fails open**.

---

## Policy Priority & Caching

### Priority

Policies are evaluated in priority order (highest first). Use this to ensure critical checks run first:

```typescript
policyEngine.addPolicy({
  id: 'rate-limit',
  priority: 100,  // Checked first — reject abusers fast
  evaluate: (req) => { /* ... */ },
});

policyEngine.addPolicy({
  id: 'rbac',
  priority: 50,   // Checked after rate limit
  evaluate: (req) => { /* ... */ },
});
```

### Per-Policy Cache TTL

```typescript
policyEngine.addPolicy({
  id: 'static-check',
  cacheTtl: 300,   // Cache for 5 minutes — this policy rarely changes
  evaluate: (req) => { /* ... */ },
});

policyEngine.addPolicy({
  id: 'rate-limit',
  cacheTtl: 0,     // NEVER cache — must check on every request
  evaluate: (req) => { /* ... */ },
});
```

> **Tradeoff**: Lower TTL = faster revocation but more Redis/compute load. Higher TTL = better performance but stale decisions persist longer. The engine uses the **minimum** cacheTtl across all contributing policies.

---

## Built-in Policies

### Rate Limiting

```typescript
import { createRateLimitPolicy } from 'ztfv2';

policyEngine.addPolicy(createRateLimitPolicy({
  maxRequests: 100,
  windowSecs: 60,
  redisClient,
  keyExtractor: (req) => req.context.ip, // Rate limit by IP (default: by user)
}));
```

### IP Filtering

```typescript
import { createIpPolicy } from 'ztfv2';

policyEngine.addPolicy(createIpPolicy({
  denylist: ['10.0.0.1', '192.168.1.100'],  // Block specific IPs
  allowlist: ['10.0.0.0'],                    // Only allow these IPs
}));
```

> Denylist is checked **before** allowlist (DENY wins).

---

## Framework Adapters

### Express (default)

```typescript
import { zeroTrustGuard } from 'ztfv2';
app.use(zeroTrustGuard({ policyEngine, sessionManager }));
```

### Fastify

```typescript
import { zeroTrustFastify } from 'ztfv2';
app.addHook('preHandler', zeroTrustFastify({ policyEngine, sessionManager }));
```

### Koa

```typescript
import { zeroTrustKoa } from 'ztfv2';
app.use(zeroTrustKoa({ policyEngine, sessionManager }));
```

### Hono

```typescript
import { zeroTrustHono } from 'ztfv2';
app.use('*', zeroTrustHono({ policyEngine, sessionManager }));
```

All adapters share the same core evaluation logic. They return **403** on DENY and **503** when Redis is unavailable.

---

## Policy Management

```typescript
// Add (replaces if same ID exists)
policyEngine.addPolicy({ id: 'my-policy', evaluate: (req) => Decision.ALLOW });

// Remove
policyEngine.removePolicy('my-policy'); // Returns true if found

// Replace
policyEngine.replacePolicy('my-policy', { id: 'my-policy', evaluate: updatedFn });

// List
const policies = policyEngine.getPolicies();
```

---

## Audit Hook

The `onDecision` hook fires on **every** evaluation (allow, deny, cache hit):

```typescript
const policyEngine = new PolicyEngine({
  redisClient,
  onDecision: async (event) => {
    // event.request  — the access request
    // event.result   — { decision, policyId, cached, reason }
    // event.timestamp — ISO 8601
    // event.durationMs — evaluation time
    await logToSIEM(event);
  },
});
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `REDIS_URL` | `redis://localhost:6379` | Redis connection URL |
| `SESSION_SECRET` | *(required)* | HMAC secret for token signing |
| `CACHE_TTL_SECONDS` | `60` | Default policy decision cache TTL |
| `SESSION_TTL_SECONDS` | `3600` | Session expiry in seconds |
| `DEFAULT_DECISION` | `DENY` | Fallback when no policy has an opinion |

---

## Testing

```bash
npm test          # Run all tests
npm run test:watch # Watch mode
npm run build     # Build for production
```

The framework uses constructor injection throughout, so testing is straightforward:

```typescript
// In your tests — no Redis needed
const mockRedis = {
  get: vi.fn().mockResolvedValue(null),
  set: vi.fn(),
  del: vi.fn(),
  // ...
} as any;

const engine = new PolicyEngine({
  redisClient: mockRedis,
  cacheEnabled: false,
});
```

---

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

---

**License**: ISC
