/**
 * Example application demonstrating ztfv2 Zero Trust Framework.
 *
 * Prerequisites:
 *   - Redis running on localhost:6379 (or set REDIS_URL)
 *   - SESSION_SECRET environment variable set
 *
 * Run: SESSION_SECRET=my-secret-key npx ts-node examples/app.ts
 */
import express from 'express';
import {
  RedisClient,
  PolicyEngine,
  SessionManager,
  zeroTrustGuard,
  Decision,
  createRateLimitPolicy,
  createIpPolicy,
  loadConfig,
} from '../src/index.js';

const config = loadConfig({ sessionSecret: process.env.SESSION_SECRET || 'example-secret-change-in-production' });

const app = express();
app.use(express.json());

// ─── Initialize Components ───────────────────────────────────────────────────

const redisClient = new RedisClient(config.redisUrl);
const sessionManager = new SessionManager(redisClient, config.sessionSecret, config.sessionTtlSeconds);

const policyEngine = new PolicyEngine({
  redisClient,
  defaultDecision: config.defaultDecision,
  cacheTtlSeconds: config.cacheTtlSeconds,
  onDecision: (event) => {
    console.log(`[AUDIT] ${event.result.decision} | ${event.request.subject} → ${event.request.action} ${event.request.resource} | ${event.result.reason} (${event.durationMs}ms)`);
  },
});

// ─── Define Policies ─────────────────────────────────────────────────────────

// Policy: Allow public routes (login, health)
policyEngine.addPolicy({
  id: 'public-routes',
  priority: 50,
  evaluate: (req) => {
    if (req.resource === '/login' || req.resource === '/health') {
      return Decision.ALLOW;
    }
    return Decision.ABSTAIN; // Not my concern — let other policies decide
  },
});

// Policy: Admin-only routes
policyEngine.addPolicy({
  id: 'admin-only',
  priority: 40,
  evaluate: (req) => {
    if (req.resource.startsWith('/admin')) {
      if (req.context.roles?.includes('admin')) {
        return Decision.ALLOW;
      }
      return Decision.DENY;
    }
    return Decision.ABSTAIN; // Not an admin route — no opinion
  },
});

// Policy: Authenticated users can access protected resources
policyEngine.addPolicy({
  id: 'authenticated-access',
  priority: 30,
  evaluate: (req) => {
    if (req.resource.startsWith('/api/protected')) {
      if (req.subject !== 'anonymous') {
        return Decision.ALLOW;
      }
      return Decision.DENY;
    }
    return Decision.ABSTAIN;
  },
});

// Built-in rate limiter
policyEngine.addPolicy(createRateLimitPolicy({
  maxRequests: 100,
  windowSecs: 60,
  redisClient,
}));

// Built-in IP filter
policyEngine.addPolicy(createIpPolicy({
  denylist: ['10.0.0.666'], // Example: block known bad IPs
}));

// ─── Apply Middleware ────────────────────────────────────────────────────────

app.use(zeroTrustGuard({
  policyEngine,
  sessionManager,
  onDeny: (req, res, result) => {
    res.status(403).json({
      error: 'Access Denied',
      reason: result.reason,
    });
  },
}));

// ─── Routes ──────────────────────────────────────────────────────────────────

app.get('/health', (_req, res) => {
  res.json({ status: 'ok' });
});

app.post('/login', async (req, res) => {
  // In a real app, verify credentials here
  const { username, role } = req.body;
  const session = await sessionManager.createSession(
    username ?? 'user-123',
    [role ?? 'user'],
  );
  // Return the signed token — not the raw sessionId
  res.json({ token: session.token });
});

app.get('/api/protected/resource', (req, res) => {
  const user = (req as Record<string, unknown>).user;
  res.json({ message: 'Protected resource accessed!', user });
});

app.get('/admin/dashboard', (req, res) => {
  const user = (req as Record<string, unknown>).user;
  res.json({ message: 'Admin dashboard', user });
});

// ─── Start Server ────────────────────────────────────────────────────────────

const PORT = process.env.PORT ?? 3000;

async function start() {
  await redisClient.connect();
  app.listen(PORT, () => {
    console.log(`Zero Trust App running at http://localhost:${PORT}`);
    console.log('─────────────────────────────────────────');
    console.log('Try:');
    console.log(`  POST http://localhost:${PORT}/login`);
    console.log(`  GET  http://localhost:${PORT}/health`);
    console.log(`  GET  http://localhost:${PORT}/api/protected/resource (with Bearer token)`);
    console.log(`  GET  http://localhost:${PORT}/admin/dashboard (with admin Bearer token)`);
  });
}

start().catch(console.error);
