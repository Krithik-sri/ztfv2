import express from 'express';
import path from 'path';
import { zeroTrustMiddleware } from '../src/middleware/zero-trust';
import { monitor } from '../src/services/monitor';

const app = express();
const PORT = 3000;

// 1. Serve Dashboard (Public)
app.use(express.static(path.join(__dirname, '../public')));

// 2. Monitor API (Public for dashboard to work)
app.get('/api/monitor/events', (req, res) => {
    res.json(monitor.getEvents());
});

// 3. Public API (No Zero Trust)
app.get('/api/public', (req, res) => {
    res.json({ message: 'This is public data.' });
});

// 4. Protected API (Zero Trust Enforced)
// specific middleware usage
app.use('/api/protected', zeroTrustMiddleware);
app.get('/api/protected/resource', (req, res) => {
    res.json({ message: 'You accessed a protected resource!', secret: 'zt-secret-123' });
});

app.use('/api/admin', zeroTrustMiddleware);
app.get('/api/admin/settings', (req, res) => {
    res.json({ message: 'Admin settings accessed.', sensitive: true });
});


app.listen(PORT, () => {
    console.log(`Zero Trust App running at http://localhost:${PORT}`);
    console.log(`- Dashboard: http://localhost:${PORT}`);
    console.log(`- Public API: http://localhost:${PORT}/api/public`);
    console.log(`- Protected API: http://localhost:${PORT}/api/protected/resource (Try with headers!)`);
});
