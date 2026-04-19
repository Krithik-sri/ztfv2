const http = require('http');

const makeRequest = (path, headers = {}) => {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: 'localhost',
      port: 3000,
      path: path,
      method: 'GET',
      headers: headers
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        resolve({ status: res.statusCode, body: data });
      });
    });

    req.on('error', (e) => reject(e));
    req.end();
  });
};

async function run() {
  try {
    console.log('--- 1. Public Access ---');
    const pub = await makeRequest('/api/public');
    console.log(`Status: ${pub.status}, Body: ${pub.body}`);

    console.log('\n--- 2. Protected (Unauthenticated) ---');
    const protectedNoAuth = await makeRequest('/api/protected/resource');
    console.log(`Status: ${protectedNoAuth.status}, Body: ${protectedNoAuth.body}`);

    console.log('\n--- 3. Protected (User Token) ---');
    const protectedUser = await makeRequest('/api/protected/resource', { 'Authorization': 'Bearer user-token' });
    console.log(`Status: ${protectedUser.status}, Body: ${protectedUser.body}`);

    console.log('\n--- 4. Admin (Admin Token) ---');
    const admin = await makeRequest('/api/admin/settings', { 'Authorization': 'Bearer admin-token' });
    console.log(`Status: ${admin.status}, Body: ${admin.body}`);

    console.log('\n--- 5. Protected (High Risk IP) ---');
    const highRisk = await makeRequest('/api/protected/resource', { 
        'Authorization': 'Bearer user-token',
        'X-Sim-Risk': 'high-ip'
    });
    console.log(`Status: ${highRisk.status}, Body: ${highRisk.body}`);

  } catch (error) {
    console.error('Error:', error.message);
  }
}

run();
