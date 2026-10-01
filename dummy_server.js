const http = require('http');
const crypto = require('crypto');

const PORT = process.env.PORT || 4000;

// In-Memory Storage
const db = {
  users: new Map(),
  notes: new Map(),
  notices: new Map(),
  autoInc: 1
};

// Helper: Generate a real (but mathematically valid) JWT
function createJwt(payload) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const hBase64 = Buffer.from(JSON.stringify(header)).toString('base64url');
  const pBase64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', 'super-secret').update(`${hBase64}.${pBase64}`).digest('base64url');
  return `${hBase64}.${pBase64}.${sig}`;
}

// Helper: Parse JSON Body
function parseBody(req) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', chunk => body += chunk.toString());
    req.on('end', () => {
      try { resolve(body ? JSON.parse(body) : {}); } 
      catch (e) { resolve({}); }
    });
  });
}

// Helper: Send JSON Response
function sendJson(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

// Helper: Send Text Response
function sendText(res, status, text) {
  res.writeHead(status, { 'Content-Type': 'text/plain' });
  res.end(text);
}

const server = http.createServer(async (req, res) => {
  const url = req.url.split('?')[0];
  const method = req.method;
  
  // ==========================================
  // 1. Static Assets (Mocking Leaked Secrets)
  // ==========================================
  if (method === 'GET') {
    if (url === '/.git/HEAD') {
      return sendText(res, 200, "ref: refs/heads/master\ncommit a1b2c3d4");
    }
    if (url === '/static/js/main.js') {
      return sendText(res, 200, 'console.log("App loaded");\nconst SUPABASE_SERVICE_ROLE_KEY = "sk_live_123456789";\nconst jwt = "eyJhbGci.eyJzdWIi.signature";');
    }
    if (url === '/seed.json') {
      return sendText(res, 200, JSON.stringify({ admin_password: "super_secret_password_123" }));
    }
    if (url === '/webpack.config.js') {
      return sendText(res, 200, 'module.exports = { target: "node", env: "production" };');
    }
  }

  // ==========================================
  // 2. Auth Routes
  // ==========================================
  if (url === '/api/auth/register' && method === 'POST') {
    const body = await parseBody(req);
    const userId = `user_${db.autoInc++}`;
    db.users.set(body.email, { id: userId, email: body.email, role: body.role || 'user' });
    return sendJson(res, 201, { id: userId });
  }

  if (url === '/api/auth/login' && method === 'POST') {
    const body = await parseBody(req);
    const user = db.users.get(body.email) || { id: `user_${db.autoInc++}`, email: body.email, role: 'user' };
    db.users.set(body.email, user);
    
    // Issue a REAL JWT so the test framework can parse/modify it
    const token = createJwt({
      sub: user.id,
      email: user.email,
      role: user.role,
      aud: 'test-app',
      exp: Math.floor(Date.now() / 1000) + 86400
    });
    return sendJson(res, 200, { token, user_id: user.id });
  }

  if (url === '/api/auth/logout' && method === 'POST') {
    // INTENTIONAL FLAW: We return 200 but don't actually invalidate the token (No blacklist)
    return sendJson(res, 200, { success: true });
  }

  // ==========================================
  // 3. Flawed General/Misc Routes (Always 200)
  // ==========================================
  // These endpoints intentionally ignore ALL Zero-Trust headers, JWT validations, etc.
  const openRoutes = [
    '/api/me', '/api/protected/action', '/api/protected/v2_tampered', 
    '/api/settings', '/api/billing', '/api/billing/upgrade', '/api/events'
  ];
  if (openRoutes.includes(url) || url.includes('restore') || url.includes('/bulk')) {
    if (url.includes('restore')) {
       // INTENTIONAL FLAW: Return 200 for restore, but DO NOT modify the data in memory.
       return sendJson(res, 200, { restored: true });
    }
    return sendJson(res, 200, { success: true });
  }

  // ==========================================
  // 4. Flawed CRUD (Notes & Notices)
  // ==========================================
  if (url === '/api/notes' && method === 'GET') {
    return sendJson(res, 200, Array.from(db.notes.values()));
  }
  
  if (url === '/api/notes/list' && method === 'GET') {
    return sendJson(res, 200, Array.from(db.notes.values()));
  }

  if (url === '/api/notes' && method === 'POST') {
    const body = await parseBody(req);
    const id = db.autoInc++;
    const note = { id, ...body };
    db.notes.set(id.toString(), note);
    return sendJson(res, 201, note);
  }

  if (url === '/api/notices' && method === 'POST') {
    const body = await parseBody(req);
    const id = db.autoInc++;
    const notice = { id, ...body };
    db.notices.set(id.toString(), notice);
    return sendJson(res, 201, notice);
  }

  // Dynamic ID routes for Notes & Notices
  const noteMatch = url.match(/^\/api\/(notes|notices)\/(\w+)$/);
  if (noteMatch) {
    const [, resource, id] = noteMatch;
    const store = resource === 'notes' ? db.notes : db.notices;
    
    if (method === 'GET') {
      const item = store.get(id);
      if (item) return sendJson(res, 200, item);
      return sendJson(res, 404, { error: 'Not found' });
    }
    
    if (method === 'PUT') {
      const body = await parseBody(req);
      const item = store.get(id);
      if (item) {
        // INTENTIONAL FLAW: No BOLA or RBAC check. Anyone can mutate anything!
        const updated = { ...item, ...body };
        store.set(id, updated);
        return sendJson(res, 200, updated);
      }
      // If doesn't exist, we just create it (allows 9999_foreign test to 'work' and return 200)
      const newItem = { id, ...body };
      store.set(id, newItem);
      return sendJson(res, 201, newItem);
    }
    
    if (method === 'DELETE') {
      // INTENTIONAL FLAW: No ownership checks
      store.delete(id);
      return sendJson(res, 200, { deleted: true });
    }
  }

  // Default Catch-All
  return sendJson(res, 404, { error: 'Route not found' });
});

server.listen(PORT, () => {
  console.log(`[VULNERABLE] Dummy Target Server running on http://localhost:${PORT}`);
  console.log(`⚠️ This server intentionally lacks ALL security controls (BOLA, RBAC, Signature, JWT, RLS).`);
});
