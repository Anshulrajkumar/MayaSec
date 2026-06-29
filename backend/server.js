import 'dotenv/config';
import cors from 'cors';
import express from 'express';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = process.env.PORT || 5000;
const supabaseUrl = process.env.SUPABASE_URL?.replace(/\/+$/, '');
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY;
const dataDir = path.join(__dirname, '../data');
const usersFile = path.join(dataDir, 'users.json');

// Flexible CORS for deployment
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || true,
  credentials: true
}));
app.use(express.json());

// ===== IN-MEMORY STORES =====
let clients = [];
const recentEvents = [];
const connectedSites = new Map();

// User store: userId -> { email, apiKey, allowedDomains: [] }
const users = new Map();
// API key lookup: apiKey -> userId
const apiKeyIndex = new Map();

loadUserStore();

// ===== STATIC FILES =====
app.use('/sdk', express.static(path.join(__dirname, '../sdk')));
app.use('/', express.static(path.join(__dirname, '../dashboard')));

// ===== AUTH HELPERS =====
function authErrorMessage(data, fallback = 'Authentication request failed') {
  return data?.msg || data?.message || data?.error_description || data?.error || data?.error_code || fallback;
}

function publicUser(user) {
  if (!user) return null;
  return {
    id: user.id,
    email: user.email,
    user_metadata: user.user_metadata || {}
  };
}

function publicSession(data) {
  const session = data?.session || data;
  if (!session?.access_token) return null;
  return {
    access_token: session.access_token,
    refresh_token: session.refresh_token,
    expires_at: session.expires_at,
    expires_in: session.expires_in,
    token_type: session.token_type || 'bearer'
  };
}

async function callSupabaseAuth(pathname, { method = 'GET', body, accessToken } = {}) {
  if (!supabaseUrl || !supabaseAnonKey) {
    return {
      ok: false,
      status: 500,
      data: { error: 'Supabase auth is not configured. Set SUPABASE_URL and SUPABASE_ANON_KEY.' }
    };
  }

  try {
    const response = await fetch(`${supabaseUrl}/auth/v1${pathname}`, {
      method,
      headers: {
        apikey: supabaseAnonKey,
        authorization: `Bearer ${accessToken || supabaseAnonKey}`,
        'content-type': 'application/json'
      },
      body: body ? JSON.stringify(body) : undefined
    });
    const text = await response.text();
    const data = text ? JSON.parse(text) : {};
    return { ok: response.ok, status: response.status, data };
  } catch (error) {
    return {
      ok: false,
      status: 502,
      data: { error: `Unable to reach Supabase auth: ${error.message}` }
    };
  }
}

async function requireAuth(req, res, next) {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, '');
  if (!token) return res.status(401).json({ error: 'Missing auth token' });

  const result = await callSupabaseAuth('/user', { accessToken: token });
  if (!result.ok) {
    return res.status(401).json({ error: authErrorMessage(result.data, 'Invalid auth token') });
  }

  req.authUser = publicUser(result.data);
  req.authToken = token;
  next();
}

function normalizeDomain(domain) {
  const value = String(domain || '').trim().toLowerCase();
  if (!value) return '';

  try {
    return new URL(value.includes('://') ? value : `https://${value}`).hostname;
  } catch {
    return value.replace(/^https?:\/\//, '').split('/')[0].replace(/:\d+$/, '');
  }
}

function siteFromRequest(req) {
  const rawOrigin = req.headers.origin || req.headers.referer || 'Unknown';
  if (rawOrigin === 'Unknown') return { origin: rawOrigin, siteName: rawOrigin, hostname: rawOrigin };

  try {
    const parsed = new URL(rawOrigin);
    return {
      origin: parsed.origin,
      siteName: parsed.host.toLowerCase(),
      hostname: parsed.hostname.toLowerCase()
    };
  } catch {
    const siteName = String(rawOrigin).replace(/^https?:\/\//, '').replace(/\/$/, '').toLowerCase();
    return { origin: rawOrigin, siteName, hostname: siteName.replace(/:\d+$/, '') };
  }
}

function isAllowedDomain(hostname, allowedDomain) {
  return hostname === allowedDomain || hostname.endsWith(`.${allowedDomain}`);
}

function loadUserStore() {
  try {
    if (!fs.existsSync(usersFile)) return;

    const savedUsers = JSON.parse(fs.readFileSync(usersFile, 'utf8'));
    Object.entries(savedUsers).forEach(([userId, user]) => {
      if (!user?.email || !user?.apiKey) return;

      const userData = {
        email: user.email,
        apiKey: user.apiKey,
        allowedDomains: Array.isArray(user.allowedDomains) ? user.allowedDomains : []
      };
      users.set(userId, userData);
      apiKeyIndex.set(userData.apiKey, userId);
    });
    console.log(`Loaded ${users.size} registered user(s) from local store`);
  } catch (error) {
    console.error('Failed to load local user store:', error.message);
  }
}

function saveUserStore() {
  try {
    fs.mkdirSync(dataDir, { recursive: true });
    const serialized = Object.fromEntries(users.entries());
    const tmpFile = `${usersFile}.tmp`;
    fs.writeFileSync(tmpFile, JSON.stringify(serialized, null, 2));
    fs.renameSync(tmpFile, usersFile);
  } catch (error) {
    console.error('Failed to save local user store:', error.message);
  }
}

// ===== AUTH API =====
app.post('/api/auth/signup', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Missing email or password' });
  if (String(password).length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

  const result = await callSupabaseAuth('/signup', {
    method: 'POST',
    body: { email: String(email).trim(), password }
  });

  if (!result.ok) return res.status(result.status).json({ error: authErrorMessage(result.data) });

  const session = publicSession(result.data);
  res.json({
    user: publicUser(result.data.user),
    session,
    message: session ? 'Account created.' : 'Account created. Check your email to confirm it, then sign in.'
  });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Missing email or password' });

  const result = await callSupabaseAuth('/token?grant_type=password', {
    method: 'POST',
    body: { email: String(email).trim(), password }
  });

  if (!result.ok) return res.status(result.status).json({ error: authErrorMessage(result.data, 'Unable to sign in') });

  res.json({
    user: publicUser(result.data.user),
    session: publicSession(result.data)
  });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ user: req.authUser });
});

app.post('/api/auth/logout', requireAuth, async (req, res) => {
  await callSupabaseAuth('/logout', { method: 'POST', accessToken: req.authToken });
  res.json({ success: true });
});

// ===== USER REGISTRATION =====
// Called after dashboard auth to create or return the user's MayaSec API key.
app.post('/api/auth/register', requireAuth, (req, res) => {
  const userId = req.authUser.id;
  const email = req.authUser.email;
  if (!userId || !email) return res.status(400).json({ error: 'Missing userId or email' });

  if (users.has(userId)) {
    const user = users.get(userId);
    return res.json({ apiKey: user.apiKey, allowedDomains: user.allowedDomains });
  }

  const apiKey = 'ms_ak_' + crypto.randomBytes(8).toString('hex');
  const userData = { email, apiKey, allowedDomains: [] };
  users.set(userId, userData);
  apiKeyIndex.set(apiKey, userId);
  saveUserStore();

  console.log(`\nNew user registered: ${email} | API Key: ${apiKey}`);
  res.json({ apiKey, allowedDomains: [] });
});

// ===== DOMAIN MANAGEMENT =====
app.post('/api/auth/domains', requireAuth, (req, res) => {
  const userId = req.authUser.id;
  const { domain } = req.body || {};
  if (!domain) return res.status(400).json({ error: 'Missing domain' });

  const user = users.get(userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const cleanDomain = normalizeDomain(domain);
  if (!cleanDomain) return res.status(400).json({ error: 'Invalid domain' });

  if (!user.allowedDomains.includes(cleanDomain)) {
    user.allowedDomains.push(cleanDomain);
    saveUserStore();
    console.log(`\nDomain added for ${user.email}: ${cleanDomain}`);
  }

  res.json({ allowedDomains: user.allowedDomains });
});

app.delete('/api/auth/domains', requireAuth, (req, res) => {
  const userId = req.authUser.id;
  const { domain } = req.body || {};
  if (!domain) return res.status(400).json({ error: 'Missing domain' });

  const user = users.get(userId);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const cleanDomain = normalizeDomain(domain);
  user.allowedDomains = user.allowedDomains.filter(d => d !== cleanDomain);
  saveUserStore();
  res.json({ allowedDomains: user.allowedDomains });
});

// ===== SSE ENDPOINT =====
app.get('/api/events/stream', (req, res) => {
  const apiKey = req.query.apiKey;

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  const filtered = apiKey
    ? recentEvents.filter(e => e._apiKey === apiKey)
    : recentEvents;
  res.write(`data: ${JSON.stringify({ type: 'history', data: filtered })}\n\n`);

  const client = { res, apiKey };
  clients.push(client);

  req.on('close', () => {
    clients = clients.filter(c => c.res !== res);
  });
});

// ===== BOT DETECTION ENGINE =====
function analyzeBehavior(payload) {
  if (payload.type !== 'behavior_batch') return null;

  const events = Array.isArray(payload.events) ? payload.events : [];
  const clicks = events.filter(e => e.type === 'click');
  const moves = events.filter(e => e.type === 'mousemove');

  if (clicks.length >= 8) {
    return {
      reason: 'BOT_BEHAVIOR_DETECTED',
      details: `Click Spamming: ${clicks.length} rapid clicks detected.`,
      confidence: 'High (95%)'
    };
  }

  if (clicks.length > 0 && moves.length === 0) {
    return {
      reason: 'BOT_BEHAVIOR_DETECTED',
      details: 'Non-human interaction: Click occurred with zero mouse trajectory.',
      confidence: 'Medium (80%)'
    };
  }

  return null;
}

// ===== BROADCAST HELPER =====
function broadcast(payload) {
  clients.forEach(client => {
    if (client.apiKey && payload._apiKey !== client.apiKey) return;
    client.res.write(`data: ${JSON.stringify({ type: 'new_event', data: payload })}\n\n`);
  });
}

function broadcastSites(apiKey) {
  const sitesForKey = Array.from(connectedSites.values()).filter(s => s.apiKey === apiKey);
  clients.forEach(client => {
    if (client.apiKey && client.apiKey !== apiKey) return;
    client.res.write(`data: ${JSON.stringify({ type: 'sites_update', data: sitesForKey })}\n\n`);
  });
}

// ===== SITES API =====
app.get('/api/sites', (req, res) => {
  const apiKey = req.query.apiKey;
  if (apiKey) {
    const filtered = Array.from(connectedSites.values()).filter(s => s.apiKey === apiKey);
    return res.json(filtered);
  }
  res.json(Array.from(connectedSites.values()));
});

// ===== INGESTION API =====
app.post('/api/ingest', (req, res) => {
  const payload = req.body;
  if (!payload || typeof payload !== 'object') {
    return res.status(400).json({ error: 'Invalid event payload' });
  }

  const apiKey = payload.apiKey;
  const { origin, siteName, hostname } = siteFromRequest(req);
  payload.origin = siteName;
  payload._apiKey = apiKey || 'unregistered';

  if (apiKey && apiKeyIndex.has(apiKey)) {
    const userId = apiKeyIndex.get(apiKey);
    const user = users.get(userId);

    if (user.allowedDomains.length > 0) {
      const isAllowed = user.allowedDomains.some(d => isAllowedDomain(hostname, d));
      if (!isAllowed) {
        console.log(`\nBLOCKED: Event from ${siteName} rejected - not in allowed domains for ${user.email}`);
        return res.status(403).json({ error: 'Domain not authorized for this API key' });
      }
    }
  }

  const siteKey = `${siteName}_${apiKey || 'none'}`;
  if (!connectedSites.has(siteKey)) {
    connectedSites.set(siteKey, {
      name: siteName,
      url: origin,
      apiKey: apiKey || 'unregistered',
      eventCount: 0,
      lastSeen: Date.now(),
      firstSeen: Date.now()
    });
  }
  const site = connectedSites.get(siteKey);
  site.eventCount++;
  site.lastSeen = Date.now();

  recentEvents.unshift(payload);
  if (recentEvents.length > 200) recentEvents.pop();

  broadcast(payload);
  broadcastSites(apiKey || 'unregistered');

  if (payload.type === 'behavior_batch') {
    const threat = analyzeBehavior(payload);

    if (threat) {
      const alertPayload = {
        type: 'SECURITY_ALERT',
        sessionId: payload.sessionId,
        origin: siteName,
        _apiKey: apiKey || 'unregistered',
        data: threat,
        timestamp: Date.now()
      };

      recentEvents.unshift(alertPayload);
      broadcast(alertPayload);
      console.log(`\nMAYASEC THREAT ENGINE: Bot Detected on [${siteName}] -> ${threat.details}`);
    }
  }

  res.status(200).json({ success: true });
});

const server = app.listen(port, () => {
  console.log(`MayaSec backend listening on http://localhost:${port}`);
});

export { app, server };
