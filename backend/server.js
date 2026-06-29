import 'dotenv/config';
import cors from 'cors';
import crypto from 'crypto';
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = process.env.PORT || 5000;
const supabaseUrl = process.env.SUPABASE_URL?.replace(/\/+$/, '');
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY;
const supabaseServiceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const appOrigin = process.env.APP_ORIGIN?.replace(/\/+$/, '') || '';
const isProduction = process.env.NODE_ENV === 'production';
const cookieSecure = process.env.COOKIE_SECURE !== 'false' && (isProduction || Boolean(appOrigin.startsWith('https://')));
const authCookieBase = {
  httpOnly: true,
  sameSite: 'Lax',
  secure: cookieSecure,
  path: '/'
};

let clients = [];
const recentEvents = [];
const connectedSites = new Map();

const ingestCors = cors({
  origin: true,
  credentials: false,
  methods: ['POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type']
});

const sdkCors = cors({
  origin: true,
  credentials: false,
  methods: ['GET', 'HEAD', 'OPTIONS']
});

app.use(express.json());
app.use('/sdk', sdkCors, express.static(path.join(__dirname, '../sdk')));

// Manually handle preflight for /api/ingest to guarantee correct headers
app.options('/api/ingest', (req, res) => {
  res.set({
    'Access-Control-Allow-Origin': req.headers.origin || '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Max-Age': '86400'
  });
  res.status(204).end();
});

app.use('/', express.static(path.join(__dirname, '../dashboard')));

validateRuntimeConfig();

function authErrorMessage(data, fallback = 'Authentication request failed') {
  return data?.msg || data?.message || data?.error_description || data?.error || data?.error_code || fallback;
}

function validateRuntimeConfig() {
  const missing = [];
  if (!supabaseUrl) missing.push('SUPABASE_URL');
  if (!supabaseAnonKey) missing.push('SUPABASE_ANON_KEY');
  if (!supabaseServiceRoleKey) missing.push('SUPABASE_SERVICE_ROLE_KEY');
  if (isProduction && !appOrigin) missing.push('APP_ORIGIN');

  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }
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

function parseCookies(req) {
  const header = req.headers.cookie;
  if (!header) return {};

  return Object.fromEntries(
    header.split(';').map(part => {
      const index = part.indexOf('=');
      const key = part.slice(0, index).trim();
      const value = part.slice(index + 1).trim();
      return [key, decodeURIComponent(value)];
    })
  );
}

function setAuthCookies(res, session) {
  if (!session?.access_token || !session?.refresh_token) return;

  const maxAgeMs = Math.max(Number(session.expires_in || 3600) * 1000, 60_000);
  res.cookie('mayasec_at', session.access_token, {
    ...authCookieBase,
    maxAge: maxAgeMs
  });
  res.cookie('mayasec_rt', session.refresh_token, {
    ...authCookieBase,
    maxAge: 1000 * 60 * 60 * 24 * 30
  });
}

function clearAuthCookies(res) {
  res.clearCookie('mayasec_at', { ...authCookieBase, maxAge: undefined });
  res.clearCookie('mayasec_rt', { ...authCookieBase, maxAge: undefined });
}

function readAccessToken(req) {
  const headerToken = req.headers.authorization?.replace(/^Bearer\s+/i, '');
  if (headerToken) return headerToken;
  const cookies = parseCookies(req);
  return cookies.mayasec_at || '';
}

function readRefreshToken(req) {
  const cookies = parseCookies(req);
  return cookies.mayasec_rt || '';
}

async function parseResponse(response) {
  const text = await response.text();
  if (!text) return {};

  try {
    return JSON.parse(text);
  } catch {
    return { raw: text };
  }
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
    return { ok: response.ok, status: response.status, data: await parseResponse(response) };
  } catch (error) {
    return {
      ok: false,
      status: 502,
      data: { error: `Unable to reach Supabase auth: ${error.message}` }
    };
  }
}

async function callSupabaseRest(pathname, { method = 'GET', body, prefer, headers = {} } = {}) {
  if (!supabaseUrl || !supabaseServiceRoleKey) {
    return {
      ok: false,
      status: 500,
      data: { error: 'Supabase database is not configured. Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY.' }
    };
  }

  try {
    const response = await fetch(`${supabaseUrl}/rest/v1/${pathname}`, {
      method,
      headers: {
        apikey: supabaseServiceRoleKey,
        authorization: `Bearer ${supabaseServiceRoleKey}`,
        'content-type': 'application/json',
        ...(prefer ? { Prefer: prefer } : {}),
        ...headers
      },
      body: body ? JSON.stringify(body) : undefined
    });
    return { ok: response.ok, status: response.status, data: await parseResponse(response) };
  } catch (error) {
    return {
      ok: false,
      status: 502,
      data: { error: `Unable to reach Supabase database: ${error.message}` }
    };
  }
}

function encodeFilterValue(value) {
  return encodeURIComponent(String(value));
}

async function getStoredUserById(userId) {
  const result = await callSupabaseRest(`mayasec_users?user_id=eq.${encodeFilterValue(userId)}&select=user_id,email,api_key,allowed_domains`);
  if (!result.ok) throw new Error(authErrorMessage(result.data, 'Failed to load MayaSec user'));

  const record = Array.isArray(result.data) ? result.data[0] : null;
  if (!record) return null;

  return {
    userId: record.user_id,
    email: record.email,
    apiKey: record.api_key,
    allowedDomains: Array.isArray(record.allowed_domains) ? record.allowed_domains : []
  };
}

async function getStoredUserByApiKey(apiKey) {
  const result = await callSupabaseRest(`mayasec_users?api_key=eq.${encodeFilterValue(apiKey)}&select=user_id,email,api_key,allowed_domains`);
  if (!result.ok) throw new Error(authErrorMessage(result.data, 'Failed to load MayaSec API key'));

  const record = Array.isArray(result.data) ? result.data[0] : null;
  if (!record) return null;

  return {
    userId: record.user_id,
    email: record.email,
    apiKey: record.api_key,
    allowedDomains: Array.isArray(record.allowed_domains) ? record.allowed_domains : []
  };
}

async function saveStoredUser({ userId, email, apiKey, allowedDomains }) {
  const result = await callSupabaseRest('mayasec_users?on_conflict=user_id', {
    method: 'POST',
    prefer: 'resolution=merge-duplicates,return=representation',
    body: [{
      user_id: userId,
      email,
      api_key: apiKey,
      allowed_domains: allowedDomains
    }]
  });

  if (!result.ok) throw new Error(authErrorMessage(result.data, 'Failed to save MayaSec user'));

  const record = Array.isArray(result.data) ? result.data[0] : null;
  return {
    userId: record?.user_id || userId,
    email: record?.email || email,
    apiKey: record?.api_key || apiKey,
    allowedDomains: Array.isArray(record?.allowed_domains) ? record.allowed_domains : allowedDomains
  };
}

async function refreshSession(refreshToken) {
  if (!refreshToken) {
    return { ok: false, status: 401, data: { error: 'Missing refresh token' } };
  }

  return callSupabaseAuth('/token?grant_type=refresh_token', {
    method: 'POST',
    body: { refresh_token: refreshToken }
  });
}

async function requireAuth(req, res, next) {
  let accessToken = readAccessToken(req);
  let authResult = accessToken ? await callSupabaseAuth('/user', { accessToken }) : null;

  if (!authResult?.ok) {
    const refreshToken = readRefreshToken(req);
    const refreshResult = await refreshSession(refreshToken);

    if (!refreshResult.ok) {
      clearAuthCookies(res);
      return res.status(401).json({ error: authErrorMessage(refreshResult.data, 'Authentication required') });
    }

    const refreshedSession = publicSession(refreshResult.data);
    setAuthCookies(res, refreshedSession);
    accessToken = refreshedSession.access_token;
    authResult = await callSupabaseAuth('/user', { accessToken });
  }

  if (!authResult?.ok) {
    clearAuthCookies(res);
    return res.status(401).json({ error: authErrorMessage(authResult?.data, 'Authentication required') });
  }

  req.authUser = publicUser(authResult.data);
  req.authToken = accessToken;
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

function authOriginAllowed(origin) {
  if (!origin) return true;
  if (!appOrigin) return origin === `http://localhost:${port}` || origin === 'http://localhost:5000';
  return origin === appOrigin;
}

function requireAppOrigin(req, res, next) {
  const origin = req.headers.origin || '';
  if (!authOriginAllowed(origin)) {
    return res.status(403).json({ error: 'Origin not allowed' });
  }
  next();
}

app.use('/api/auth', requireAppOrigin);

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
  if (session) setAuthCookies(res, session);

  res.json({
    user: publicUser(result.data.user),
    hasSession: Boolean(session),
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

  const session = publicSession(result.data);
  setAuthCookies(res, session);

  res.json({
    user: publicUser(result.data.user),
    hasSession: true
  });
});

app.get('/api/auth/google', (req, res) => {
  const redirectTo = appOrigin || `http://localhost:${port}`;
  const url = `${supabaseUrl}/auth/v1/authorize?provider=google&redirect_to=${encodeURIComponent(redirectTo + '/api/auth/callback')}`;
  res.redirect(url);
});

app.get('/api/auth/callback', async (req, res) => {
  const { access_token, refresh_token } = req.query;
  
  // If tokens come as hash fragments, Supabase redirects with them in the URL
  // We need a small page to extract them and send them to us
  if (!access_token) {
    // Serve a tiny page that reads hash fragments and sends them as query params
    return res.send(`<!DOCTYPE html><html><body><script>
      const hash = window.location.hash.substring(1);
      const params = new URLSearchParams(hash);
      const at = params.get('access_token');
      const rt = params.get('refresh_token');
      if (at) {
        fetch('/api/auth/token-exchange?access_token=' + at + '&refresh_token=' + (rt||''), { credentials: 'same-origin' })
          .then(() => window.location.href = '/')
          .catch(() => window.location.href = '/');
      } else { window.location.href = '/'; }
    </script></body></html>`);
  }

  // Direct query param tokens (some flows)
  if (access_token) {
    const maxAge = 3600 * 1000;
    res.cookie('mayasec_at', access_token, { ...authCookieBase, maxAge });
    if (refresh_token) {
      res.cookie('mayasec_rt', refresh_token, { ...authCookieBase, maxAge: 1000 * 60 * 60 * 24 * 30 });
    }
  }
  res.redirect('/');
});

app.get('/api/auth/token-exchange', (req, res) => {
  const { access_token, refresh_token } = req.query;
  if (!access_token) return res.status(400).json({ error: 'Missing token' });

  const maxAge = 3600 * 1000;
  res.cookie('mayasec_at', access_token, { ...authCookieBase, maxAge });
  if (refresh_token) {
    res.cookie('mayasec_rt', refresh_token, { ...authCookieBase, maxAge: 1000 * 60 * 60 * 24 * 30 });
  }
  res.json({ success: true });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ user: req.authUser });
});

app.post('/api/auth/logout', requireAuth, async (req, res) => {
  clearAuthCookies(res);
  await callSupabaseAuth('/logout', { method: 'POST', accessToken: req.authToken });
  res.json({ success: true });
});

app.post('/api/auth/register', requireAuth, async (req, res) => {
  const userId = req.authUser.id;
  const email = req.authUser.email;
  if (!userId || !email) return res.status(400).json({ error: 'Missing userId or email' });

  try {
    const existingUser = await getStoredUserById(userId);
    if (existingUser) {
      return res.json({ apiKey: existingUser.apiKey, allowedDomains: existingUser.allowedDomains });
    }

    const savedUser = await saveStoredUser({
      userId,
      email,
      apiKey: 'ms_ak_' + crypto.randomBytes(8).toString('hex'),
      allowedDomains: []
    });

    res.json({ apiKey: savedUser.apiKey, allowedDomains: savedUser.allowedDomains });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/auth/domains', requireAuth, async (req, res) => {
  const { domain } = req.body || {};
  if (!domain) return res.status(400).json({ error: 'Missing domain' });

  try {
    const storedUser = await getStoredUserById(req.authUser.id);
    if (!storedUser) return res.status(404).json({ error: 'User not found' });

    const cleanDomain = normalizeDomain(domain);
    if (!cleanDomain) return res.status(400).json({ error: 'Invalid domain' });

    const allowedDomains = storedUser.allowedDomains.includes(cleanDomain)
      ? storedUser.allowedDomains
      : [...storedUser.allowedDomains, cleanDomain];

    const savedUser = await saveStoredUser({ ...storedUser, allowedDomains });
    res.json({ allowedDomains: savedUser.allowedDomains });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/auth/domains', requireAuth, async (req, res) => {
  const { domain } = req.body || {};
  if (!domain) return res.status(400).json({ error: 'Missing domain' });

  try {
    const storedUser = await getStoredUserById(req.authUser.id);
    if (!storedUser) return res.status(404).json({ error: 'User not found' });

    const cleanDomain = normalizeDomain(domain);
    const savedUser = await saveStoredUser({
      ...storedUser,
      allowedDomains: storedUser.allowedDomains.filter(d => d !== cleanDomain)
    });

    res.json({ allowedDomains: savedUser.allowedDomains });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/events/stream', requireAuth, async (req, res) => {
  let userRecord;

  try {
    userRecord = await getStoredUserById(req.authUser.id);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }

  if (!userRecord?.apiKey) return res.status(404).json({ error: 'User not registered' });

  const apiKey = userRecord.apiKey;
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  const filtered = recentEvents.filter(event => event._apiKey === apiKey);
  res.write(`data: ${JSON.stringify({ type: 'history', data: filtered })}\n\n`);

  const client = { res, apiKey };
  clients.push(client);

  req.on('close', () => {
    clients = clients.filter(c => c.res !== res);
  });
});

function analyzeBehavior(payload) {
  if (payload.type !== 'behavior_batch') return null;

  const events = Array.isArray(payload.events) ? payload.events : [];
  const clicks = events.filter(event => event.type === 'click');
  const moves = events.filter(event => event.type === 'mousemove');

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

function broadcast(payload) {
  clients.forEach(client => {
    if (client.apiKey && payload._apiKey !== client.apiKey) return;
    client.res.write(`data: ${JSON.stringify({ type: 'new_event', data: payload })}\n\n`);
  });
}

function broadcastSites(apiKey) {
  const sitesForKey = Array.from(connectedSites.values()).filter(site => site.apiKey === apiKey);
  clients.forEach(client => {
    if (client.apiKey && client.apiKey !== apiKey) return;
    client.res.write(`data: ${JSON.stringify({ type: 'sites_update', data: sitesForKey })}\n\n`);
  });
}

app.get('/api/sites', requireAuth, async (req, res) => {
  try {
    const userRecord = await getStoredUserById(req.authUser.id);
    if (!userRecord?.apiKey) return res.status(404).json({ error: 'User not registered' });

    const filtered = Array.from(connectedSites.values()).filter(site => site.apiKey === userRecord.apiKey);
    res.json(filtered);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/ingest', async (req, res) => {
  // Set CORS headers manually for cross-origin SDK requests (sendBeacon uses credentials: include)
  res.set({
    'Access-Control-Allow-Origin': req.headers.origin || '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Credentials': 'true'
  });

  const payload = req.body;
  if (!payload || typeof payload !== 'object') {
    return res.status(400).json({ error: 'Invalid event payload' });
  }

  const apiKey = payload.apiKey;
  if (!apiKey) return res.status(401).json({ error: 'Missing API key' });

  const { origin, siteName, hostname } = siteFromRequest(req);
  payload.origin = siteName;
  payload._apiKey = apiKey;

  let userRecord;
  try {
    userRecord = await getStoredUserByApiKey(apiKey);
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }

  if (!userRecord) {
    return res.status(403).json({ error: 'Invalid API key' });
  }

  if (userRecord.allowedDomains.length > 0) {
    const isAllowed = userRecord.allowedDomains.some(domain => isAllowedDomain(hostname, domain));
    if (!isAllowed) {
      return res.status(403).json({ error: 'Domain not authorized for this API key' });
    }
  }

  const siteKey = `${siteName}_${apiKey}`;
  if (!connectedSites.has(siteKey)) {
    connectedSites.set(siteKey, {
      name: siteName,
      url: origin,
      apiKey,
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
  broadcastSites(apiKey);

  if (payload.type === 'behavior_batch') {
    const threat = analyzeBehavior(payload);
    if (threat) {
      const alertPayload = {
        type: 'SECURITY_ALERT',
        sessionId: payload.sessionId,
        origin: siteName,
        _apiKey: apiKey,
        data: threat,
        timestamp: Date.now()
      };

      recentEvents.unshift(alertPayload);
      broadcast(alertPayload);
    }
  }

  res.status(200).json({ success: true });
});

const server = app.listen(port, () => {
  console.log(`MayaSec backend listening on http://localhost:${port}`);
});

export { app, server };
