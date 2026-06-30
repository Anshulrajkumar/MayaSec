import { callSupabaseAuth } from '../database/supabase.js';
import {
  authErrorMessage
} from '../database/supabase.js';
import {
  clearAuthCookies,
  ensureStoredUser,
  getStoredUserById,
  normalizeDomain,
  publicSession,
  publicUser,
  resolveAppOrigin,
  saveStoredUser,
  setAuthCookies
} from '../services/authService.js';

const isSecure = process.env.APP_ORIGIN?.startsWith('https://') || process.env.NODE_ENV === 'production';
const callbackCookie = { httpOnly: true, sameSite: 'Lax', secure: isSecure, path: '/' };

export async function signup(req, res) {
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
}

export async function login(req, res) {
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
}

export function googleLogin(req, res) {
  const redirectTo = resolveAppOrigin(req);
  const supabaseUrl = process.env.SUPABASE_URL?.replace(/\/+$/, '');
  const url = `${supabaseUrl}/auth/v1/authorize?provider=google&redirect_to=${encodeURIComponent(`${redirectTo}/api/auth/callback`)}`;
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.redirect(url);
}

export async function authCallback(req, res) {
  const { access_token: accessToken, refresh_token: refreshToken } = req.query;

  if (!accessToken) {
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

  res.cookie('mayasec_at', accessToken, { ...callbackCookie, maxAge: 3600 * 1000 });
  if (refreshToken) {
    res.cookie('mayasec_rt', refreshToken, { ...callbackCookie, maxAge: 1000 * 60 * 60 * 24 * 30 });
  }
  res.redirect('/');
}

export function tokenExchange(req, res) {
  const { access_token: accessToken, refresh_token: refreshToken } = req.query;
  if (!accessToken) return res.status(400).json({ error: 'Missing token' });

  res.cookie('mayasec_at', accessToken, { ...callbackCookie, maxAge: 3600 * 1000 });
  if (refreshToken) {
    res.cookie('mayasec_rt', refreshToken, { ...callbackCookie, maxAge: 1000 * 60 * 60 * 24 * 30 });
  }
  res.json({ success: true });
}

export function me(req, res) {
  res.json({ user: req.authUser });
}

export async function logout(req, res) {
  clearAuthCookies(res);
  await callSupabaseAuth('/logout', { method: 'POST', accessToken: req.authToken });
  res.json({ success: true });
}

export async function register(req, res) {
  if (!req.authUser?.id || !req.authUser?.email) {
    return res.status(400).json({ error: 'Missing userId or email' });
  }

  try {
    const user = await ensureStoredUser(req.authUser);
    res.json({ apiKey: user.apiKey, allowedDomains: user.allowedDomains });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
}

export async function addDomain(req, res) {
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
}

export async function removeDomain(req, res) {
  const { domain } = req.body || {};
  if (!domain) return res.status(400).json({ error: 'Missing domain' });

  try {
    const storedUser = await getStoredUserById(req.authUser.id);
    if (!storedUser) return res.status(404).json({ error: 'User not found' });

    const cleanDomain = normalizeDomain(domain);
    const savedUser = await saveStoredUser({
      ...storedUser,
      allowedDomains: storedUser.allowedDomains.filter((item) => item !== cleanDomain)
    });

    res.json({ allowedDomains: savedUser.allowedDomains });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
}
