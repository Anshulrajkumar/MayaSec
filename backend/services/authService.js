import {
  authErrorMessage,
  callSupabaseAuth,
  callSupabaseRest,
  encodeFilterValue,
  generateApiKey
} from '../database/supabase.js';

const port = process.env.PORT || 5000;
const appOrigin = process.env.APP_ORIGIN?.replace(/\/+$/, '') || '';
const isProduction = process.env.NODE_ENV === 'production';
const cookieSecure = process.env.COOKIE_SECURE !== 'false' && (isProduction || Boolean(appOrigin.startsWith('https://')));

const authCookieBase = {
  httpOnly: true,
  sameSite: 'Lax',
  secure: cookieSecure,
  path: '/'
};

export function publicUser(user) {
  if (!user) return null;
  return {
    id: user.id,
    email: user.email,
    user_metadata: user.user_metadata || {}
  };
}

export function publicSession(data) {
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

export function parseCookies(req) {
  const header = req.headers.cookie;
  if (!header) return {};

  return Object.fromEntries(
    header.split(';').map((part) => {
      const index = part.indexOf('=');
      const key = part.slice(0, index).trim();
      const value = part.slice(index + 1).trim();
      return [key, decodeURIComponent(value)];
    })
  );
}

export function setAuthCookies(res, session) {
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

export function clearAuthCookies(res) {
  res.clearCookie('mayasec_at', { ...authCookieBase, maxAge: undefined });
  res.clearCookie('mayasec_rt', { ...authCookieBase, maxAge: undefined });
}

export function readAccessToken(req) {
  const headerToken = req.headers.authorization?.replace(/^Bearer\s+/i, '');
  if (headerToken) return headerToken;
  const cookies = parseCookies(req);
  return cookies.mayasec_at || '';
}

export function readRefreshToken(req) {
  const cookies = parseCookies(req);
  return cookies.mayasec_rt || '';
}

export async function refreshSession(refreshToken) {
  if (!refreshToken) {
    return { ok: false, status: 401, data: { error: 'Missing refresh token' } };
  }

  return callSupabaseAuth('/token?grant_type=refresh_token', {
    method: 'POST',
    body: { refresh_token: refreshToken }
  });
}

export async function getStoredUserById(userId) {
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

export async function getStoredUserByApiKey(apiKey) {
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

export async function saveStoredUser({ userId, email, apiKey, allowedDomains }) {
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

export function normalizeDomain(domain) {
  const value = String(domain || '').trim().toLowerCase();
  if (!value) return '';

  try {
    return new URL(value.includes('://') ? value : `https://${value}`).hostname;
  } catch {
    return value.replace(/^https?:\/\//, '').split('/')[0].replace(/:\d+$/, '');
  }
}

export function originFromRequest(req) {
  const explicitOrigin = String(req.headers.origin || '').trim();
  if (explicitOrigin) return explicitOrigin.replace(/\/+$/, '');

  const referer = String(req.headers.referer || '').trim();
  if (referer) {
    try {
      return new URL(referer).origin.replace(/\/+$/, '');
    } catch {
      return '';
    }
  }

  const host = req.get('host');
  if (!host) return '';
  const protocol = req.headers['x-forwarded-proto'] || req.protocol || 'http';
  return `${protocol}://${host}`.replace(/\/+$/, '');
}

export function resolveAppOrigin(req) {
  const requestOrigin = originFromRequest(req);
  if (requestOrigin && /localhost|127\.0\.0\.1/i.test(requestOrigin)) {
    return requestOrigin;
  }

  return requestOrigin || appOrigin || `http://localhost:${port}`;
}

export function authOriginAllowed(origin) {
  if (!origin) return true;
  const normalizedOrigin = String(origin).replace(/\/+$/, '');
  if (/localhost|127\.0\.0\.1/i.test(normalizedOrigin)) return true;
  if (!appOrigin) return normalizedOrigin === `http://localhost:${port}` || normalizedOrigin === 'http://localhost:5000';
  return normalizedOrigin === appOrigin;
}

export async function ensureStoredUser(authUser) {
  const existingUser = await getStoredUserById(authUser.id);
  if (existingUser) return existingUser;

  return saveStoredUser({
    userId: authUser.id,
    email: authUser.email,
    apiKey: generateApiKey(),
    allowedDomains: []
  });
}
