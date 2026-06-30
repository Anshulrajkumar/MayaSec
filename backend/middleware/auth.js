import {
  authErrorMessage,
  callSupabaseAuth
} from '../database/supabase.js';
import {
  authOriginAllowed,
  clearAuthCookies,
  publicUser,
  publicSession,
  readAccessToken,
  readRefreshToken,
  refreshSession,
  setAuthCookies
} from '../services/authService.js';

export async function requireAuth(req, res, next) {
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

export function requireAppOrigin(req, res, next) {
  const origin = req.headers.origin || '';
  if (!authOriginAllowed(origin)) {
    return res.status(403).json({ error: 'Origin not allowed' });
  }

  next();
}
