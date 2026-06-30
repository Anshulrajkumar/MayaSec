import crypto from 'crypto';

const supabaseUrl = process.env.SUPABASE_URL?.replace(/\/+$/, '');
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY;
const supabaseServiceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

/**
 * Parses a fetch response body.
 *
 * @param {Response} response
 * @returns {Promise<Record<string, unknown>>}
 */
async function parseResponse(response) {
  const text = await response.text();
  if (!text) return {};

  try {
    return JSON.parse(text);
  } catch {
    return { raw: text };
  }
}

/**
 * Builds a friendly auth error.
 *
 * @param {Record<string, unknown>} data
 * @param {string} fallback
 * @returns {string}
 */
export function authErrorMessage(data, fallback = 'Authentication request failed') {
  return data?.msg || data?.message || data?.error_description || data?.error || data?.error_code || fallback;
}

/**
 * @returns {void}
 */
export function validateRuntimeConfig() {
  const missing = [];
  if (!supabaseUrl) missing.push('SUPABASE_URL');
  if (!supabaseAnonKey) missing.push('SUPABASE_ANON_KEY');
  if (process.env.NODE_ENV === 'production' && !process.env.APP_ORIGIN) missing.push('APP_ORIGIN');

  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }
}

/**
 * @param {string} pathname
 * @param {{ method?: string, body?: unknown, accessToken?: string }} options
 * @returns {Promise<{ ok: boolean, status: number, data: Record<string, unknown> }>}
 */
export async function callSupabaseAuth(pathname, { method = 'GET', body, accessToken } = {}) {
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

    return {
      ok: response.ok,
      status: response.status,
      data: await parseResponse(response)
    };
  } catch (error) {
    return {
      ok: false,
      status: 502,
      data: { error: `Unable to reach Supabase auth: ${error.message}` }
    };
  }
}

/**
 * @param {string} pathname
 * @param {{ method?: string, body?: unknown, prefer?: string, headers?: Record<string, string> }} options
 * @returns {Promise<{ ok: boolean, status: number, data: Record<string, unknown> }>}
 */
export async function callSupabaseRest(pathname, { method = 'GET', body, prefer, headers = {} } = {}) {
  const keyToUse = supabaseServiceRoleKey || supabaseAnonKey;
  if (!supabaseUrl || !keyToUse) {
    return {
      ok: false,
      status: 500,
      data: { error: 'Supabase database is not configured. Set SUPABASE_URL and SUPABASE_ANON_KEY.' }
    };
  }

  try {
    const response = await fetch(`${supabaseUrl}/rest/v1/${pathname}`, {
      method,
      headers: {
        apikey: keyToUse,
        authorization: `Bearer ${keyToUse}`,
        'content-type': 'application/json',
        ...(prefer ? { Prefer: prefer } : {}),
        ...headers
      },
      body: body ? JSON.stringify(body) : undefined
    });

    return {
      ok: response.ok,
      status: response.status,
      data: await parseResponse(response)
    };
  } catch (error) {
    return {
      ok: false,
      status: 502,
      data: { error: `Unable to reach Supabase database: ${error.message}` }
    };
  }
}

/**
 * @param {string} value
 * @returns {string}
 */
export function encodeFilterValue(value) {
  return encodeURIComponent(String(value));
}

/**
 * @returns {string}
 */
export function generateApiKey() {
  return `ms_ak_${crypto.randomBytes(8).toString('hex')}`;
}
